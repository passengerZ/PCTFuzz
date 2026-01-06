// This file is part of SymCC.
//
// SymCC is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// SymCC is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// SymCC. If not, see <https://www.gnu.org/licenses/>.

#include <llvm/ADT/SmallVector.h>
#include <llvm/CodeGen/IntrinsicLowering.h>
#include <llvm/CodeGen/TargetLowering.h>
#include <llvm/CodeGen/TargetSubtargetInfo.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetOptions.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>

#if LLVM_VERSION_MAJOR < 14
#include <llvm/Support/TargetRegistry.h>
#include <sstream>
#else
#include <llvm/MC/TargetRegistry.h>
#endif

#include "Pass.h"
#include "Runtime.h"
#include "Symbolizer.h"

#include "picojson.h"
#include "fstream"

using namespace llvm;

#ifndef NDEBUG
#define DEBUG(X)                                                               \
  do {                                                                         \
    X;                                                                         \
  } while (false)
#else
#define DEBUG(X) ((void)0)
#endif

char SymbolizeLegacyPass::ID = 0;

namespace {

static constexpr char kSymCtorName[] = "__sym_ctor";

std::map<uint64_t,uint32_t> globalBBIDMap;
uint32_t globalFuncIDCounter = 0;

class FunctionCFG {
public:
  std::string funcName;
  uint32_t funcID;
  uint32_t entryBBID;                                // 入口基本块 ID
  std::set<uint32_t> bbIDs;                          // 本函数内所有 BB ID
  std::map<uint32_t, std::set<uint32_t>> intraEdges; // 内部转移: srcBBID -> {dstBBID}
  std::map<uint32_t, std::vector<std::string>> callEdges; // 调用关系: srcBBID -> [calledFuncName]

  FunctionCFG(const std::string& name, uint32_t id)
      : funcName(name), funcID(id), entryBBID(0) {}
};

std::vector<FunctionCFG> loadExistingCFGs(const std::string& cfgFile) {
  std::vector<FunctionCFG> existing;

  std::ifstream file(cfgFile);
  if (!file.is_open())
    return existing;

  std::stringstream buffer;
  buffer << file.rdbuf();
  file.close();

  std::string err;
  picojson::value v;
  picojson::parse(v, buffer.str().c_str(), buffer.str().c_str() + buffer.str().size(), &err);
  if (!err.empty()) {
    llvm::errs() << "[PCT] Failed to parse existing CFG JSON: " << err << "\n";
    return existing;
  }

  if (!v.is<picojson::object>()) return existing;
  auto root = v.get<picojson::object>();

  if (root.find("functions") == root.end() ||
      !root.at("functions").is<picojson::array>()) {
    return existing;
  }

  const auto& funcs = root.at("functions").get<picojson::array>();
  for (const auto& fval : funcs) {
    if (!fval.is<picojson::object>()) continue;
    auto fobj = fval.get<picojson::object>();

    FunctionCFG cfg("", 0);

    // func_name
    cfg.funcName  = fobj.at("func_name").get<std::string>();
    cfg.funcID    = static_cast<uint32_t>(fobj.at("func_id").get<double>());
    cfg.entryBBID = static_cast<uint32_t>(fobj.at("entry_bb_id").get<double>());

    // bb_ids
    for (auto& idval : fobj.at("bb_ids").get<picojson::array>())
      cfg.bbIDs.insert(static_cast<uint32_t>(idval.get<double>()));

    // intra_edges
    auto edges = fobj.at("intra_edges").get<picojson::object>();
    for (auto& kv : edges) {
      uint32_t src = static_cast<uint32_t>(std::stoul(kv.first));
      std::set<uint32_t> dsts;
      for (auto& d : kv.second.get<picojson::array>())
        dsts.insert(static_cast<uint32_t>(d.get<double>()));

      cfg.intraEdges[src] = dsts;
    }

    // call_edges
    auto calls = fobj.at("call_edges").get<picojson::object>();
    for (auto& kv : calls) {
      uint32_t src = static_cast<uint32_t>(std::stoul(kv.first));
      std::vector<std::string> callees;
      for (auto& c : kv.second.get<picojson::array>())
        callees.push_back(c.get<std::string>());
      cfg.callEdges[src] = callees;
    }

    existing.push_back(std::move(cfg));
  }

  return existing;
}

void genCFGJsonFile(const std::string& CFGFile, const std::vector<FunctionCFG>& allCFGs) {
  picojson::object topObj;

  // 构建 functions 数组
  picojson::array functionsArray;
  for (const auto& cfg : allCFGs) {
    picojson::object funcObj;

    funcObj["func_name"] = picojson::value(cfg.funcName);
    funcObj["func_id"] = picojson::value(static_cast<double>(cfg.funcID));
    funcObj["entry_bb_id"] = picojson::value(static_cast<double>(cfg.entryBBID));

    // bb_ids
    picojson::array bbIdsArr;
    for (uint32_t bbid : cfg.bbIDs) {
      bbIdsArr.push_back(picojson::value(static_cast<double>(bbid)));
    }
    funcObj["bb_ids"] = picojson::value(bbIdsArr);

    // intra_edges: map<uint32_t, set<uint32_t>> → JSON object of arrays
    picojson::object intraEdgesObj;
    for (const auto& edge : cfg.intraEdges) {
      uint32_t src = edge.first;
      picojson::array dstArr;
      for (uint32_t dst : edge.second) {
        dstArr.push_back(picojson::value(static_cast<double>(dst)));
      }
      intraEdgesObj[std::to_string(src)] = picojson::value(dstArr);
    }
    funcObj["intra_edges"] = picojson::value(intraEdgesObj);

    // call_edges: map<uint32_t, vector<string>> -> JSON object of string arrays
    picojson::object callEdgesObj;
    for (const auto& call : cfg.callEdges) {
      uint32_t src = call.first;
      picojson::array calleeArr;
      for (const std::string& callee : call.second) {
        calleeArr.push_back(picojson::value(callee));
      }
      callEdgesObj[std::to_string(src)] = picojson::value(calleeArr);
    }
    funcObj["call_edges"] = picojson::value(callEdgesObj);

    functionsArray.push_back(picojson::value(funcObj));
  }

  topObj["functions"] = picojson::value(functionsArray);

  // write to json file
  picojson::value topValue(topObj);
  std::string jsonStr = topValue.serialize(true); // true = pretty-print

  std::ofstream outFile(CFGFile);
  if (outFile.is_open()) {
    outFile << jsonStr;
    outFile.close();
  } else {
    fprintf(stderr, "Failed to open %s for writing CFG JSON.\n", CFGFile.c_str());
  }
}

void constructICFG(Module &M){
  auto *CFGFile = getenv("PCT_CFG_PATH");
  if (CFGFile == nullptr) {
    llvm_unreachable("[PCT] Not set PCT_CFG_PATH, do not generate CFG!\n");
  }
  llvm::errs() << "[PCT] dump CFG in PCT_CFG_PATH : " << CFGFile << "\n";

  // Step 1: 加载已有的 CFG（来自之前的 Module）
  std::vector<FunctionCFG> allCFGs = loadExistingCFGs(CFGFile);

  // 构建已有函数名集合，避免重复分析
  std::set<std::string> existingFuncNames;
  uint32_t maxFuncID = 0;
  for (const auto& cfg : allCFGs) {
    existingFuncNames.insert(cfg.funcName);
    if (cfg.funcID >= maxFuncID)
      maxFuncID = cfg.funcID;
  }
  // 确保新分配的 funcID 不冲突
  globalFuncIDCounter = maxFuncID + 1;

  std::vector<Function*> validFuncs;
  for (auto &F : M.functions())
    if (!F.isDeclaration() && !F.empty() &&
        existingFuncNames.count(F.getName().str()) == 0)
      validFuncs.push_back(&F);

  // 为每个函数分配唯一 funcID，并建立函数名到 funcID 的映射
  std::map<std::string, uint32_t> funcNameToID;
  std::map<Function*, uint32_t> funcPtrToID;
  for (auto *F : validFuncs) {
    funcPtrToID[F] = globalFuncIDCounter++;
  }

  // 第一遍：为每个函数构建 BBID 映射（局部于该函数）
  for (auto *F : validFuncs) {
    std::string funcName = F->getName().str();
    uint32_t funcID = funcPtrToID[F];
    FunctionCFG cfg(funcName, funcID);

    std::map<uint64_t, uint32_t> localBBIDMap;
    uint32_t bbCounter = 1;

    // 分配 BBID 并记录入口
    for (auto &BB : *F) {
      uint64_t addr = reinterpret_cast<uint64_t>(&BB);
      uint32_t bbid = bbCounter++;
      bbid = funcID * 10000 + bbid; // get the global BBID
      localBBIDMap[addr]  = bbid;
      globalBBIDMap[addr] = bbid;
      cfg.bbIDs.insert(bbid);
    }

    if (!F->empty()) {
      uint64_t entryAddr = reinterpret_cast<uint64_t>(&F->getBasicBlockList().front());
      cfg.entryBBID = localBBIDMap[entryAddr];
    }

    // 第二遍：构建内部转移边（intra-procedural edges）
    for (auto &BB : *F) {
      uint64_t srcAddr = reinterpret_cast<uint64_t>(&BB);
      uint32_t srcBBID = localBBIDMap[srcAddr];
      std::set<uint32_t> succBBIDs;

      for (auto SI = succ_begin(&BB), SE = succ_end(&BB); SI != SE; ++SI) {
        BasicBlock *Succ = *SI;
        uint64_t dstAddr = reinterpret_cast<uint64_t>(Succ);
        if (localBBIDMap.count(dstAddr)) {
          succBBIDs.insert(localBBIDMap[dstAddr]);
        }
      }
      if (!succBBIDs.empty()) {
        cfg.intraEdges[srcBBID] = succBBIDs;
      }

      for (auto &I : BB) {
        if (CallInst *CI = dyn_cast<CallInst>(&I)) {
          Function *callee = CI->getCalledFunction();
          if (callee && callee->hasName()) {
            std::string calleeName = callee->getName().str();
            cfg.callEdges[srcBBID].push_back(calleeName);
          }
        }
      }
    }

    allCFGs.push_back(std::move(cfg));
  }

  // 生成 JSON 文件
  genCFGJsonFile(CFGFile, allCFGs);
}

bool instrumentModule(Module &M) {
  DEBUG(errs() << "Symbolizer module instrumentation\n");

  constructICFG(M);

  // Redirect calls to external functions to the corresponding wrappers and
  // rename internal functions.
  M.getFunctionList();
  for (auto &function : M.functions()) {
    auto name = function.getName();
    if (isInterceptedFunction(function))
      function.setName(name + "_symbolized");
  }

  // Insert a constructor that initializes the runtime and any globals.
  Function *ctor;
  std::tie(ctor, std::ignore) = createSanitizerCtorAndInitFunctions(
      M, kSymCtorName, "_sym_initialize", {}, {});
  appendToGlobalCtors(M, ctor, 0);

  return true;
}

bool canLower(const CallInst *CI) {
  const Function *Callee = CI->getCalledFunction();
  if (!Callee)
    return false;

  switch (Callee->getIntrinsicID()) {
  case Intrinsic::expect:
  case Intrinsic::ctpop:
  case Intrinsic::ctlz:
  case Intrinsic::cttz:
  case Intrinsic::prefetch:
  case Intrinsic::pcmarker:
  case Intrinsic::dbg_declare:
  case Intrinsic::dbg_label:
  case Intrinsic::annotation:
  case Intrinsic::ptr_annotation:
  case Intrinsic::assume:
#if LLVM_VERSION_MAJOR > 11
  case Intrinsic::experimental_noalias_scope_decl:
#endif
  case Intrinsic::var_annotation:
  case Intrinsic::sqrt:
  case Intrinsic::log:
  case Intrinsic::log2:
  case Intrinsic::log10:
  case Intrinsic::exp:
  case Intrinsic::exp2:
  case Intrinsic::pow:
  case Intrinsic::sin:
  case Intrinsic::cos:
  case Intrinsic::floor:
  case Intrinsic::ceil:
  case Intrinsic::trunc:
  case Intrinsic::round:
#if LLVM_VERSION_MAJOR > 10
  case Intrinsic::roundeven:
#endif
  case Intrinsic::copysign:
#if LLVM_VERSION_MAJOR < 16
  case Intrinsic::flt_rounds:
#else
  case Intrinsic::get_rounding:
#endif
  case Intrinsic::invariant_start:
  case Intrinsic::lifetime_start:
  case Intrinsic::invariant_end:
  case Intrinsic::lifetime_end:
    return true;
  default:
    return false;
  }

  llvm_unreachable("Control cannot reach here");
}

void liftInlineAssembly(CallInst *CI) {
  // TODO When we don't have to worry about the old pass manager anymore, move
  // the initialization to the pass constructor. (Currently there are two
  // passes, but only if we're on a recent enough LLVM...)

  Function *F = CI->getFunction();
  Module *M = F->getParent();
  auto triple = M->getTargetTriple();

  std::string error;
  auto target = TargetRegistry::lookupTarget(triple, error);
  if (!target) {
    errs() << "Warning: can't get target info to lift inline assembly\n";
    return;
  }

  auto cpu = F->getFnAttribute("target-cpu").getValueAsString();
  auto features = F->getFnAttribute("target-features").getValueAsString();

  std::unique_ptr<TargetMachine> TM(
      target->createTargetMachine(triple, cpu, features, TargetOptions(), {}));
  auto subTarget = TM->getSubtargetImpl(*F);
  if (subTarget == nullptr)
    return;

  auto targetLowering = subTarget->getTargetLowering();
  if (targetLowering == nullptr)
    return;

  targetLowering->ExpandInlineAsm(CI);
}

bool instrumentFunction(Function &F) {
  auto functionName = F.getName();
  if (functionName == kSymCtorName)
    return false;

  DEBUG(errs() << "Symbolizing function ");
  DEBUG(errs().write_escaped(functionName) << '\n');

  SmallVector<Instruction *, 0> allInstructions;
  allInstructions.reserve(F.getInstructionCount());
  for (auto &I : instructions(F))
    allInstructions.push_back(&I);

  IntrinsicLowering IL(F.getParent()->getDataLayout());
  for (auto *I : allInstructions) {
    if (auto *CI = dyn_cast<CallInst>(I)) {
      if (canLower(CI)) {
        IL.LowerIntrinsicCall(CI);
      } else if (isa<InlineAsm>(CI->getCalledOperand())) {
        liftInlineAssembly(CI);
      }
    }
  }

  allInstructions.clear();
  for (auto &I : instructions(F))
    allInstructions.push_back(&I);

  Symbolizer symbolizer(*F.getParent());
  symbolizer.symbolizeFunctionArguments(F);

  symbolizer.setBBConfigure(globalBBIDMap);
  for (auto &basicBlock : F)
    symbolizer.insertBasicBlockNotification(basicBlock);

  for (auto *instPtr : allInstructions)
    symbolizer.visit(instPtr);

  symbolizer.finalizePHINodes();
  symbolizer.shortCircuitExpressionUses();

  // DEBUG(errs() << F << '\n');
  // F.print(llvm::errs());
  assert(!verifyFunction(F, &errs()) &&
         "SymbolizePass produced invalid bitcode");

  return true;
}

} // namespace

bool SymbolizeLegacyPass::doInitialization(Module &M) {
  return instrumentModule(M);
}

bool SymbolizeLegacyPass::runOnFunction(Function &F) {
  return instrumentFunction(F);
}

#if LLVM_VERSION_MAJOR >= 13

PreservedAnalyses SymbolizePass::run(Function &F, FunctionAnalysisManager &) {
  return instrumentFunction(F) ? PreservedAnalyses::none()
                               : PreservedAnalyses::all();
}

PreservedAnalyses SymbolizePass::run(Module &M, ModuleAnalysisManager &) {
  return instrumentModule(M) ? PreservedAnalyses::none()
                             : PreservedAnalyses::all();
}

#endif
