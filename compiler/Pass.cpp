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

#include "Pass.h"

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

#else
#include <llvm/MC/TargetRegistry.h>
#endif

#include <sstream>
#include <fstream>

#include "Runtime.h"
#include "Symbolizer.h"
#include "picojson.h"

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

char *CFGPath;

class FunctionCFG {
public:
  std::string funcName;
  uint64_t entryBBAddr;                              // 入口基本块 ID
  std::set<uint64_t> bbAddrs;                          // 本函数内所有 BB ID
  std::map<uint64_t, std::set<uint32_t>> intraEdges; // 内部转移: srcBBAddr -> {dstBBAddr}
  std::map<uint64_t, std::vector<std::string>> callEdges; // 调用关系: srcBBAddr -> [calledFuncName]

  FunctionCFG(const std::string& name)
      : funcName(name), entryBBAddr(0) {}
};

void genCFGJsonFile(const std::string& CFGFile, const FunctionCFG *cfg) {

  picojson::object funcObj;

  funcObj["func_name"] = picojson::value(cfg->funcName);
  funcObj["entry_bb_addr"] = picojson::value(static_cast<double>(cfg->entryBBAddr));

  // bb_ids
  picojson::array bbAddrsArr;
  for (uint32_t bbAddr : cfg->bbAddrs) {
    bbAddrsArr.push_back(picojson::value(static_cast<double>(bbAddr)));
  }
  funcObj["bb_addrs"] = picojson::value(bbAddrsArr);

  // intra_edges: map<uint32_t, set<uint32_t>> → JSON object of arrays
  picojson::object intraEdgesObj;
  for (const auto& edge : cfg->intraEdges) {
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
  for (const auto& call : cfg->callEdges) {
    uint32_t src = call.first;
    picojson::array calleeArr;
    for (const std::string& callee : call.second) {
      calleeArr.push_back(picojson::value(callee));
    }
    callEdgesObj[std::to_string(src)] = picojson::value(calleeArr);
  }
  funcObj["call_edges"] = picojson::value(callEdgesObj);

  // write to json file
  picojson::value topValue(funcObj);
  std::string jsonStr = topValue.serialize(true); // true = pretty-print

  std::ofstream outFile(CFGFile);
  if (outFile.is_open()) {
    outFile << jsonStr;
    outFile.close();
  } else {
    fprintf(stderr, "Failed to open %s for writing CFG JSON.\n", CFGFile.c_str());
  }
}

bool instrumentModule(Module &M) {
  DEBUG(errs() << "Symbolizer module instrumentation\n");

  CFGPath = getenv("PCT_CFG_PATH");
  if (CFGPath == nullptr) {
    llvm_unreachable("[PCT] Not set PCT_CFG_PATH, do not generate CFG!\n");
  }
  llvm::errs() << "[PCT] dump CFG in PCT_CFG_PATH : " << CFGPath << "\n";

  // Redirect calls to external functions to the corresponding wrappers and
  // rename internal functions.
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

  FunctionCFG cfg(functionName.str());
  cfg.entryBBAddr = reinterpret_cast<uint64_t>(&F.getBasicBlockList().front());

  Symbolizer symbolizer(*F.getParent());
  symbolizer.symbolizeFunctionArguments(F);

  for (auto &basicBlock : F){
    symbolizer.insertBasicBlockNotification(basicBlock);

    uint64_t srcAddr = reinterpret_cast<uint64_t>(&basicBlock);
    cfg.bbAddrs.insert(srcAddr);

    std::set<uint32_t> succBBAddr;
    for (auto SI = succ_begin(&basicBlock), SE = succ_end(&basicBlock);
         SI != SE; ++SI) {
      BasicBlock *Succ = *SI;
      uint64_t dstAddr = reinterpret_cast<uint64_t>(Succ);
      succBBAddr.insert(dstAddr);
    }
    if (!succBBAddr.empty()) {
      cfg.intraEdges[srcAddr] = succBBAddr;
    }

    for (auto &I : basicBlock) {
      if (CallInst *CI = dyn_cast<CallInst>(&I)) {
        Function *callee = CI->getCalledFunction();
        if (callee && callee->hasName() &&
            ! callee->getName().startswith("_sym") &&
            ! callee->getName().startswith("llvm.")) {
          std::string calleeName = callee->getName().str();
          cfg.callEdges[srcAddr].push_back(calleeName);
        }
      }
    }
  }

  for (auto *instPtr : allInstructions)
    symbolizer.visit(instPtr);

  symbolizer.finalizePHINodes();
  symbolizer.shortCircuitExpressionUses();

  // DEBUG(errs() << F << '\n');
  assert(!verifyFunction(F, &errs()) &&
         "SymbolizePass produced invalid bitcode");

  std::string FuncCFG = std::string(CFGPath) + "/" + cfg.funcName + ".cfg";
  genCFGJsonFile(FuncCFG, &cfg);
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
