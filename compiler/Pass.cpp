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
std::map<uint32_t,std::set<uint32_t>> globalBBIDTraceMap;

void genCFGJsonFile(std::string CFGFile) {
  // 顶层对象：picojson::value (object type)
  picojson::object topObj;

  // 1. 构建 BBInfo 数组
  picojson::array bbInfoArray;
  for (const auto& kv : globalBBIDMap) {
    // kv.second 是 uint32_t 或 int64_t，picojson 支持 double/bool/string/null
    // 对于整数，可直接转为 double（JSON 无整型，但数值相同）
    bbInfoArray.push_back(picojson::value(static_cast<double>(kv.second)));
  }
  topObj["BBInfo"] = picojson::value(bbInfoArray);

  // 2. 构建 TRInfo 对象
  picojson::object trInfoObj;
  for (const auto& trIt : globalBBIDTraceMap) {
    uint32_t srcBBID = trIt.first;
    picojson::array dstArr;
    for (uint32_t dstBBID : trIt.second) {
      dstArr.push_back(picojson::value(static_cast<double>(dstBBID)));
    }
    // 键必须是 std::string；srcBBID 转为字符串
    trInfoObj[std::to_string(srcBBID)] = picojson::value(dstArr);
  }
  topObj["TRInfo"] = picojson::value(trInfoObj);

  // 3. 写入文件
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
  if (CFGFile == nullptr){
    llvm::errs() << "[PCT] Not set PCT_CFG_PATH, do not generate CFG!\n";
    return;
  }
  llvm::errs() << "[PCT] dump CFG in PCT_CFG_PATH : " << CFGFile << "\n";

  // label the uniq CFG
  std::set<Function *> visitedFunc;
  for (auto &F : M.functions()) {
    for (auto &BB : F){
      visitedFunc.insert(&F);
      uint32_t BBID = globalBBIDMap.size() + 1;
      globalBBIDMap[reinterpret_cast<uint64_t>(&BB)] = BBID;
    }
  }

  // construct the intro-CFG
  for (auto &F : M.functions()) {
    for (auto &BB : F) {
      uint64_t srcBBAddr = reinterpret_cast<uint64_t>(&BB);
      assert(globalBBIDMap.find(srcBBAddr) != globalBBIDMap.end());
      uint32_t srcBBID = globalBBIDMap[srcBBAddr];
      std::set<uint32_t> dstBBIDSet;

      for (auto SI = succ_begin(&BB), SE = succ_end(&BB); SI != SE; ++SI) {
        BasicBlock *SuccBB = *SI;
        uint64_t dstBBAddr = reinterpret_cast<uint64_t>(SuccBB);
        assert(globalBBIDMap.find(dstBBAddr) != globalBBIDMap.end());
        uint32_t dstBBID = globalBBIDMap[dstBBAddr];
        dstBBIDSet.insert(dstBBID);
      }
      globalBBIDTraceMap.insert(std::make_pair(srcBBID, dstBBIDSet));
    }
  }

  // construct the inter-CFG
  for (auto &F : M.functions()) {
    for (auto &BB : F){
      uint64_t srcBBAddr = reinterpret_cast<uint64_t>(&BB);
      assert(globalBBIDMap.find(srcBBAddr) != globalBBIDMap.end());
      uint32_t srcBBID   = globalBBIDMap[srcBBAddr];

      // construct inter-CFG by call instruction
      for (auto &I : BB){
        if (CallInst *CI = dyn_cast<CallInst>(&I)){
          Function *calledFunc = CI->getCalledFunction();
          if (!calledFunc || visitedFunc.count(calledFunc) == 0)
            continue;

          BasicBlock *enterBB  = &(calledFunc->getBasicBlockList().front());
          uint64_t enterBBAddr = reinterpret_cast<uint64_t>(enterBB);
          uint32_t enterBBID   = globalBBIDMap[enterBBAddr];

          // construct the enter trace
          globalBBIDTraceMap[srcBBID].insert(enterBBID);
          // NOTICE : do not need to get the return edge,
          // becasuse use DIJ to check each BB's reach_error reachability
        }
      }
    }
  }

  genCFGJsonFile(CFGFile);
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
