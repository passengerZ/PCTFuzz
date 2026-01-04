#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "BinaryTree.h"
#include "HybridFuzzer.h"
#include "TransformPass.h"
#include "call_stack_manager.h"
#include "qsymExpr.pb.h"
#include "solver.h"
#include "SearchStrategy.h"

#include "llvm/Support/CommandLine.h"

using namespace llvm;

cl::opt<std::string> FuzzerName(
    "fuzzer-name", cl::desc("The name of the fuzzer to work with"),
    cl::Required
);

cl::opt<std::string> OutputDir(
    "output-dir",
    cl::desc("The AFL output directory"),
    cl::Required
);

cl::opt<std::string> SymCCName(
    "name",
    cl::desc("Name to use for SymCC"),
    llvm::cl::init("symcc")
);

cl::opt<std::string> SymCCTargetBin(
    cl::Positional,
    cl::desc("Program under test"),
    cl::Required
);

namespace fs = std::filesystem;

namespace qsym {

using namespace pct;

ExprBuilder *g_expr_builder;
Solver *g_solver;
CallStackManager g_call_stack_manager;
z3::context *g_z3_context;

std::map<UINT32, ExprRef> cached;
ExecutionTree *executionTree;
SearchStrategy *search;

template <typename E> constexpr auto to_underlying(E e) noexcept {
  return static_cast<std::underlying_type_t<E>>(e);
}

void deserializeToQsymExpr(const SymbolicExpr &protoExpr,
                           ExprRef &qsymExpr) {
  UINT32 hashValue = protoExpr.hash();
  auto it = cached.find(hashValue);
  if (it != cached.end()) {
    qsymExpr = it->second;
    return;
  }

  ExprRef child0, child1, child2;
  ExprKind exprKind = static_cast<ExprKind>(protoExpr.type());
  assert(to_underlying(exprKind) <= 79);

  switch (exprKind) {
  case ExprKind::Bool: {
    qsymExpr = g_expr_builder->createBool(protoExpr.value());
    break;
  }
  case ExprKind::Constant: {
    qsymExpr = g_expr_builder->createConstant(protoExpr.value(),
                                              protoExpr.bits());
    break;
  }
  case ExprKind::Read: {
    // ReadExpr has a _index of type uint32, so we need to do a int64 t0 uint32
    // translate.
    qsymExpr = g_expr_builder->createRead(protoExpr.value());
    break;
  }
  case ExprKind::Extract: {
    deserializeToQsymExpr(protoExpr.children(0), child0);
    qsymExpr = g_expr_builder->createExtract(
        child0, protoExpr.value() & 0xFFFFFFFF, protoExpr.bits());
    break;
  }
  case ExprKind::ZExt: {
    uint32_t bits = protoExpr.bits();
    deserializeToQsymExpr(protoExpr.children(0), child0);
    qsymExpr = g_expr_builder->createZExt(child0, bits);
    break;
  }
  case ExprKind::SExt: {
    uint32_t bits = protoExpr.bits();
    deserializeToQsymExpr(protoExpr.children(0), child0);
    qsymExpr = g_expr_builder->createSExt(child0, bits);
    break;
  }
  case ExprKind::Neg: case ExprKind::Not:
  case ExprKind::LNot: case ExprKind::FAbs: {
    deserializeToQsymExpr(protoExpr.children(0), child0);
    qsymExpr = g_expr_builder->createUnaryExpr(
        static_cast<qsym::Kind>(to_underlying(exprKind)), child0);
    break;
  }
  case ExprKind::Concat:{
    deserializeToQsymExpr(protoExpr.children(0), child0);
    deserializeToQsymExpr(protoExpr.children(1), child1);
    qsymExpr = g_expr_builder->createConcat(child0, child1);
    break;
  }
  // Binary arithmetic operators
  case ExprKind::Add: case ExprKind::Sub: case ExprKind::Mul:
  case ExprKind::UDiv: case ExprKind::SDiv:
  case ExprKind::URem: case ExprKind::SRem:
  case ExprKind::And: case ExprKind::Or: case ExprKind::Xor:
  case ExprKind::Shl: case ExprKind::LShr: case ExprKind::AShr:
    // Binary floating-point arithmetic operators
  case ExprKind::FAdd: case ExprKind::FSub: case ExprKind::FMul:
  case ExprKind::FDiv: case ExprKind::FRem:
  case ExprKind::FOgt: case ExprKind::FOge:
  case ExprKind::FOlt: case ExprKind::FOle:
  case ExprKind::FOne: case ExprKind::FOeq:
  case ExprKind::FOrd: case ExprKind::FUno:
  case ExprKind::FUlt: case ExprKind::FUle:
  case ExprKind::FUgt: case ExprKind::FUge:
  case ExprKind::FUeq: case ExprKind::FUne:
    // Binary relational operators
  case ExprKind::Equal: case ExprKind::Distinct:
  case ExprKind::Ult: case ExprKind::Ule:
  case ExprKind::Ugt: case ExprKind::Uge:
  case ExprKind::Slt: case ExprKind::Sle:
  case ExprKind::Sgt: case ExprKind::Sge:
  case ExprKind::LOr: case ExprKind::LAnd: {
    deserializeToQsymExpr(protoExpr.children(0), child0);
    deserializeToQsymExpr(protoExpr.children(1), child1);
    qsymExpr = g_expr_builder->createBinaryExpr(
        static_cast<qsym::Kind>(to_underlying(exprKind)), child0, child1);
    break;
  }
  case ExprKind::Ite: {
    deserializeToQsymExpr(protoExpr.children(0), child0);
    deserializeToQsymExpr(protoExpr.children(1), child1);
    deserializeToQsymExpr(protoExpr.children(2), child2);
    qsymExpr = g_expr_builder->createIte(child0, child1, child2);
    break;
  }

    // Floating-point arithmetic operators
  case ExprKind::FPToBV: {
    deserializeToQsymExpr(protoExpr.children(0), child0);
    qsymExpr = g_expr_builder->floatToBits(child0);
    break;
  }
  case ExprKind::BVToFP: {
    deserializeToQsymExpr(protoExpr.children(0), child0);
    qsymExpr = g_expr_builder->bitsToFloat(child0, protoExpr.bits() == 64);
    break;
  }
  case ExprKind::FPToFP: {
    deserializeToQsymExpr(protoExpr.children(0), child0);
    qsymExpr = g_expr_builder->floatToFloat(child0, protoExpr.bits() == 64);
    break;
  }
  case ExprKind::FPToSI: {
    deserializeToQsymExpr(protoExpr.children(0), child0);
    qsymExpr = g_expr_builder->floatToSignInt(child0, protoExpr.bits());
    break;
  }
  case ExprKind::FPToUI: {
    deserializeToQsymExpr(protoExpr.children(0), child0);
    qsymExpr = g_expr_builder->floatToUnsignInt(child0, protoExpr.bits());
    break;
  }
  case ExprKind::SIToFP: {
    deserializeToQsymExpr(protoExpr.children(0), child0);
    qsymExpr = g_expr_builder->intToFloat(
        child0, protoExpr.bits() == 64, true);
    break;
  }
  case ExprKind::UIToFP: {
    deserializeToQsymExpr(protoExpr.children(0), child0);
    qsymExpr = g_expr_builder->intToFloat(
        child0, protoExpr.bits() == 64, false);
    break;
  }
  case ExprKind::Float: {
    llvm::APInt iValue = llvm::APInt(64, protoExpr.value());
    qsymExpr = g_expr_builder->createConstantFloat(
        llvm::APFloat(iValue.bitsToDouble()), protoExpr.bits());
    break;
  }
    // Unknown operators
  case ExprKind::Rol:
  case ExprKind::Ror:
  case ExprKind::Invalid:
    LOG_FATAL("Unsupported expression kind in deserialization");
    break; // to silence the compiler warning
  default:
    LOG_FATAL("Unknown expression kind in deserialization");
    break;
  }
  cached.insert(make_pair(hashValue, qsymExpr));
}

unsigned updatePCTree(const fs::path &constraint_file, const fs::path &input) {
  ifstream inputf(constraint_file, std::ofstream::in | std::ofstream::binary);
  if (inputf.fail()){
    std::cerr << "Unable to open a file ["
              << constraint_file <<"] to update Path Constaint Tree\n";
    return false;
  }

  ConstraintSequence cs;
  cs.ParseFromIstream(&inputf);

  // if current varByte less than initial,
  // may cause path constraint tree Divergent
  if (executionTree->varSizeLowerBound == 0 ||
      cs.varbytes() >= executionTree->varSizeLowerBound)
    executionTree->varSizeLowerBound = cs.varbytes();

  if (cs.varbytes() < executionTree->varSizeLowerBound)
    return false;

  // (1) covnew ----> interst = 1;
  // (2) signal > 0 ----> crash = 2;
  unsigned isInterest = 0;
  //std::cerr << "[PCT] visTrace : ";
  for (int i = 0; i < cs.bbid_size(); i+=2) {
    // note : Odd position as srcBB, even position as dstBB
    const uint32_t srcBB = cs.bbid(i);
    const uint32_t dstBB = cs.bbid(i+1);
    //std::cerr << " " << srcBB << "->" << dstBB << ",";

    trace covTrace = std::make_pair(srcBB,dstBB);
    bool isCovNew = search->updateCovTrace(covTrace);
    // insert success, means new trace have been visited
    if (isCovNew){
      isInterest = 1;
    }
  }
  if (cs.runsignal() != 0)
    isInterest = 2;
  //std::cerr << "\n";

  ExprRef pathCons;
  TreeNode *currNode = executionTree->getRoot();
  for (int i = 0; i < cs.node_size(); i++) {
    const SequenceNode &pnode = cs.node(i);
    if (!pnode.has_constraint())
      continue;

    bool branchTaken = pnode.taken() > 0;
    deserializeToQsymExpr(pnode.constraint(), pathCons);
    PCTNode pctNode(pathCons, input, branchTaken, cs.varbytes(),
                    pnode.b_id(), pnode.b_left(), pnode.b_right());

    currNode = executionTree->updateTree(currNode, pctNode);
  }

  return isInterest;
}

void execute_one(const std::string& input,
                 State *state, SymCC *symcc, AflConfig* afl_config){
  fs::path pct_file = state->concolic_execution(input, *symcc, *afl_config);
  unsigned inputStatus = qsym::updatePCTree(pct_file, input);
  remove_file(pct_file);

  // save important input
  if (inputStatus > 0){
    fs::path fuzzInput = state->copy_testcase_to_fuzzer(
        input, inputStatus == 1 ? state->queue : state->crashes);
    std::cerr << "[PCT] new important input : " << fuzzInput.string() << "\n";
    state->processed_seeds.insert(fuzzInput);
  }
}

void executePCT(std::vector<TreeNode *> *tobeExplores,
                State *state, SymCC *symcc, AflConfig* afl_config){
  for (auto node : *tobeExplores){
    std::string new_case = executionTree->generateTestCase(node);
    if (new_case.empty())
      continue;
    execute_one(new_case, state, symcc, afl_config);
  }
}

} // namespace qsym

int main (int argc, char* argv[]){
  cl::ParseCommandLineOptions(argc, argv, "Make SymCC collaborate with AFL.\n");

  std::string output_dir_Str = OutputDir;
  std::string fuzzer_name = FuzzerName;
  std::string symcc_name  = SymCCName;

  fs::path output_dir(output_dir_Str);
  if (!fs::exists(output_dir) || !fs::is_directory(output_dir)) {
    std::cerr << "The directory "<< output_dir_Str << " does not exist!\n";
    return 1;
  }

  auto afl_queue = output_dir / fuzzer_name / "queue";
  if (!fs::exists(afl_queue) || !fs::is_directory(afl_queue)) {
    std::cerr << "The AFL queue "<< afl_queue.string() << " does not exist!\n";
    return 1;
  }

  auto symcc_dir = output_dir / symcc_name;
  if (fs::exists(symcc_dir)) {
    std::cerr << symcc_dir.string() << " already exists; we do not currently support resuming\n";
    return 1;
  }

  std::vector<std::string> command;
  command.push_back(SymCCTargetBin);
  command.push_back("@@");

  SymCC symcc(symcc_dir, command);
  fs::path fuzzer_output = output_dir / fuzzer_name;
  auto afl_config = AflConfig::load(fuzzer_output);
  auto state = State::initialize(symcc_dir, fuzzer_output);

  qsym::g_z3_context = new z3::context{};
  qsym::g_solver = new qsym::Solver("/dev/null", state.solved.path, ""); // for QSYM-internal use
  qsym::g_expr_builder = qsym::SymbolicExprBuilder::create();
  qsym::executionTree = new ExecutionTree(g_solver, g_expr_builder);
  qsym::search = new SearchStrategy();

  while (true) {
    // 1. fetch all covnew seed, but not execute before
    // 2. symbolic execute all seed, and get path constraints tree
    // 3. rebuild PCT
    // 4. use SMT Solver to generate covnew SEED
    // 5. if no covnew SEED, dump filter
    // 6. use filter to AFL++, and restart AFL++

    // step(1) : rebuild PCT from AFL
    std::vector<fs::path> covnew_seeds =
        afl_config.get_unseen_seeds(afl_config.queue, state.processed_seeds);
    if (covnew_seeds.empty()){
      std::cerr << "[PCT] Waiting for new test cases...\n";
      std::this_thread::sleep_for(10s);
    }else{
      // step(2) : execute inputs from afl, and rebuild PCT
      for (const auto& input : covnew_seeds)
        execute_one(input, &state, &symcc, &afl_config);

      if (executionTree->getLeftNodeSize() > 0){
        std::cerr << "[zgf dbg] execution tree after fuzz : " << executionTree->getLeftNodeSize() << "\n";
        executionTree->printTree(true);

        /*
        // step(3) : select uncovered traces
        std::map<trace, std::set<trace>> ReachEdgeBranches =
            qsym::search->recomputeGuidance();
        for (auto guideIt : ReachEdgeBranches){
          trace t = guideIt.first;
          std::set<trace> *relaBranchTraces = &guideIt.second;
          std::set<TreeNode*> leafNodes = executionTree->getBBNodes(t);
          for (auto leafNode : leafNodes){
            if (leafNode->depth < 3){

              std::string input = executionTree->generateTestCase(leafNode);
              if (!input.empty())
                qsym::execute_one(input, &state, &symcc, &afl_config);

              continue;
            }

            std::vector<qsym::ExprRef> relaCons =
                executionTree->getRelaConstraints(leafNode, relaBranchTraces);
            std::cerr << t.first << "->" << t.second << ", taken: " << leafNode->data.taken << "\n";
            for (auto e : relaCons)
              std::cerr << "e : " << e->toString() << "\n";
          }
        }*/

        // step(4) : execute the inputs from PCT, decide which cov-new
        std::vector<TreeNode *> tobeExplore = executionTree->getWillBeVisitedNodes();
        while(!tobeExplore.empty()){
          executePCT(&tobeExplore, &state, &symcc, &afl_config);
          tobeExplore = executionTree->getWillBeVisitedNodes();
        }

        std::cerr << "[zgf dbg] execution tree after DSE : " << tobeExplore.size() << "\n";
        executionTree->printTree(true);
        std::cerr << "========\n";

        // step (3) : dump the visited leaf node to build failed pass
        PCT::TransformPass TP;
        TP.buildFailedPass(executionTree, 8);
      }
    }

    auto now = std::chrono::steady_clock::now();
    if (now - state.last_stats_output > STATS_INTERVAL_SEC) {
      try {
        state.stats.log(state.stats_file);
        state.last_stats_output = now;
      } catch (const std::exception& e) {
        std::cerr << "Failed to log run-time statistics:" << e.what() << "\n";
      }
    }
  }

  return 0;
}