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

SearchStrategy *g_searcher;
std::map<UINT32, ExprRef> cached;
ExecutionTree *executionTree;

std::set<uint32_t> lastExitNodes;
uint32_t MAX_DEPTH = 50, curr_depth = 10;

template <typename E> constexpr auto to_underlying(E e) noexcept {
  return static_cast<std::underlying_type_t<E>>(e);
}

void deserializeToQsymExpr(
    const SymbolicExpr &protoExpr,ExprRef &qsymExpr) {
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
    uint32_t idx = protoExpr.value();
    qsymExpr = g_expr_builder->createRead(idx);
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

  // covnew ----> interst = 1;
  unsigned isInterest = 0;
  //std::cerr << "[PCT] visTrace : ";
  for (int i = 0; i < cs.bbid_size(); i+=2) {
    // note : Odd position as srcBB, even position as dstBB
    const uint32_t srcBB = cs.bbid(i);
    const uint32_t dstBB = cs.bbid(i+1);
    //std::cerr << " " << srcBB << "->" << dstBB << ",";

    trace covTrace = std::make_pair(srcBB,dstBB);
    bool isCovNew = executionTree->updateCovTrace(covTrace);
    // insert success, means new trace have been visited
    if (isCovNew){
      isInterest = 1;
    }
  }

  ExprRef pathCons;
  TreeNode *currNode = executionTree->getRoot();
  for (int i = 0; i < cs.node_size(); i++) {
    const SequenceNode &pnode = cs.node(i);
    if (!pnode.has_constraint())
      continue;

    bool branchTaken = pnode.taken() > 0;

    deserializeToQsymExpr(pnode.constraint(), pathCons);
    PCTNode pctNode(pathCons, input, branchTaken, 0,
                    pnode.b_id(), pnode.b_left(), pnode.b_right());

    currNode = executionTree->updateTree(currNode, pctNode);
  }

  return isInterest;
}

unsigned execute_fuzzer(
    std::string input, State *state, SymCC *symcc, AflConfig* afl_config){

  // avoid symcc to failed open afl-busy seed
  fs::path currInput = state->copy_testcase_to_dir(input, state->seen);
  input = currInput.string();

  fs::path pct_file = state->concolic_execution(input, *symcc, *afl_config);
  qsym::updatePCTree(pct_file, input);
  remove_file(pct_file);

  // save covnew input
  TestcaseResult res = state->evaluate_new_testcase(
      input, symcc->work_dir, *afl_config, true);
  return res == TestcaseResult::New;
}

unsigned execute_dse(
    std::string input, State *state, SymCC *symcc, AflConfig* afl_config){

  fs::path pct_file = state->concolic_execution(input, *symcc, *afl_config);
  qsym::updatePCTree(pct_file, input);
  remove_file(pct_file);

  // save covnew input
  TestcaseResult res = state->evaluate_new_testcase(
        input, symcc->work_dir, *afl_config, false);
  return res == TestcaseResult::New;
}

bool execute_pct(std::vector<TreeNode *> *tobeExplores,
                 State *state, SymCC *symcc, AflConfig* afl_config){
  bool covNew = false;
  if (tobeExplores->empty())
    return covNew;

//  uint32_t deepest = 0;
//  std::string deepestCase;

  for (auto node : *tobeExplores){
    std::string new_case = executionTree->generateTestCase(node);
    if (new_case.empty())
      continue;

//    if (node->depth > deepest){
//      deepestCase = new_case;
//      deepest = node->depth;
//    }

    unsigned status = execute_dse(new_case, state, symcc, afl_config);
    if (status > 0){
      // intresting input
      std::cerr << "[zgf dbg] covnew info BB:" << node->data.currBB
                << ", depth:" << node->depth << "\n";
      executionTree->updateBBWeight(node->data.currBB);
      covNew = true;
    }
  }
  if (!covNew){
//    std::string heurisCase = state->copy_testcase_to_dir(deepestCase, state->queue);
//    std::cerr << "[PCT] Heuristic Case : " << heurisCase << "\n";

    for (auto node : executionTree->divergtNodes){
      std::string new_case = executionTree->generateTestCase(node);
      if (new_case.empty())
        continue;
      execute_dse(new_case, state, symcc, afl_config);
    }
  }
  return covNew;
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
  qsym::g_searcher = new SearchStrategy();
  qsym::executionTree = new ExecutionTree(g_solver, g_expr_builder, g_searcher);

  bool isRestart = false;
  while (true) {
    // 1. fetch all covnew seed, but not execute before
    // 2. symbolic execute all seed, and get path constraints tree
    // 3. rebuild PCT
    // 4. use SMT Solver to generate covnew SEED
    // 5. generate AFL seed evaluator
    // 6. use filter to AFL++, and restart AFL++

    // step(1) : rebuild PCT from AFL
    std::vector<fs::path> covnew_seeds =
        afl_config.get_unseen_seeds(afl_config.queue, state.processed_seeds);

    if (covnew_seeds.empty()){
      std::cerr << "[PCT] SMT dump new testcases ...\n";

      // step(3) : execute the inputs from PCT, decide which cov-new
      std::vector<TreeNode *> tobeExplore =
          executionTree->selectWillBeVisitedNodes(64);
      std::cerr << "[PCT] Select nodes : " << tobeExplore.size() << "\n";
      execute_pct(&tobeExplore, &state, &symcc, &afl_config);

//    std::cerr << "[zgf dbg] execution tree after DSE : " << "\n";
//    executionTree->printTree(true);
//    std::cerr << "========\n";

      // step (4) : dump the visited leaf node to build failed pass
      std::vector<TreeNode *> terminalNodes =
          executionTree->getHasVisitedLeafNodes(curr_depth);
      std::set<uint32_t> currExitNodeIDs;
      for (auto node : terminalNodes)
        currExitNodeIDs.insert(node->id);

      bool hasChanged = currExitNodeIDs != lastExitNodes;
      std::cerr << "[PCT] Evaluator Changed : " << hasChanged << "\n";

      if (hasChanged){
        PCT::TransformPass TP;
        if(TP.buildEvaluator(executionTree, curr_depth)){
          // update the changed exit nodes
          lastExitNodes.clear();
          lastExitNodes.insert(currExitNodeIDs.begin(), currExitNodeIDs.end());

          TP.dumpEvaluator(state.evaluator_file.string());

          std::this_thread::sleep_for(5s);

          // AFL rename all seeds
          state.processed_seeds.clear();
          isRestart = true;
        }
      }else{
        curr_depth += 2;
      }
      std::this_thread::sleep_for(3s);
    }else{
      // step(2) : execute inputs from afl, and rebuild PCT
      std::cerr << "[PCT] AFL new test cases : " << covnew_seeds.size()
                << ", isRestart : " << isRestart << "\n";
      for (const auto& input : covnew_seeds){
        //std::cerr << "AFL NEW : " << input.string() << "\n";
        state.processed_seeds.insert(input);
        if (!isRestart)
          execute_fuzzer(input, &state, &symcc, &afl_config);
      }
      isRestart = false;
      std::this_thread::sleep_for(1s);
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