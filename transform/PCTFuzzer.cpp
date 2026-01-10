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
uint32_t ByteLimit = 1024 * 1024;

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
  case ExprKind::LNot: {
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

void updatePCTree(const fs::path &constraint_file, const fs::path &input) {
  ifstream inputf(constraint_file, std::ofstream::in | std::ofstream::binary);
  if (inputf.fail()){
    std::cerr << "Unable to open a file ["
              << constraint_file <<"] to update Path Constaint Tree\n";
    return;
  }

  ConstraintSequence cs;
  cs.ParseFromIstream(&inputf);

  ExprRef pathCons;
  TreeNode *currNode = executionTree->getRoot();
  for (int i = 0; i < cs.node_size(); i++) {
    const SequenceNode &pnode = cs.node(i);
    if (!pnode.has_constraint())
      continue;

    bool branchTaken = pnode.taken() > 0;

    deserializeToQsymExpr(pnode.constraint(), pathCons);
//    std::cerr << "[zgf dbg] idx : " << i << " " << pathCons->toString() << "\n";
    PCTNode pctNode(pathCons, input, branchTaken, 0, pnode.b_id());

    currNode = executionTree->updateTree(currNode, pctNode);
    if (currNode == executionTree->getRoot())
      break;
  }

}

void execute_fuzzer(std::string input, State *state,
                    SymCC *symcc, AflConfig* afl_config){
  // avoid symcc to failed open afl-busy seed
  fs::path currInput = state->copy_testcase_to_dir(input, state->sync, true);
  input = currInput.string();
  if (input.empty())
    return;

  // merge AFL new input into current Bitmap
  state->evaluate_new_testcase(
      input, symcc->work_dir, *afl_config, true);
  SymCCResult symccRes = state->concolic_execution(
      input, *symcc, *afl_config, true);
  qsym::updatePCTree(symccRes.constraint_file, input);

  for (const auto& new_test : symccRes.test_cases){
    state->evaluate_new_testcase(
        new_test, symcc->work_dir, *afl_config, false);
    // collected concolic execution dumped testcases
    state->copy_testcase_to_dir(new_test, state->sync, false);
  }
}

void execute_dse(std::string input, State *state,
                 SymCC *symcc, AflConfig* afl_config){
  SymCCResult symccRes = state->concolic_execution(
      input, *symcc, *afl_config, false);
  qsym::updatePCTree(symccRes.constraint_file, input);

  state->evaluate_new_testcase(
        input, symcc->work_dir, *afl_config, false);
}

void solved_pct(std::vector<TreeNode *> *tobeExplores,
                 State *state, SymCC *symcc, AflConfig* afl_config){
  if (tobeExplores->empty())
    return ;

  for (auto node : *tobeExplores){
    std::string testcase = executionTree->generateTestCase(node);
    if (testcase.empty())
      continue;

    execute_dse(testcase, state, symcc, afl_config);
    state->solved.current_id++;
  }
}

bool build_pct_evaluator(State *state){
  bool isNewEvaluator = false;

  // step (4) : dump the visited leaf node to build failed pass
  std::vector<TreeNode *> terminalNodes =
      executionTree->selectTerminalNodes(curr_depth);
  std::set<uint32_t> currTerminalIDs;
  for (auto node : terminalNodes)
    currTerminalIDs.insert(node->id);

  bool hasChanged = currTerminalIDs != lastExitNodes;
  std::cerr << "[PCT] Evaluator Changed: " << hasChanged
            << ", Terminal Size: " << terminalNodes.size()
            << ", Depth: " << curr_depth << "\n";

  if (!hasChanged){
    curr_depth += 2;
    return isNewEvaluator;
  }

  PCT::TransformPass TP;
  if(TP.buildEvaluator(executionTree, curr_depth)){
    // update the changed exit nodes
    lastExitNodes.clear();
    lastExitNodes.insert(currTerminalIDs.begin(), currTerminalIDs.end());

    TP.dumpEvaluator(state->evaluator_file.string());
    isNewEvaluator = true;
  }
  return isNewEvaluator;
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

  fs::path fuzzer_output = output_dir / fuzzer_name;
  auto afl_config = AflConfig::load(fuzzer_output);

  std::vector<std::string> symcc_command(afl_config.target_command);
  symcc_command[0] = SymCCTargetBin.c_str();
  SymCC symcc(symcc_dir, symcc_command);

  auto state = State::initialize(symcc_dir);

  qsym::g_z3_context = new z3::context{};
  qsym::g_solver = new qsym::Solver("/dev/null", state.solved.path, ""); // for QSYM-internal use
  qsym::g_expr_builder = qsym::SymbolicExprBuilder::create();
  qsym::g_searcher = new SearchStrategy();
  qsym::executionTree = new ExecutionTree(g_solver, g_expr_builder, g_searcher);

  auto start_time = std::chrono::steady_clock::now();
  auto last_evaluator_time = start_time;

  uint32_t PollInterval = 5;
  uint32_t BatchSeedSize = 64;
  uint32_t EvaluatorTimeLimitSec = 30;

  while (true) {
    std::this_thread::sleep_for(std::chrono::seconds(PollInterval));

    std::vector<fs::path> covnew_seeds =
        afl_config.get_unseen_seeds(afl_queue, state.processed_seeds);

    if (covnew_seeds.empty())
      continue;

    uint32_t seedSize = covnew_seeds.size();
    std::cerr << "[PCT] Got " << seedSize << " new AFL test cases.\n";

    // must clean sync dir before
    state.sync.clean();



    for (const auto& input : covnew_seeds) {
      state.processed_seeds.insert(input);
      if (get_file_bytes(input) > ByteLimit)
        continue;
      execute_fuzzer(input.string(), &state, &symcc, &afl_config);
    }

    // use concolic execution dumped testcase to rebuild PCT
    std::vector<fs::path> concolic_seeds =
        afl_config.get_all_seeds(state.sync.path);
    for (const auto& input : concolic_seeds) {
      execute_dse(input.string(), &state, &symcc, &afl_config);
    }

    // compute the evaluator
    auto now = std::chrono::steady_clock::now();
    bool evaluator_limit = (std::chrono::duration_cast<std::chrono::seconds>(
        now - last_evaluator_time).count() >= EvaluatorTimeLimitSec);

    if (evaluator_limit && curr_depth < MAX_DEPTH){
      std::vector<TreeNode*> tobeExplore =
          executionTree->getWillBeVisitedNodes(2 * BatchSeedSize);

      solved_pct(&tobeExplore, &state, &symcc, &afl_config);
      std::cerr << "[PCT] SMT Selected " << tobeExplore.size()
                << " nodes, Now testcases is "
                << state.solved.current_id <<".\n";

      if (build_pct_evaluator(&state)){
        last_evaluator_time = now;

        if (EvaluatorTimeLimitSec < 300)
          EvaluatorTimeLimitSec += 30;

        std::cerr << "[STOP AFL] : " << state.evaluator_file.string() << std::endl;
      }
    }

    if (now - state.last_stats_output > STATS_INTERVAL_SEC) {
      try {
        state.stats.log(state.stats_file);
        state.last_stats_output = now;
      } catch (const std::exception& e) {
        std::cerr << "Failed to log run-time statistics: " << e.what() << "\n";
      }
    }
  }

  return 0;
}