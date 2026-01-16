#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>
#include <optional>

#include "HybridFuzzer.h"
#include "BinaryTree.h"
#include "TransformPass.h"
#include "call_stack_manager.h"
#include "qsymExpr.pb.h"
#include "solver.h"

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;
namespace fs = std::filesystem;
using namespace std::chrono;

// Command-line options
cl::opt<std::string> FuzzerName(
    "fuzzer-name", cl::desc("The name of the fuzzer to work with"), cl::Required);

cl::opt<std::string> OutputDir(
    "output-dir", cl::desc("The AFL output directory"), cl::Required);

cl::opt<std::string> SymCCName(
    "name", cl::desc("Name to use for SymCC"), cl::init("symcc"));

cl::opt<std::string> SymCCTargetBin(
    cl::Positional,
    cl::desc("Program under test"),
    cl::Required
);

constexpr seconds STATS_INTERVAL_SEC{60};

uint32_t MAX_DEPTH = 50, BATCH_SIZE = 64;
uint32_t evaluator_depth = 10;

namespace qsym {
ExprBuilder *g_expr_builder;
Solver *g_solver;
CallStackManager g_call_stack_manager;
z3::context *g_z3_context;

SearchStrategy *g_searcher;
ExecutionTree *executionTree;


std::set<uint32_t> lastExitNodes;

void solved_pct(std::vector<TreeNode *> *tobeExplores,
                State *state, SymCC *symcc, AflConfig* afl_config){
  if (tobeExplores->empty())
    return ;

  for (auto node : *tobeExplores){
    std::string testcase = executionTree->generateTestCase(node);
    if (testcase.empty()){
      continue;
    }

    state->run_symcc_input(testcase, *symcc, *afl_config, executionTree);
    state->solved.current_id++;
  }
}

bool build_pct_evaluator(State *state){
  bool isNewEvaluator = false;

  // step (4) : dump the visited leaf node to build failed pass
  std::vector<TreeNode *> deadNodes =
      executionTree->selectDeadNode(evaluator_depth);
  std::set<uint32_t> currTerminalIDs;
  for (auto node : deadNodes)
    currTerminalIDs.insert(node->id);

  bool hasChanged = currTerminalIDs != lastExitNodes;
  std::cerr << "[PCT] Evaluator Changed: " << hasChanged
            << ", DeadNode Size: " << deadNodes.size()
            << ", Depth: " << evaluator_depth << "\n";

  if (!hasChanged){
    return isNewEvaluator;
  }

  PCT::TransformPass TP;
  if(TP.buildEvaluator(executionTree, &deadNodes)){
    // update the changed exit nodes
    lastExitNodes.clear();
    lastExitNodes.insert(currTerminalIDs.begin(), currTerminalIDs.end());

    TP.dumpEvaluator(state->evaluator_file.string());
    isNewEvaluator = true;
  }

  return isNewEvaluator;
}
}
// =============================================================================
// Main
// =============================================================================

int main(int argc, char* argv[]) {
  cl::ParseCommandLineOptions(argc, argv, "Make SymCC collaborate with AFL.\n");

  std::string fuzzer_name_str = FuzzerName;
  std::string output_dir_str  = OutputDir;
  std::string symcc_name_str  = SymCCName;

  fs::path output_dir(output_dir_str);
  if (!fs::exists(output_dir) || !fs::is_directory(output_dir)) {
    std::cerr << "The directory " << output_dir << " does not exist!\n";
    return 1;
  }

  auto afl_queue = output_dir / fuzzer_name_str / "queue";
  if (!fs::exists(afl_queue) || !fs::is_directory(afl_queue)) {
    std::cerr << "The AFL queue " << afl_queue << " does not exist!\n";
    return 1;
  }

  auto symcc_dir = output_dir / symcc_name_str;
  if (fs::exists(symcc_dir)) {
    std::cerr << symcc_dir << " already exists; resuming not supported\n";
    return 1;
  }

  fs::path fuzzer_output = output_dir / fuzzer_name_str;
  auto afl_config = AflConfig::load(fuzzer_output);
  auto state = State::initialize(symcc_dir);

  std::vector<std::string> symcc_command(afl_config.target_command);
  symcc_command[0] = SymCCTargetBin.c_str();
  SymCC symcc(symcc_dir, symcc_command);

  qsym::g_expr_builder = qsym::SymbolicExprBuilder::create();
  qsym::g_z3_context = new z3::context{};
  qsym::g_solver = new qsym::Solver("/dev/null", state.solved.path, "");
  g_searcher = new SearchStrategy();
  executionTree = new ExecutionTree(g_expr_builder, g_solver, g_searcher);

  auto last_evaluator_time = std::chrono::steady_clock::now();
  uint32_t EvaluatorTimeLimitSec = 10;

  while (true) {
    auto new_testcase = afl_config.best_new_testcase(state.processed_files);
    if (new_testcase.has_value()) {
      // clean sync dir to collect DSE dumped testcases
      fs::path local_afl_seed = symcc.copy_testcase(
          *new_testcase, state.sync, new_testcase.value());

      state.processed_files.insert(new_testcase.value());
      state.run_afl_input(local_afl_seed, symcc, afl_config, executionTree);
    }else{
      std::this_thread::sleep_for(seconds(3));
    }

    // compute the evaluator
    auto now = std::chrono::steady_clock::now();

    // make sure in curr_depth, there are no willbeVisited nodes
    std::vector<fs::path> unvis_seeds =
        afl_config.get_unvis_seeds(state.queue.path, state.concoliced_files);

    for (auto ce_seed : unvis_seeds)
      state.run_symcc_input(ce_seed, symcc, afl_config, executionTree);

    bool evalutorStatus = false;

    std::vector<TreeNode *> willbeVisit =
        executionTree->selectNodesFromDepth(evaluator_depth);
    if (willbeVisit.empty())
      evalutorStatus = true;

    if (willbeVisit.size() < BATCH_SIZE){
      std::vector<TreeNode *> extendVisit =
          executionTree->selectNodesFromGroup(BATCH_SIZE - willbeVisit.size());
      willbeVisit.insert(willbeVisit.end(), extendVisit.begin(), extendVisit.end());
    }

    solved_pct(&willbeVisit, &state, &symcc, &afl_config);

    executionTree->updateTobeVisited();

    bool evaluator_limit = (std::chrono::duration_cast<std::chrono::seconds>(
        now - last_evaluator_time).count() >= EvaluatorTimeLimitSec);
    if (evaluator_limit && evaluator_depth < MAX_DEPTH && evalutorStatus){
      if (build_pct_evaluator(&state)){
        if (EvaluatorTimeLimitSec < 120)
          EvaluatorTimeLimitSec += 30;

        std::cerr << "[STOP AFL] : " << state.evaluator_file.string() << std::endl;
      }else{
        if (EvaluatorTimeLimitSec > 30)
          EvaluatorTimeLimitSec -= 10;
      }

      last_evaluator_time = now;
      evaluator_depth += 2;
    }

    if (duration_cast<seconds>(now - state.last_stats_output) > STATS_INTERVAL_SEC) {
      if (!state.stats.log(state.stats_file)) {
        std::cerr << "Failed to log statistics\n";
      }
      state.last_stats_output = now;
    }
  }

  return 0;
}