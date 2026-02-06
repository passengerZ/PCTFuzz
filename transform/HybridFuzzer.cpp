#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
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

namespace qsym {
ExprBuilder *g_expr_builder;
Solver *g_solver;
CallStackManager g_call_stack_manager;
z3::context *g_z3_context;

SearchStrategy *g_searcher;
ExecutionTree *executionTree;

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

  std::vector<DeadZone> deadZones;
  std::set<uint32_t> deadBB;

  uint32_t cnt = 0, batch_size = 8;
  uint32_t updateDeadZone = 0;

  while (true) {
    cnt ++;
    // compute the evaluator
    auto now = std::chrono::steady_clock::now();

    std::cerr << "[PCT] Loops : " << cnt << "\n";
    auto new_testcase = afl_config.best_new_testcase(state.processed_files,
                                                     state.fileHashes);
    if (new_testcase.has_value()) {
//      auto fsize = fs::file_size(new_testcase.value());
//      std::cerr << "[PCT] Sync AFL++ best : " << new_testcase.value().string()
//                << ", file size : " << fsize << "\n";

      state.processed_files.insert(new_testcase.value());
      fs::path local_testcase =
          SymCC::copy_testcase(new_testcase.value(), state.sync, new_testcase.value());
      state.run_afl_input(
          local_testcase, symcc, afl_config, executionTree);
    }
    else{
      std::vector<TreeNode *> willbeVisit =
          executionTree->selectDeepestNodes(batch_size);
      state.run_pct_input(&willbeVisit, symcc, afl_config, executionTree);
    }

    if (cnt % 50 == 0 && deadZones.size() < 50){
      // make sure in curr_depth, there are no willbeVisited nodes
      std::vector<fs::path> unvis_seeds =
          afl_config.get_unvis_seeds(state.queue.path, state.concoliced_files);

      for (const auto& ce_seed : unvis_seeds)
        state.run_symcc_input(ce_seed, symcc, afl_config, executionTree);
      executionTree->cleanTobeVisited();

      std::cerr << "[PCT] Replaied Symcc testcases : " << unvis_seeds.size()
                << ", left Nodes: " << executionTree->tobeVisited.size() << "\n";

      std::vector<TreeNode *> deadNodes = executionTree->selectDeadNode();
      for (auto node : deadNodes) {
        uint32_t BBID = node->data.currBB;
        std::set<uint32_t> domBB = g_searcher->computeDominatorsFor(BBID);

        DeadZone dzone(BBID);

        auto *currNode = node;
        while(currNode != executionTree->getRoot()){
          if (domBB.empty() ||
              domBB.count(currNode->data.currBB))
            dzone.domNodes.push_back(currNode);

          currNode = currNode->parent;
        }

        bool isCollected = false;
        for (const auto &zone : deadZones)
          if (zone.equal(&dzone)){
            isCollected = true;
            break;
          }

        if (!isCollected && !dzone.domNodes.empty()){
          deadZones.push_back(std::move(dzone));
          deadBB.insert(node->data.currBB);
          updateDeadZone += 1;
        }
      }

      std::cerr << "[PCT] Construct Dead Zone : " << deadZones.size()
                << ", isUpdate: " << updateDeadZone << "\n";

      if((updateDeadZone >= 5) || deadZones.size() >= 50){
        PCT::TransformPass TP;
        if (TP.buildEvaluator(executionTree, &deadZones)){
          TP.dumpEvaluator(state.evaluator_file.string());
          std::cerr << "[STOP AFL] : " << state.evaluator_file.string() << "\n";
        }
        updateDeadZone = 0;
      }
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
