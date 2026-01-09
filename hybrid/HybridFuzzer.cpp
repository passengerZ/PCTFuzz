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

// =============================================================================
// TestcaseResult
// =============================================================================

enum class TestcaseResult {
  Uninteresting,
  New,
  Hang,
  Crash
};

// =============================================================================
// Stats
// =============================================================================

struct Stats {
  uint32_t total_count = 0;
  milliseconds total_time{0};
  std::optional<milliseconds> solver_time;
  uint32_t failed_count = 0;
  milliseconds failed_time{0};

  void add_execution(const SymCCResult& result) {
    auto exec_ms = duration_cast<milliseconds>(result.time);
    if (result.killed) {
      failed_count++;
      failed_time += exec_ms;
    } else {
      total_count++;
      total_time += exec_ms;
      if (result.solver_time.has_value()) {
        auto st_ms = duration_cast<milliseconds>(*result.solver_time);
        if (solver_time.has_value()) {
          solver_time = *solver_time + st_ms;
        } else {
          solver_time = st_ms;
        }
      }
    }
  }

  bool log(std::ofstream& out) const {
    try {
      out << "Successful executions: " << total_count << "\n";
      out << "Time in successful executions: " << total_time.count() << "ms\n";

      if (total_count > 0) {
        auto avg = total_time / total_count;
        out << "Avg time per successful execution: " << avg.count() << "ms\n";
      }

      if (solver_time.has_value()) {
        auto st = *solver_time;
        out << "Solver time (successful executions): " << st.count() << "ms\n";

        if (total_time.count() > 0) {
          double share = static_cast<double>(st.count()) / total_time.count() * 100.0;
          out << "Solver time share (successful executions): "
              << std::fixed << std::setprecision(2) << share
              << "% (-> " << (100.0 - share) << "% in execution)\n";
          if (total_count > 0) {
            auto avg_solver = st / total_count;
            out << "Avg solver time per successful execution: "
                << avg_solver.count() << "ms\n";
          }
        }
      }

      out << "Failed executions: " << failed_count << "\n";
      out << "Time spent on failed executions: " << failed_time.count() << "ms\n";

      if (failed_count > 0) {
        auto avg_fail = failed_time / failed_count;
        out << "Avg time in failed executions: " << avg_fail.count() << "ms\n";
      }

      out << "--------------------------------------------------------------------------------\n";
      out.flush();
      return true;
    } catch (const std::exception& e) {
      std::cerr << "Error writing stats: " << e.what() << "\n";
      return false;
    }
  }
};

// =============================================================================
// State
// =============================================================================

class State {
public:
  AflMap current_bitmap;
  std::set<fs::path> processed_files;
  TestcaseDir queue;
  TestcaseDir hangs;
  TestcaseDir crashes;
  Stats stats;
  steady_clock::time_point last_stats_output = steady_clock::now();
  std::ofstream stats_file;

  static std::optional<State> initialize(const fs::path& output_dir) {
    std::error_code ec;

    if (!fs::create_directory(output_dir, ec) && ec) {
      std::cerr << "Failed to create SymCC's directory " << output_dir << ": " << ec.message() << "\n";
      return std::nullopt;
    }

    auto queue_dir   = output_dir / "queue";
    auto hangs_dir   = output_dir / "hangs";
    auto crashes_dir = output_dir / "crashes";
    auto stats_path  = output_dir / "stats";

    auto q = TestcaseDir(queue_dir);
    auto h = TestcaseDir(hangs_dir);
    auto c = TestcaseDir(crashes_dir);

    std::ofstream sf(stats_path);
    if (!sf.is_open()) {
      std::cerr << "Failed to create stats file\n";
      return std::nullopt;
    }

    return State{
        .current_bitmap = AflMap{},
        .processed_files = {},
        .queue = q,
        .hangs = h,
        .crashes = c,
        .stats = {},
        .last_stats_output = steady_clock::now(),
        .stats_file = std::move(sf)
    };
  }

  bool test_input(const fs::path& input, const SymCC& symcc, const AflConfig& afl_config) {
    std::cerr << "Running on input " << input << "\n";

    fs::path tmp_dir;
    {
      const char* tmpdir_env = std::getenv("TMPDIR");
      std::string tmp_base = tmpdir_env ? tmpdir_env : "/tmp";
      std::string pattern = fs::path(tmp_base) / "symcc-XXXXXX";

      std::vector<char> buffer(pattern.begin(), pattern.end());
      buffer.push_back('\0');

      char* result = mkdtemp(buffer.data());
      if (!result) {
        std::cerr << "Failed to create unique temp directory: " << strerror(errno) << "\n";
        return false;
      }
      tmp_dir = fs::path(result);
    }

    auto cleanup = [&tmp_dir]() {
      std::error_code ec;
      fs::remove_all(tmp_dir, ec);
    };

    uint64_t num_total = 0, num_interesting = 0;
    auto symcc_result = symcc.run(input, tmp_dir / "output");
    for (const auto& new_test : symcc_result.test_cases) {
      auto res = process_new_testcase(new_test, input, tmp_dir, afl_config);
      num_total++;
      if (res == TestcaseResult::New) {
        num_interesting++;
      }
    }

    std::cerr << "Generated " << num_total << " test cases (" << num_interesting << " new)\n";

    if (symcc_result.killed) {
      std::cerr << "The target process was killed (probably timeout or OOM); archiving to "
                << hangs.path << "\n";
      SymCC::copy_testcase(input, hangs, input);
    }

    processed_files.insert(input);
    stats.add_execution(symcc_result);
    cleanup();
    return true;
  }

private:
  TestcaseResult process_new_testcase(
      const fs::path& testcase,
      const fs::path& parent,
      const fs::path& tmp_dir,
      const AflConfig& afl_config) {

    std::cerr << "Processing test case " << testcase << "\n";
    auto bitmap_path = tmp_dir / "testcase_bitmap";

    auto showmap_res = afl_config.run_showmap(bitmap_path, testcase);

    switch (showmap_res.kind) {
    case AflShowmapResultKind::Success: {
      bool interesting = current_bitmap.merge(showmap_res.map);
      if (interesting) {
        SymCC::copy_testcase(testcase, queue, parent);
        return TestcaseResult::New;
      }
      return TestcaseResult::Uninteresting;
    }
    case AflShowmapResultKind::Hang:
      std::cerr << "Ignoring new test case " << testcase << " because afl-showmap timed out\n";
      return TestcaseResult::Hang;
    case AflShowmapResultKind::Crash:
      std::cerr << "Test case " << testcase << " crashes afl-showmap; probably interesting\n";
      SymCC::copy_testcase(testcase, crashes, parent);
      SymCC::copy_testcase(testcase, queue, parent);
      return TestcaseResult::Crash;
    default:
      return TestcaseResult::Uninteresting;
    }
  }
};

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

  while (true) {
    auto new_testcase = afl_config.best_new_testcase(state->processed_files);
    if (!new_testcase.has_value()) {
      std::this_thread::sleep_for(seconds(5));
      continue;
    }

    if (!state->test_input(*new_testcase, symcc, afl_config)) {
      std::cerr << "Failed to process input " << *new_testcase << "\n";
    }

    auto now = steady_clock::now();
    if (duration_cast<seconds>(now - state->last_stats_output) > STATS_INTERVAL_SEC) {
      if (!state->stats.log(state->stats_file)) {
        std::cerr << "Failed to log statistics\n";
      }
      state->last_stats_output = now;
    }
  }

  return 0;
}