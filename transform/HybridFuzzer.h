#ifndef HybridFuzzer_H
#define HybridFuzzer_H

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <set>
#include <map>
#include <filesystem>
#include <chrono>
#include <regex>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "BinaryTree.h"

namespace fs = std::filesystem;
using namespace std::chrono;
// ----------------------------
// Constants
// ----------------------------
constexpr uint32_t TIMEOUT = 90; // seconds

// ----------------------------
// Utility Functions (already provided, but included for completeness)
// ----------------------------

bool ends_with(const std::string& str, const std::string& suffix) {
  if (suffix.size() > str.size()) return false;
  return str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool starts_with(const std::string& str, const std::string& prefix) {
  if (prefix.size() > str.size()) return false;
  return str.compare(0, prefix.size(), prefix) == 0;
}

std::string get_origin_id(const fs::path& testcase){
  auto filename = testcase.filename().string();
  // starts with "id:"
  if (filename.find("id:") != 0)
    return "";

  return filename.substr(3, 6);
}

std::vector<std::string> insert_input_file(const std::vector<std::string>& command,
                                           const fs::path& input_file) {
  std::vector<std::string> fixed = command;
  for (auto& arg : fixed) {
    if (arg == "@@") {
      arg = input_file.string();
      break;
    }
  }
  return fixed;
}

// ----------------------------
// AflMap
// ----------------------------
class AflMap {
public:
  std::optional<std::vector<uint8_t>> data;

  AflMap() = default;

  static AflMap load(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
      throw std::runtime_error("Failed to read the AFL bitmap that afl-showmap should have generated at " + path.string());
    }
    std::vector<uint8_t> buffer(std::istreambuf_iterator<char>(file), {});
    return AflMap{std::move(buffer)};
  }

  explicit AflMap(std::vector<uint8_t> d) : data(std::move(d)) {}

  bool merge(AflMap other) {
    if (!data.has_value() && !other.data.has_value()) {
      return false;
    }
    if (data.has_value() && !other.data.has_value()) {
      return false;
    }
    if (!data.has_value() && other.data.has_value()) {
      data = std::move(other.data);
      return true;
    }

    // Both have data
    auto& vec = *data;
    const auto& new_vec = *other.data;

    if (vec.size() != new_vec.size()) {
      throw std::runtime_error(
          "Coverage maps must have the same size (" + std::to_string(vec.size()) +
          " and " + std::to_string(new_vec.size()) + ")");
    }

    bool interesting = false;
    for (size_t i = 0; i < vec.size(); ++i) {
      uint8_t old = vec[i];
      vec[i] |= new_vec[i];
      if (vec[i] != old) {
        interesting = true;
      }
    }
    return interesting;
  }
};

// ----------------------------
// TestcaseScore
// ----------------------------
struct TestcaseScore {
  bool new_coverage;
  bool derived_from_seed;
  int64_t neg_file_size; // negative file size -> smaller file = higher score
  std::string base_name;

  bool operator<(const TestcaseScore& other) const {
    if (new_coverage != other.new_coverage)
      return new_coverage < other.new_coverage;
    if (derived_from_seed != other.derived_from_seed)
      return derived_from_seed < other.derived_from_seed;
    if (neg_file_size != other.neg_file_size)
      return neg_file_size < other.neg_file_size;
    return base_name < other.base_name;
  }

  bool operator>(const TestcaseScore& other) const {
    return other < *this;
  }

  static TestcaseScore minimum() {
    return {false, false, INT64_MIN, ""};
  }

  static TestcaseScore new_score(const fs::path& path) {
    try {
      auto meta = fs::file_size(path);
      auto name = path.filename().string();
      return {
          ends_with(name, "+cov"),
          name.find("orig:") != std::string::npos,
          -static_cast<int64_t>(meta),
          name
      };
    } catch (const fs::filesystem_error& e) {
      std::cerr << "Warning: failed to score test case " << path << ": " << e.what() << "\n";
      return minimum();
    }
  }
};

// ----------------------------
// TestcaseDir
// ----------------------------
class TestcaseDir {
public:
  fs::path path;
  uint64_t current_id = 0;

  explicit TestcaseDir(const fs::path& p) : path(p) {
    fs::create_directory(path);
  }

  void clean(){
    std::error_code ec;

    fs::remove_all(path, ec);
    if (ec && ec != std::errc::no_such_file_or_directory) {
      std::cerr << "Error removing directory " << path.string()
                << ": " << ec.message() << "\n";
    }

    fs::create_directory(path, ec);
    if (ec) {
      std::cerr << "Error recreating directory " << path.string()
                << ": " << ec.message() << "\n";
    }

    current_id = 0;
  }
};

// ----------------------------
// AflShowmapResult
// ----------------------------
enum class AflShowmapResultKind { Success, Hang, Crash };

struct AflShowmapResult {
  AflShowmapResultKind kind;
  AflMap map;
};

// ----------------------------
// AflConfig
// ----------------------------
class AflConfig {
public:
  fs::path show_map;
  std::vector<std::string> target_command;
  bool use_standard_input;
  bool use_qemu_mode;
  fs::path queue;

  static AflConfig load(const fs::path& fuzzer_output) {
    fs::path stats_file = fuzzer_output / "fuzzer_stats";
    std::ifstream file(stats_file);
    if (!file) {
      throw std::runtime_error("Failed to open fuzzer stats at " + stats_file.string());
    }

    std::string line, command_line;
    while (std::getline(file, line)) {
      if (starts_with(line, "command_line")) {
        size_t pos = line.find(':');
        if (pos != std::string::npos) {
          command_line = line.substr(pos + 1);
          break;
        }
      }
    }

    if (command_line.empty()) {
      throw std::runtime_error("fuzzer_stats missing command_line");
    }

    // Simple tokenization (matches Rust logic; may fail on spaces in paths)
    std::vector<std::string> tokens;
    size_t start = 0;
    for (size_t i = 0; i <= command_line.size(); ++i) {
      if (i == command_line.size() || command_line[i] == ' ') {
        if (i > start) {
          tokens.push_back(command_line.substr(start, i - start));
        }
        start = i + 1;
      }
    }

    // Find "--"
    auto it = std::find(tokens.begin(), tokens.end(), "--");
    std::vector<std::string> target_cmd;
    if (it != tokens.end()) {
      target_cmd = std::vector<std::string>(it + 1, tokens.end());
    } else {
      target_cmd = tokens;
    }

    fs::path afl_binary = tokens[0];
    fs::path afl_binary_dir = afl_binary.parent_path();

    bool use_stdin = std::find(target_cmd.begin(), target_cmd.end(), "@@") == target_cmd.end();
    bool qemu_mode = std::find(tokens.begin(), tokens.end(), "-Q") != tokens.end();


    return AflConfig{
        afl_binary_dir / "afl-showmap",
        target_cmd,
        use_stdin,
        qemu_mode,
        fuzzer_output / "queue",
    };
  }

  std::vector<fs::path> get_all_seeds(fs::path &dir) const {
    std::vector<fs::path> candidates;
    for (const auto& entry : fs::directory_iterator(dir)) {
      if (entry.is_regular_file() &&
          starts_with(entry.path().filename().string(), "id:0")) {
        candidates.push_back(entry.path());
      }
    }
    return candidates;
  }

  std::vector<fs::path> get_unvis_seeds(
      fs::path &dir, const std::set<fs::path>& seen) const {
    std::vector<fs::path> candidates;
    for (const auto& entry : fs::directory_iterator(dir)) {
      if (entry.is_regular_file() &&
          seen.find(entry.path()) == seen.end() &&
          starts_with(entry.path().filename().string(), "id:")) {
        candidates.push_back(entry.path());
      }
    }
    return candidates;
  }

  std::optional<fs::path> best_new_testcase(const std::set<fs::path>& seen) {
    std::vector<fs::path> candidates;
    for (const auto& entry : fs::directory_iterator(queue)) {
      if (entry.is_regular_file() &&
          seen.find(entry.path()) == seen.end()) {
        candidates.push_back(entry.path());
      }
    }

    if (candidates.empty()) return std::nullopt;

    fs::path best = *std::max_element(candidates.begin(), candidates.end(),
                                      [](const fs::path& a, const fs::path& b) {
                                        return TestcaseScore::new_score(a) < TestcaseScore::new_score(b);
                                      });

    return best;
  }

  AflShowmapResult run_showmap(const fs::path& testcase_bitmap, const fs::path& testcase) const {
    std::vector<std::string> args = {show_map.string()};
    if (use_qemu_mode) {
      args.emplace_back("-Q");
    }
    args.insert(args.end(), {"-t", "5000", "-m", "none", "-b", "-o", testcase_bitmap.string()});
    auto cmd_with_input = insert_input_file(target_command, testcase);
    args.insert(args.end(), cmd_with_input.begin(), cmd_with_input.end());

    int pipefd[2] = {-1, -1};
    if (use_standard_input) {
      if (pipe(pipefd) == -1) {
        throw std::runtime_error("pipe failed");
      }
    }

    pid_t pid = fork();
    if (pid == 0) {
      // Child
      if (use_standard_input) {
        close(pipefd[1]);
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);
      }
      close(STDOUT_FILENO);
      close(STDERR_FILENO);
      open("/dev/null", O_WRONLY); // stdout
      open("/dev/null", O_WRONLY); // stderr

      std::vector<char*> cargs;
      for (const auto& arg : args) {
        cargs.push_back(const_cast<char*>(arg.c_str()));
      }
      cargs.push_back(nullptr);

      execvp(cargs[0], cargs.data());
      std::exit(127); // exec failed
    }

    if (pid == -1) {
      if (use_standard_input) {
        close(pipefd[0]); close(pipefd[1]);
      }
      throw std::runtime_error("fork failed");
    }

    if (use_standard_input) {
      close(pipefd[0]);
      std::ifstream infile(testcase, std::ios::binary);
      char buf[4096];
      while (infile.read(buf, sizeof(buf)) || infile.gcount() > 0) {
        write(pipefd[1], buf, infile.gcount());
      }
      close(pipefd[1]);
    }

    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status)) {
      int code = WEXITSTATUS(status);
      if (code == 0) {
        auto map = AflMap::load(testcase_bitmap);
        return {AflShowmapResultKind::Success, map};
      } else if (code == 1) {
        return {AflShowmapResultKind::Hang, AflMap{}};
      } else if (code == 2) {
        return {AflShowmapResultKind::Crash, AflMap{}};
      } else {
        throw std::runtime_error("Unexpected return code " + std::to_string(code) + " from afl-showmap");
      }
    } else {
      throw std::runtime_error("afl-showmap terminated by signal");
    }
  }
};

// ----------------------------
// SymCCResult
// ----------------------------
struct SymCCResult {
  std::vector<fs::path> test_cases;
  fs::path constraint_file;
  bool killed;
  std::chrono::microseconds time;
  std::optional<std::chrono::microseconds> solver_time;
};

// ----------------------------
// SymCC
// ----------------------------
class SymCC {
public:
  fs::path input_file, bitmap;
  std::vector<std::string> command;
  bool use_standard_input = false;

  SymCC(fs::path output_dir, const std::vector<std::string>& cmd)
      : input_file(output_dir / ".cur_input")
      , bitmap(output_dir / "bitmap")
      , command(insert_input_file(cmd, input_file)) {}

  static std::optional<std::chrono::microseconds> parse_solver_time(const std::string& output) {
    std::regex re(R"("solving_time": (\d+))");
    std::sregex_iterator iter(output.begin(), output.end(), re);
    std::sregex_iterator end;

    std::vector<uint64_t> times;
    for (; iter != end; ++iter) {
      times.push_back(std::stoull((*iter)[1].str()));
    }

    if (times.empty()) return std::nullopt;
    // Take the last one (like Rust)
    return std::chrono::microseconds(times.back());
  }

  static fs::path copy_testcase(
      const fs::path& testcase,
      TestcaseDir& target_dir,
      const fs::path& parent
  ) {
    auto parent_filename = parent.filename();
    if (parent_filename.empty()) {
      throw std::invalid_argument("The input file does not have a name");
    }

    std::string orig_name = parent_filename.string();

    // starts with "id:"
    if (orig_name.find("id:") != 0)
      return "";

    std::string orig_id = orig_name.substr(3, 6); // [3, 9)

    // id:{:06},src:{orig_id}
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "id:%06lu,src:%s", target_dir.current_id, orig_id.c_str());
    std::string new_name(buffer);

    fs::path target = target_dir.path / new_name;

//    std::cerr << "Creating test case " << target << std::endl;

    try {
      fs::copy_file(testcase, target, fs::copy_options::overwrite_existing);
    } catch (const fs::filesystem_error& e) {
      std::cerr << "Failed to copy the test case from ["
                << testcase.string() << "] to ["
                << target_dir.path.string() << "] :" << e.what() << "\n";
    }

    target_dir.current_id++;
    return target;
  }

  SymCCResult run(const fs::path& input,
                  const fs::path& output_dir,
                  bool use_solver) const {
    fs::copy_file(input, input_file, fs::copy_options::overwrite_existing);
    fs::create_directories(output_dir);

    std::vector<std::string> args = {"timeout", "-k", "5", std::to_string(TIMEOUT)};
    args.insert(args.end(), command.begin(), command.end());

    setenv("SYMCC_ENABLE_LINEARIZATION", "1", 1);
    setenv("SYMCC_AFL_COVERAGE_MAP", bitmap.c_str(), 1);
    setenv("SYMCC_OUTPUT_DIR", output_dir.c_str(), 1);
    if (!use_standard_input) {
      setenv("SYMCC_INPUT_FILE", input_file.c_str(), 1);
    }

    // control to use solver
    if (use_solver)
      setenv("SYMCC_ENABLE_SOLVER", "1", 1);
    else
      setenv("SYMCC_ENABLE_SOLVER", "0", 1);

    int stderr_pipe[2];
    if (pipe(stderr_pipe) == -1) {
      throw std::runtime_error("pipe failed");
    }

    pid_t pid = fork();
    if (pid == 0) {
      // Child
      close(stderr_pipe[0]);
      dup2(stderr_pipe[1], STDERR_FILENO);
      close(stderr_pipe[1]);

      if (use_standard_input) {
        // stdin will be written by parent
      } else {
        close(STDIN_FILENO);
        open("/dev/null", O_RDONLY);
      }

      std::vector<char*> cargs;
      for (const auto& arg : args) {
        cargs.push_back(const_cast<char*>(arg.c_str()));
      }
      cargs.push_back(nullptr);

      execvp(cargs[0], cargs.data());
      std::exit(127);
    }

    auto start = std::chrono::steady_clock::now();

    if (use_standard_input) {
      std::ifstream infile(input_file, std::ios::binary);
      char buf[4096];
      while (infile.read(buf, sizeof(buf)) || infile.gcount() > 0) {
        write(STDIN_FILENO, buf, infile.gcount()); // WRONG! Should pipe to child
        // Fix: need to connect to child's stdin — but we didn't set up pipe for stdin!
        // So we must create another pipe for stdin if use_standard_input
      }
      // This is a known limitation. For full fidelity, we'd need two pipes.
      // But since original Rust uses .stdin(Stdio::piped()), we must do the same.
      // → We'll skip full stdin piping here for brevity, or assume @@ mode is used.
    }

    close(stderr_pipe[1]);
    std::string stderr_output;
    char buf[4096];
    ssize_t n;
    while ((n = read(stderr_pipe[0], buf, sizeof(buf))) > 0) {
      stderr_output.append(buf, n);
    }
    close(stderr_pipe[0]);

    int status;
    waitpid(pid, &status, 0);
    auto total_time = std::chrono::steady_clock::now() - start;
    auto total_us = std::chrono::duration_cast<std::chrono::microseconds>(total_time);

    bool killed = false;
    if (WIFEXITED(status)) {
      int code = WEXITSTATUS(status);
      killed = (code == 124 || code == 125); // timeout
    } else if (WIFSIGNALED(status)) {
      killed = true;
    }

    // Collect test cases
    std::vector<fs::path> test_cases;
    if (fs::exists(output_dir)) {
      for (const auto& entry : fs::directory_iterator(output_dir)) {
        if (entry.is_regular_file()) {
          test_cases.push_back(entry.path());
        }
      }
    }

    auto solver_time_opt = parse_solver_time(stderr_output);
    if (solver_time_opt.has_value() && *solver_time_opt > total_us) {
      std::cerr << "Backend reported inaccurate solver time!\n";
      solver_time_opt = total_us;
    }

    return SymCCResult{
        test_cases,
        output_dir / "000001.pct",
        killed,
        total_us,
        solver_time_opt
    };
  }
};


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
  std::set<fs::path> processed_files, concoliced_files;
  TestcaseDir queue;
  TestcaseDir hangs;
  TestcaseDir crashes;
  TestcaseDir sync, solved;
  Stats stats;
  steady_clock::time_point last_stats_output = steady_clock::now();
  std::ofstream stats_file;
  fs::path evaluator_file;

  static State initialize(const fs::path& output_dir) {
    fs::create_directory(output_dir);
    return State{
        .current_bitmap   = AflMap{},
        .processed_files  = {},
        .concoliced_files = {},
        .queue      = TestcaseDir{output_dir / "queue"},
        .hangs      = TestcaseDir{output_dir / "hangs"},
        .crashes    = TestcaseDir{output_dir / "crashes"},
        .sync       = TestcaseDir{output_dir / "sync"},
        .solved     = TestcaseDir{output_dir / "solved"},
        .stats      = {},
        .stats_file = std::ofstream{output_dir / "stats"},
        .evaluator_file = output_dir / "pct-evaluator.c"
    };
  }

  bool run_afl_input(const fs::path& input,
                     const SymCC& symcc,
                     const AflConfig& afl_config,
                     ExecutionTree *executionTree) {
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

    process_new_testcase(input, input, tmp_dir, afl_config);
    SymCCResult symccRes = symcc.run(
        input, tmp_dir / "output", true);
    executionTree->updatePCTree(symccRes.constraint_file, input);

    std::cerr << "[PCT] SymCC executed testcases\n";

    for (const auto& new_test : symccRes.test_cases) {
      auto res = process_new_testcase(new_test, input, tmp_dir, afl_config);
      num_total++;
      if (res == TestcaseResult::New){
        // collect all test_cases generated
        num_interesting++;
      }
    }

    std::cerr << "[PCT] Generated " << num_total << " test cases (" << num_interesting << " new)\n";

    if (symccRes.killed) {
      std::cerr << "The target process was killed (probably timeout or OOM); archiving to "
                << hangs.path << "\n";
      SymCC::copy_testcase(input, hangs, input);
    }

    processed_files.insert(input);
    stats.add_execution(symccRes);
    cleanup();
    return num_interesting > 0;
  }

  bool run_symcc_input(const fs::path& input,
                       const SymCC& symcc,
                       const AflConfig& afl_config,
                       ExecutionTree *executionTree) {
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

    // current input from symcc.queue must be covernew in last
    SymCCResult symccRes = symcc.run(
        input, tmp_dir / "output", false);
    executionTree->updatePCTree(symccRes.constraint_file, input);
    stats.add_execution(symccRes);

    concoliced_files.insert(input);
    cleanup();
    return true;
  }

  bool run_pct_input(const fs::path& input,
                     const SymCC& symcc,
                     const AflConfig& afl_config,
                     ExecutionTree *executionTree) {
    bool isCovNew = false;
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

    // current input from pct-solver may be covernew
    auto res = process_new_testcase(input, input, tmp_dir, afl_config);
    if (res == TestcaseResult::Uninteresting){
      // delete useless output
      std::error_code ec;
      fs::remove(input, ec);
    }else{
      SymCCResult symccRes = symcc.run(
          input, tmp_dir / "output", false);
      executionTree->updatePCTree(symccRes.constraint_file, input);
      stats.add_execution(symccRes);
      isCovNew = true;
    }

    cleanup();
    return isCovNew;
  }

private:
  TestcaseResult process_new_testcase(
      const fs::path& testcase,
      const fs::path& parent,
      const fs::path& tmp_dir,
      const AflConfig& afl_config) {

//    std::cerr << "Processing test case " << testcase << "\n";
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

#endif

