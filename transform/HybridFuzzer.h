//
// Created by aaa on 2025/12/24.
//

#ifndef SYMCC_HYBRIDFUZZER_H
#define SYMCC_HYBRIDFUZZER_H

#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <regex>
#include <set>
#include <string>
#include <vector>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

namespace fs = std::filesystem;
using namespace std::chrono_literals;

constexpr uint32_t TIMEOUT = 90; // seconds
constexpr auto STATS_INTERVAL_SEC = 60s;

enum class TestcaseResult {
  Uninteresting,
  New,
  Hang,
  Crash
};

enum class AflShowmapResultKind { Success, Hang, Crash };

bool ends_with(const std::string& str, const std::string& suffix) {
  if (suffix.size() > str.size()) return false;
  return str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool starts_with(const std::string& str, const std::string& prefix) {
  if (prefix.size() > str.size()) return false;
  return str.compare(0, prefix.size(), prefix) == 0;
}

bool is_under_directory(const std::string& file_path_str, const fs::path& base_dir) {
  fs::path file_path = fs::absolute(file_path_str);
  fs::path base = fs::absolute(base_dir);

  file_path = fs::weakly_canonical(file_path);
  base = fs::weakly_canonical(base);

  if (file_path.string().length() > base.string().length() &&
      file_path.string().substr(0, base.string().length()) == base) {
    return true;
  }

  return false;
}

std::vector<fs::path> get_pct_solution(fs::path& dir) {
  std::vector<fs::path> result;

  if (!fs::exists(dir) || !fs::is_directory(dir)) {
    return result;
  }

  for (const auto& entry : fs::directory_iterator(dir)) {
    if (entry.is_regular_file()) {
      const std::string filename = entry.path().filename().string();
      if (filename.substr(0, 4) == "pct_") {
        result.push_back(entry.path());
      }
    }
  }

  return result;
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

inline bool remove_file(const fs::path& p) {
  if (!fs::exists(p) || fs::is_directory(p)) {
    return true;
  }
  std::error_code ec;
  return fs::remove(p, ec);
}

// ----------------------------
// AflMap
// ----------------------------
class AflMap {
public:
  std::vector<uint8_t> data;

  AflMap() = default;
  AflMap(std::vector<uint8_t> d) : data(std::move(d)) {}

  static AflMap load(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
      throw std::runtime_error("Failed to read the AFL bitmap that afl-showmap should have generated at " + path.string());
    }
    std::vector<uint8_t> buffer(std::istreambuf_iterator<char>(file), {});
    return AflMap{buffer};
  }

  bool merge(const AflMap& other) {
    if (other.data.empty())
      return false;
    if (this->data.empty()) {
      this->data = other.data;
      return true;
    }

    const auto& new_data = other.data;

    if (data.size() != new_data.size()) {
      throw std::runtime_error(
          "Coverage maps must have the same size (" + std::to_string(data.size()) +
          " and " + std::to_string(new_data.size()) + ")");
    }

    bool interesting = false;
    for (size_t i = 0; i < data.size(); ++i) {
      uint8_t old = data[i];
      data[i] |= new_data[i];
      if (data[i] != old) {
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
  int64_t neg_file_size; // larger file => smaller score
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
};

// ----------------------------
// AflShowmapResult
// ----------------------------
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
  fs::path queue;
  fs::path input_dir;

  static AflConfig load(const fs::path& fuzzer_output) {
    fs::path stats_file = fuzzer_output / "fuzzer_stats";
    std::ifstream file(stats_file);
    if (!file) {
      throw std::runtime_error("Failed to open fuzzer stats at " + stats_file.string());
    }

    std::string line;
    std::string command_line;
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

    // Tokenize (simple split by space, may break on paths with spaces — but matches Rust logic)
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

    fs::path input_dir;
    for (size_t i = 0; i < tokens.size(); ++i) {
      if (tokens[i] == "-i" && i + 1 < tokens.size()) {
        input_dir = tokens[i + 1];
        break;
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
//    bool qemu_mode = std::find(tokens.begin(), tokens.end(), "-Q") != tokens.end();

    return AflConfig{
        afl_binary_dir / "afl-showmap",
        target_cmd,
        use_stdin,
        fuzzer_output / "queue",
        input_dir
    };
  }

  std::vector<fs::path> get_unseen_seeds(
      fs::path &dir, const std::set<fs::path>& seen) const {
    std::vector<fs::path> candidates;
    for (const auto& entry : fs::directory_iterator(dir)) {
      if (entry.is_regular_file() &&
          seen.find(entry.path()) == seen.end() &&
          starts_with(entry.path().filename().string(), "id:0")) {
        candidates.push_back(entry.path());
      }
    }
    return candidates;
  }

  AflShowmapResult run_showmap(const fs::path& testcase_bitmap, const fs::path& testcase) const {
    std::vector<std::string> args = {"timeout", "-k", "5", std::to_string(TIMEOUT), show_map.string()};
//    if (use_qemu_mode)
//      args.emplace_back("-Q");
    args.insert(args.end(), {"-t", "5000", "-m", "none", "-b", "-o", testcase_bitmap.string()});
    auto cmd_with_input = insert_input_file(target_command, testcase);
    args.insert(args.end(), cmd_with_input.begin(), cmd_with_input.end());

    // Build command line string
//    std::string cmdline;
//    for (const auto& arg : args) cmdline += arg + " ";
//    std::cerr << "Running afl-showmap as follows: " << cmdline << "\n"; // debug

    int pipefd[2];
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
  fs::path constraint_file;
  bool killed;
  std::chrono::microseconds total_time;
};

// ----------------------------
// SymCC
// ----------------------------
class SymCC {
public:
  fs::path input_file, work_dir;
  fs::path bitmap;
  bool use_standard_input = false;
  std::vector<std::string> command;

  SymCC(fs::path output_dir, const std::vector<std::string>& cmd)
      : input_file(output_dir / ".cur_input")
      , work_dir(output_dir)
      , bitmap(output_dir / "bitmap")
      , command(insert_input_file(cmd, input_file)) {}

  SymCCResult run(const fs::path& input, const fs::path& output_dir) {
    fs::copy_file(input, input_file, fs::copy_options::overwrite_existing);

    std::vector<std::string> args = {"timeout", "-k", "5", std::to_string(TIMEOUT)};
    args.insert(args.end(), command.begin(), command.end());

    setenv("SYMCC_ENABLE_LINEARIZATION", "1", 1);
    setenv("SYMCC_AFL_COVERAGE_MAP", bitmap.c_str(), 1);
    setenv("SYMCC_OUTPUT_DIR", output_dir.c_str(), 1);
    setenv("SYMCC_INPUT_FILE", input_file.c_str(), 1);

//    std::string cmdline;
//    for (const auto& arg : args) cmdline += arg + " ";
//    std::cerr << "Running SymCC as follows: " << cmdline << "\n";

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
        // stdin will be piped by parent
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

    bool killed = false;
    if (WIFEXITED(status)) {
      int code = WEXITSTATUS(status);
      killed = (code == 124 || code == 125); // timeout returns 124 or 125
    } else if (WIFSIGNALED(status)) {
      killed = true;
    }

    //std::cerr << "[zgf dbg] symcc output : " << stderr_output << "\n";

    fs::path constriant_path = output_dir / "000001.pct";
    auto total_us = std::chrono::duration_cast<std::chrono::microseconds>(total_time);

    return SymCCResult{
        constriant_path,
        killed,
        total_us
    };
  }
};

// -------------------------------
// Stats class
// -------------------------------
struct Stats {
  uint32_t total_count = 0;
  std::chrono::microseconds total_time{0};
  uint32_t failed_count = 0;
  std::chrono::microseconds failed_time{0};

  void add_execution(const SymCCResult& result) {
    if (result.killed) {
      ++failed_count;
      failed_time += result.total_time;
    } else {
      ++total_count;
      total_time += result.total_time;
    }
  }

  void log(std::ostream& out) const {
    out << "Successful executions: " << total_count << "\n";
    out << "Time in successful executions: " << total_time.count() / 1000000 << "s\n";

    if (total_count > 0) {
      auto avg = total_time / total_count;
      out << "Avg time per successful execution: " << avg.count() / 1000000<< "s\n";
    }

    out << "Failed executions: " << failed_count << "\n";
    out << "Time spent on failed executions: " << failed_time.count() / 1000000 << "s\n";
    if (failed_count > 0) {
      auto avg_fail = failed_time / failed_count;
      out << "Avg time in failed executions: " << avg_fail.count() / 1000000 << "s\n";
    }

    out << "--------------------------------------------------------------------------------\n"
        << std::flush;
  }
};

// -------------------------------
// State class
// -------------------------------
class State {
public:
  AflMap current_bitmap;
  std::set<fs::path> processed_seeds;
  TestcaseDir queue, hangs, crashes, conditions, seen, solved;
  Stats stats;
  std::ofstream stats_file;
  fs::path evaluator_file;
  std::chrono::steady_clock::time_point last_stats_output;

  static State initialize(const fs::path& output_dir, const fs::path& fuzzer_output) {
    fs::create_directory(output_dir);
    return State{
        .current_bitmap = AflMap{},
        .processed_seeds = {},
        .queue      = TestcaseDir{fuzzer_output / "queue"},
        .hangs      = TestcaseDir{fuzzer_output / "hangs"},
        .crashes    = TestcaseDir{fuzzer_output / "crashes"},
        .conditions = TestcaseDir{output_dir / "conditions"},
        .seen       = TestcaseDir{output_dir / "seen"},
        .solved     = TestcaseDir{output_dir / "solved"},
        .stats      = {},
        .stats_file = std::ofstream{output_dir / "stats"},
        .evaluator_file    = output_dir / "pct-evaluator.c",
        .last_stats_output = std::chrono::steady_clock::now()
    };
  }

  fs::path concolic_execution(
      const fs::path& input, SymCC& symcc, const AflConfig& afl_config) {
    auto result = symcc.run(input, conditions.path);
    if (result.killed) {
      std::cerr << "The target process was killed (probably timeout or OOM); archiving to "
                << hangs.path.string() << "\n";
      copy_testcase_to_dir(input, hangs, false);
    }
    processed_seeds.insert(input);
    stats.add_execution(result);
    return result.constraint_file;
  }

  fs::path copy_testcase_to_dir(
      const fs::path& src, TestcaseDir& dest, bool isCovNew) {
    // 格式化新文件名：id:{:06},src:{}
    std::ostringstream oss;
    uint32_t newID = 900000 + dest.current_id;
    oss << "id:" << std::setw(6) << std::setfill('0') << newID
        << ",op:pct";
    if (isCovNew)
      oss << ",+cov";
    std::string new_name = oss.str();
    fs::path target = dest.path / new_name;

    try {
      fs::copy_file(src, target, fs::copy_options::overwrite_existing);
    } catch (const fs::filesystem_error& e) {
      std::cerr << "Failed to copy the test case from ["
                << src.string() << "] to ["
                << dest.path.string() << "] :" << e.what() << "\n";
    }

    dest.current_id++;
    return target;
  }

  TestcaseResult evaluate_new_testcase(const fs::path& testcase,
                                       const fs::path& symcc_dir,
                                       const AflConfig& afl_config,
                                       bool  isFromFuzzer) {
    //std::cerr << "Processing test case " << testcase.string() << "\n";
    auto bitmap_path = symcc_dir / "testcase_bitmap";

    auto showmap_res = afl_config.run_showmap(bitmap_path, testcase);
    switch (showmap_res.kind) {
    case AflShowmapResultKind::Success: {
      bool interesting = current_bitmap.merge(showmap_res.map);
      if (interesting && !isFromFuzzer) {
        fs::path newCase = copy_testcase_to_dir(testcase, queue, true);
        std::cerr << "[PCT] Covnew : " << newCase.string() << "\n";
        return TestcaseResult::New;
      }
      return TestcaseResult::Uninteresting;
    }
    case AflShowmapResultKind::Hang:
      //std::cerr << "Ignoring new test case "<< testcase.string() << " because afl-showmap timed out\n";
      return TestcaseResult::Hang;
    case AflShowmapResultKind::Crash:{
      if (!isFromFuzzer){
        copy_testcase_to_dir(testcase, crashes, false);
        fs::path newCase = copy_testcase_to_dir(testcase, queue, true);
        std::cerr << "[PCT] New Crash Testcase : " << newCase.string() << "\n";
      }
      return TestcaseResult::Crash;
    }
    default:
      return TestcaseResult::Uninteresting;
    }
    return TestcaseResult::Uninteresting; // unreachable
  }
};

#endif // SYMCC_HYBRIDFUZZER_H
