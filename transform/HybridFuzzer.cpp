#include "HybridFuzzer.h"

static bool ends_with(const std::string& str, const std::string& suffix) {
  if (suffix.size() > str.size()) return false;
  return str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

static bool starts_with(const std::string& str, const std::string& prefix) {
  if (prefix.size() > str.size()) return false;
  return str.compare(0, prefix.size(), prefix) == 0;
}

AflMap AflMap::load(const fs::path &path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    throw std::runtime_error("Failed to read the AFL bitmap that afl-showmap should have generated at " + path.string());
  }
  std::vector<uint8_t> buffer(std::istreambuf_iterator<char>(file), {});
  return AflMap{buffer};
}

bool AflMap::merge(const AflMap& other) {
  if (other.data.empty()) return false;
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

TestcaseScore TestcaseScore::new_score(const fs::path& path) {
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

AflConfig AflConfig::load(const fs::path& fuzzer_output) {
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
      fuzzer_output / "queue"
  };
}

/////////////////////////

std::optional<fs::path> AflConfig::best_new_testcase(
    const std::set<fs::path>& seen) {
  std::vector<fs::path> candidates;
  for (const auto& entry : fs::directory_iterator(queue)) {
    if (entry.is_regular_file() && seen.find(entry.path()) == seen.end()) {
      candidates.push_back(entry.path());
    }
  }

  if (candidates.empty()) return std::nullopt;

  auto best = *std::max_element(candidates.begin(), candidates.end(),
                                [](const fs::path& a, const fs::path& b) {
                                  return TestcaseScore::new_score(a) < TestcaseScore::new_score(b);
                                });
  return best;
}

std::vector<fs::path> AflConfig::get_unseen_testcases(
    const std::set<fs::path>& seen) {
  std::vector<fs::path> candidates;
  for (const auto& entry : fs::directory_iterator(queue)) {
    if (entry.is_regular_file() && seen.find(entry.path()) == seen.end()) {
      candidates.push_back(entry.path());
    }
  }
  return candidates;
}

AflShowmapResult AflConfig::run_showmap(
    const fs::path& testcase_bitmap, const fs::path& testcase) const {
  std::vector<std::string> args = {"timeout", "-k", "5", std::to_string(TIMEOUT), show_map.string()};
  if (use_qemu_mode) args.push_back("-Q");
  args.insert(args.end(), {"-t", "5000", "-m", "none", "-b", "-o", testcase_bitmap.string()});
  auto cmd_with_input = insert_input_file(target_command, testcase);
  args.insert(args.end(), cmd_with_input.begin(), cmd_with_input.end());

  // Build command line string
  std::string cmdline;
  for (const auto& arg : args) {
    cmdline += arg + " ";
  }

  std::cerr << "Running afl-showmap as follows: " << cmdline << "\n"; // debug

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

/////////////////////////

std::chrono::microseconds SymCC::parse_solver_time(const std::string& output) {
  std::regex re(R"("solving_time": (\d+))");
  std::sregex_iterator iter(output.begin(), output.end(), re);
  std::sregex_iterator end;

  std::smatch last_match;
  while (iter != end) {
    last_match = *iter;
    ++iter;
  }

  if (last_match.empty())
    return std::chrono::microseconds(0);
  uint64_t micros = std::stoull(last_match[1].str());
  return std::chrono::microseconds(micros);
}

SymCCResult SymCC::run(const fs::path& input, const fs::path& output_dir) {
  fs::copy_file(input, input_file, fs::copy_options::overwrite_existing);
  //fs::create_directories(output_dir);

  std::vector<std::string> args = {"timeout", "-k", "5", std::to_string(TIMEOUT)};
  args.insert(args.end(), command.begin(), command.end());

  setenv("SYMCC_ENABLE_LINEARIZATION", "1", 1);
  setenv("SYMCC_AFL_COVERAGE_MAP", bitmap.c_str(), 1);
  setenv("SYMCC_OUTPUT_DIR", output_dir.c_str(), 1);
  setenv("SYMCC_INPUT_FILE", input_file.c_str(), 1);

  std::string cmdline;
  for (const auto& arg : args) cmdline += arg + " ";
  std::cerr << "Running SymCC as follows: " << cmdline << "\n";

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

  if (use_standard_input) {
    // Parent writes input to child's stdin via another pipe (omitted for brevity)
    // For simplicity, we assume non-stdin mode or rely on SYMCC_INPUT_FILE
    // In full impl, you'd create a stdin pipe similar to afl-showmap
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

  bool killed = false;
  if (WIFEXITED(status)) {
    int code = WEXITSTATUS(status);
    killed = (code == 124 || code == 125); // timeout returns 124 or 125
  } else if (WIFSIGNALED(status)) {
    killed = true;
  }

  std::vector<fs::path> new_tests;
  for (const auto& entry : fs::directory_iterator(output_dir)) {
    if (entry.is_regular_file()) {
      new_tests.push_back(entry.path());
    }
  }

  auto solver_time_opt = parse_solver_time(stderr_output);
  if (solver_time_opt.count() != 0  && solver_time_opt > total_time) {
    std::cerr << "Backend reported inaccurate solver time!\n";
    solver_time_opt = std::chrono::microseconds(total_time.count());
  }

  // 转换为 microseconds
  auto total_us = std::chrono::duration_cast<std::chrono::microseconds>(total_time);

  return SymCCResult{
      std::move(new_tests),
      killed,
      total_us,
      solver_time_opt
  };
}

/////////////////////////////////

void State::test_input(const fs::path& input, SymCC& symcc, const AflConfig& afl_config) {
  std::cerr << "Running on input " << input.string() << "\n";

//    uint64_t num_interesting = 0, num_total = 0;

  auto result = symcc.run(input, conditions.path);
//    for (const auto& new_test : result.test_cases) {
//      auto res = process_new_testcase(new_test, input, tmp_dir, afl_config);
//      ++num_total;
//      if (res == TestcaseResult::New) {
//        ++num_interesting;
//      }
//    }
//
//    std::cerr << "Generated " << num_total << " testcases, " << num_interesting << " new\n";

  if (result.killed) {
    std::cerr << "The target process was killed (probably timeout or OOM); archiving to "
              << hangs.path.string() << "\n";
    copy_testcase(input, hangs, input);
  }

  processed_files.insert(input);
  stats.add_execution(result);
}

void State::copy_testcase(const fs::path& src, TestcaseDir& dest, const fs::path& parent) {
  auto parent_filename = parent.filename();
  std::string orig_name = parent_filename.string();

  // 检查是否以 "id:" 开头
  // 提取 ID 部分：从索引 3 到 8（共 6 个字符）
  if (orig_name.substr(0, 3) == "id:" &&
      orig_name.length() >= 9) {
    std::string orig_id = orig_name.substr(3, 6); // [3, 9)

    // 格式化新文件名：id:{:06},src:{}
    std::ostringstream oss;
    oss << "id:" << std::setw(6)
        << std::setfill('0') << dest.current_id
        << ",src:" << orig_id;
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
  } else {
    std::cerr << "Test case "<< parent.string()
              << " does not contain a proper ID\n";
  }
}

TestcaseResult State::process_new_testcase(
    const fs::path& testcase,
    const fs::path& parent,
    const fs::path& tmp_dir,
    const AflConfig& afl_config) {
  std::cerr << "Processing test case " << testcase.string() << "\n";
  auto bitmap_path = tmp_dir / "testcase_bitmap";

  auto showmap_res = afl_config.run_showmap(bitmap_path, testcase);
  switch (showmap_res.kind) {
  case AflShowmapResultKind::Success: {
    bool interesting = current_bitmap.merge(showmap_res.map);
    if (interesting) {
      copy_testcase(testcase, queue, parent);
      return TestcaseResult::New;
    }
    return TestcaseResult::Uninteresting;
  }
  case AflShowmapResultKind::Hang:
    std::cerr << "Ignoring new test case "<< testcase.string() << " because afl-showmap timed out\n";
    return TestcaseResult::Hang;
  case AflShowmapResultKind::Crash:
    std::cerr << "Test case " << testcase.string() << " crashes afl-showmap; probably interesting\n";
    copy_testcase(testcase, crashes, parent);
    copy_testcase(testcase, queue, parent);
    return TestcaseResult::Crash;
  default:
    return TestcaseResult::Uninteresting;
  }
  return TestcaseResult::Uninteresting; // unreachable
}