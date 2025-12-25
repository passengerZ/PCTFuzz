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

ExprBuilder *g_expr_builder;
Solver *g_solver;
CallStackManager g_call_stack_manager;
z3::context *g_z3_context;

std::map<UINT32, ExprRef> cached;
ExecutionTree *executionTree;

template <typename E> constexpr auto to_underlying(E e) noexcept {
  return static_cast<std::underlying_type_t<E>>(e);
}

std::unordered_set<std::string> getPCTFilesInDirectory(const std::string& dir) {
  std::unordered_set<std::string> files;
  try {
    for (const auto& entry : fs::directory_iterator(dir)) {
      if (!entry.is_regular_file())
        continue;

      std::string filename = entry.path().filename().string();
      // 检查是否以 ".pct" 结尾
      if (filename.substr(filename.size() - 4) != ".pct")
        continue;
      files.insert(fs::absolute(entry.path()).string());
    }
  } catch (const fs::filesystem_error& ex) {
    std::cerr << "Error reading directory '" << dir << "': " << ex.what() << "\n";
  }
  return files;
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

void updatePCTree(const std::vector<std::string>& newFiles) {
  for (const auto& fname : newFiles){
    ifstream inputf(fname, std::ofstream::in | std::ofstream::binary);
    if (inputf.fail()){
      std::cerr << "Unable to open a file ["<<
          fname <<"] to update Path Constaint Tree\n";
      continue;
    }

    std::cout << "Load path constraint tree: " << fname << "\n";
    ConstraintSequence cs;
    cs.ParseFromIstream(&inputf);

    TreeNode *root = executionTree->getRoot();
    ExprRef pathCons;
    std::vector<ExprRef> cons;

    for (int i = 0; i < cs.node_size(); i++) {
      const SequenceNode &pnode = cs.node(i);

      if (!pnode.has_constraint())
        continue;

      bool isLastPC = (i == cs.node_size() - 1);

      deserializeToQsymExpr(pnode.constraint(), pathCons);

      PCTNode bNode(pathCons, (pnode.taken() > 0), isLastPC,
                    pnode.b_id(), pnode.b_left(), pnode.b_right());

      int branchTaken  =  pnode.taken() > 0;
      if (branchTaken)
        cons.push_back(pathCons);
      else
        cons.push_back(g_expr_builder->createLNot(pathCons));

//      std::cerr << "[zgf dbg] idx : " << i << ", taken : " << branchTaken << "\n"
//                << pathCons->toString() << "\n";

      if (branchTaken) { /// left is the true branch
        if (root->left) {
          if (root->left->data.constraint->hash() != pathCons->hash()) {
            // if path is divergent, try to rebuild it !
            root->left = executionTree->constructTreeNode(root, bNode);
            std::cerr << "[zgf dbg] left Divergent !!!\n";
          }

          root->left->data.taken = true;
        } else {
          root->left = executionTree->constructTreeNode(root, bNode);
        }

        if (!root->right) {
          root->right = executionTree->constructTreeNode(root, bNode);
          root->right->data.taken = false;
        }
        root = root->left;
      } else {
        if (root->right) {
          if (root->right->data.constraint->hash() != pathCons->hash()) {
            // if path is divergent, try to rebuild it !
            root->right = executionTree->constructTreeNode(root, bNode);
            std::cerr << "[zgf dbg] right Divergent !!!\n";
          }

          root->right->data.taken = false;
        } else {
          root->right = executionTree->constructTreeNode(root, bNode);
        }

        if (!root->left) {
          root->left = executionTree->constructTreeNode(root, bNode);
          root->left->data.taken = true;
        }
        root = root->right;
      }
    }
    PCT::TransformPass TP;
    TP.build(cons);
  }

  executionTree->printTree(true);
}

} // namespace qsym

/*
int main(int argc, char* argv[]) {
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0] << " <watch_dir> <duration_seconds>\n";
    return 1;
  }

  std::string watchDir = argv[1];
  int durationSec = std::stoi(argv[2]);

  // 检查目录是否存在
  if (!fs::exists(watchDir) || !fs::is_directory(watchDir)) {
    std::cerr << "Error: '" << watchDir << "' is not a valid directory.\n";
    return 1;
  }

  qsym::g_z3_context = new z3::context{};
  qsym::g_solver = nullptr; // for QSYM-internal use
  qsym::g_expr_builder = qsym::SymbolicExprBuilder::create();
  qsym::executionTree = new ExecutionTree();

  std::cout << "Watching directory: " << watchDir << "\n";
  std::cout << "Total runtime: " << durationSec << " seconds\n";
  std::cout << "Checking every 30 seconds...\n";

  auto startTime = std::chrono::steady_clock::now();
  auto endTime = startTime + std::chrono::seconds(durationSec);

  // 初始快照
  std::unordered_set<std::string> knownFiles =
      qsym::getPCTFilesInDirectory(watchDir);
  if (!knownFiles.empty()) {
    std::vector<std::string> originPCTFiles(knownFiles.begin(), knownFiles.end());
    qsym::updatePCTree(originPCTFiles);
  }

  while (std::chrono::steady_clock::now() < endTime) {
    std::this_thread::sleep_for(std::chrono::seconds(10));

    auto currentFiles = qsym::getPCTFilesInDirectory(watchDir);
    std::vector<std::string> newFiles;

    // find new files
    for (const auto& file : currentFiles) {
      if (knownFiles.find(file) == knownFiles.end()) {
        newFiles.push_back(file);
      }
    }

    if (!newFiles.empty()) {
      qsym::updatePCTree(newFiles);
      knownFiles = std::move(currentFiles);
    } else {
      std::cout << "[" << std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::steady_clock::now() - startTime).count()
                << "s] No new files.\n";
    }
  }

  std::cout << "Watcher finished after " << durationSec << " seconds.\n";
  return 0;
}
*/

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
  auto afl_config = AflConfig::load(output_dir / fuzzer_name);
  auto state = State::initialize(symcc_dir);

  while (true) {
    auto maybe_input = afl_config.best_new_testcase(state.processed_files);
    if (!maybe_input) {
      std::cout << "Waiting for new test cases...\n";
      std::this_thread::sleep_for(5s);
    } else {
      state.test_input(*maybe_input, symcc, afl_config);
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