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
#include "picojson.h"

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

std::set<uint32_t> BBIDSet;
std::set<std::pair<uint32_t, uint32_t>> Trace;
std::map<uint32_t,std::set<uint32_t>> ICFG;

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

void updatePCTree(const fs::path &constraint_file, const fs::path &input) {
  ifstream inputf(constraint_file, std::ofstream::in | std::ofstream::binary);
  if (inputf.fail()){
    std::cerr << "Unable to open a file ["
              << constraint_file <<"] to update Path Constaint Tree\n";
    return;
  }

  std::cout << "Load path constraint tree: " << constraint_file.string() << "\n";
  ConstraintSequence cs;
  cs.ParseFromIstream(&inputf);

  TreeNode *root = executionTree->getRoot();
  ExprRef pathCons;

  for (int i = 0; i < cs.node_size(); i++) {
    const SequenceNode &pnode = cs.node(i);
    if (!pnode.has_constraint())
      continue;

    bool isLastPC = (i == cs.node_size() - 1);
    bool branchTaken = pnode.taken() > 0;

    deserializeToQsymExpr(pnode.constraint(), pathCons);
    PCTNode pctNode(pathCons, input, branchTaken, isLastPC,
                    pnode.b_id(), pnode.b_left(), pnode.b_right());

    root->isVisited = true;
    if (branchTaken) { /// left is the true branch
      if (root->left) {
        if (root->left->data.constraint->hash() != pathCons->hash()) {
          // if path is divergent, try to rebuild it !
          root->left = executionTree->constructTreeNode(root, pctNode, isLastPC);
          std::cerr << "[zgf dbg] left Divergent !!!\n";
        }

        root->left->data.taken = true;
      } else {
        root->left = executionTree->constructTreeNode(root, pctNode, isLastPC);
      }

      if (!root->right) {
        root->right = executionTree->constructTreeNode(root, pctNode, isLastPC);
        root->right->data.taken = false;
//        executionTree->addToBeExploredNodes(root->right, input);
      }
      root = root->left;
    } else {
      if (root->right) {
        if (root->right->data.constraint->hash() != pathCons->hash()) {
          // if path is divergent, try to rebuild it !
          root->right = executionTree->constructTreeNode(root, pctNode, isLastPC);
          std::cerr << "[zgf dbg] right Divergent !!!\n";
        }

        root->right->data.taken = false;
      } else {
        root->right = executionTree->constructTreeNode(root, pctNode, isLastPC);
      }

      if (!root->left) {
        root->left = executionTree->constructTreeNode(root, pctNode, isLastPC);
        root->left->data.taken = true;
//        executionTree->addToBeExploredNodes(root->left, input);
      }
      root = root->right;
    }
  }
}

void getCFGFromJson(std::string cfgFile) {
  // 1. 读取 JSON 文件内容
  std::ifstream file(cfgFile);
  if (!file.is_open()) {
    throw std::runtime_error("Failed to open JSON file: " + cfgFile);
  }
  std::stringstream buffer;
  buffer << file.rdbuf();
  std::string jsonStr = buffer.str();
  file.close();

  // 2. 解析 JSON
  picojson::value v;
  std::string err = picojson::parse(v, jsonStr);
  if (!err.empty()) {
    throw std::runtime_error("JSON parse error: " + err);
  }

  if (!v.is<picojson::object>()) {
    throw std::runtime_error("Root JSON element is not an object");
  }
  const picojson::object& root = v.get<picojson::object>();

  // 3. 解析 BBInfo 数组
  auto bbInfoIt = root.find("BBInfo");
  if (bbInfoIt != root.end() && bbInfoIt->second.is<picojson::array>()) {
    const picojson::array& bbArray = bbInfoIt->second.get<picojson::array>();
    for (const auto& elem : bbArray) {
      if (elem.is<double>()) {
        // picojson 用 double 存数字，但值是整数
        double val = elem.get<double>();
        if (val >= 0 && val <= static_cast<double>(UINT32_MAX)) {
          BBIDSet.insert(static_cast<uint32_t>(val));
        }
      }
    }
  }

  // 4. 解析 TRInfo 对象
  auto trInfoIt = root.find("TRInfo");
  if (trInfoIt != root.end() && trInfoIt->second.is<picojson::object>()) {
    const picojson::object& trObj = trInfoIt->second.get<picojson::object>();
    for (const auto& kv : trObj) {
      const std::string& srcStr = kv.first;
      const picojson::value& dstVal = kv.second;

      // 转换 src 字符串为 uint32_t
      uint32_t srcID;
      try {
        srcID = static_cast<uint32_t>(std::stoul(srcStr));
      } catch (...) {
        continue; // 跳过非法 key
      }

      std::set<uint32_t> dstSet;
      if (dstVal.is<picojson::array>()) {
        const picojson::array& dstArray = dstVal.get<picojson::array>();
        for (const auto& dstElem : dstArray) {
          if (dstElem.is<double>()) {
            double d = dstElem.get<double>();
            if (d >= 0 && d <= static_cast<double>(UINT32_MAX)) {
              uint32_t dstID = static_cast<uint32_t>(d);
              dstSet.insert(dstID);
              Trace.insert(std::make_pair(srcID, dstID));
            }
          }
        }
      }
      ICFG[srcID] = dstSet;
    }
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

  auto *CFGFile = getenv("PCT_CFG_PATH");
  if (CFGFile == nullptr){
    llvm::errs() << "[PCT] Not set PCT_CFG_PATH, do not generate CFG!\n";
  }else{
    llvm::errs() << "[PCT] fetch CFG in PCT_CFG_PATH : " << CFGFile << "\n";
    getCFGFromJson(CFGFile);
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
  qsym::executionTree = new ExecutionTree();

  while (true) {
    // 1. fetch all covnew seed, but not execute before
    // 2. symbolic execute all seed, and get path constraints tree
    // 3. rebuild PCT
    // 4. use SMT Solver to generate covnew SEED
    // 5. if no covnew SEED, dump filter
    // 6. use filter to AFL++, and restart AFL++

    // step(1)
    std::vector<fs::path> covnew_seeds =
        afl_config.get_unseen_seeds(afl_config.queue, state.processed_seeds);
    if (covnew_seeds.empty()){
      std::cout << "Waiting for new test cases...\n";
      std::this_thread::sleep_for(10s);
    }else{
      for (const auto& input : covnew_seeds){
        // step(2) : execute one input
        fs::path pct_file = state.concolic_execution(input, symcc, afl_config);

        // step(3) : rebuild PCT
        qsym::updatePCTree(pct_file, input);
        remove_file(pct_file);
      }

      std::vector<TreeNode *> tobeExplores = executionTree->getToBeExploredNodes();

      // step(4) : invoke solver to generate multiple inputs
      for (auto node : tobeExplores){
        fs::path input_file = node->data.input_file;
        node->isVisited = true;

        std::vector<PCTNode> constraints;
        auto currNode = node;
        while (currNode != executionTree->getRoot()) {
          constraints.push_back(currNode->data);
          currNode = currNode->parent;
        }

        g_solver->reset();
        g_solver->setInputFile(input_file);
        for (const auto& cons : constraints){
          ExprRef expr = cons.constraint;
          if (!cons.taken)
            expr = g_expr_builder->createLNot(expr);
          g_solver->add(expr->toZ3Expr());
        }
        std::string new_case = g_solver->fetchTestcase();
        // no solution
        if (new_case.empty()){
          node->isSat = false;
          continue;
        }

        state.copy_testcase_to_fuzzer(new_case, state.queue);
        // TODO : use 'process_new_testcase' to evaluate if covnew ?
//        auto res = state.evaluate_new_testcase(new_case, symcc_dir, afl_config);
//        if (res == TestcaseResult::New){}
//          std::cerr << "[zgf dbg] seed cov new : " << new_case << "\n";
      }
    }

    executionTree->printTree(true);

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