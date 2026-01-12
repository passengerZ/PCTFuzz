#include "BinaryTree.h"

template<typename T> std::ostream &operator<<(std::ostream &output, Node<T> node);

template<typename T> std::ostream &operator<<(std::ostream &output, Node<T> node) {
    output << "Value: " << node.data;
    if (node.parent) output << " Parent: " << node.parent -> data;
    if (node.left) output << " Left: " << node.left -> data;
    if (node.right) output << " Right: " << node.right -> data;
    output << "\n";
    return output;
}

template <typename E> constexpr auto to_underlying(E e) noexcept {
  return static_cast<std::underlying_type_t<E>>(e);
}

/////////////////////

void ExecutionTree::deserializeToQsymExpr(
    const pct::SymbolicExpr &protoExpr, qsym::ExprRef &qsymExpr) {
  UINT32 hashValue = protoExpr.hash();
  auto it = protoCached.find(hashValue);
  if (it != protoCached.end()) {
    qsymExpr = it->second;
    return;
  }

  qsym::ExprRef child0, child1, child2;
  pct::ExprKind exprKind = static_cast<pct::ExprKind>(protoExpr.type());
  assert(to_underlying(exprKind) <= 79);

  switch (exprKind) {
  case pct::ExprKind::Bool: {
    qsymExpr = g_expr_builder->createBool(protoExpr.value());
    break;
  }
  case pct::ExprKind::Constant: {
    qsymExpr = g_expr_builder->createConstant(protoExpr.value(),
                                              protoExpr.bits());
    break;
  }
  case pct::ExprKind::Read: {
    // ReadExpr has a _index of type uint32, so we need to do a int64 t0 uint32
    // translate.
    uint32_t idx = protoExpr.value();
    qsymExpr = g_expr_builder->createRead(idx);
    break;
  }
  case pct::ExprKind::Extract: {
    deserializeToQsymExpr(protoExpr.children(0), child0);
    qsymExpr = g_expr_builder->createExtract(
        child0, protoExpr.value() & 0xFFFFFFFF, protoExpr.bits());
    break;
  }
  case pct::ExprKind::ZExt: {
    uint32_t bits = protoExpr.bits();
    deserializeToQsymExpr(protoExpr.children(0), child0);
    qsymExpr = g_expr_builder->createZExt(child0, bits);
    break;
  }
  case pct::ExprKind::SExt: {
    uint32_t bits = protoExpr.bits();
    deserializeToQsymExpr(protoExpr.children(0), child0);
    qsymExpr = g_expr_builder->createSExt(child0, bits);
    break;
  }
  case pct::ExprKind::Neg: case pct::ExprKind::Not:
  case pct::ExprKind::LNot: {
    deserializeToQsymExpr(protoExpr.children(0), child0);
    qsymExpr = g_expr_builder->createUnaryExpr(
        static_cast<qsym::Kind>(to_underlying(exprKind)), child0);
    break;
  }
  case pct::ExprKind::Concat:{
    deserializeToQsymExpr(protoExpr.children(0), child0);
    deserializeToQsymExpr(protoExpr.children(1), child1);
    qsymExpr = g_expr_builder->createConcat(child0, child1);
    break;
  }
    // Binary arithmetic operators
  case pct::ExprKind::Add: case pct::ExprKind::Sub: case pct::ExprKind::Mul:
  case pct::ExprKind::UDiv: case pct::ExprKind::SDiv:
  case pct::ExprKind::URem: case pct::ExprKind::SRem:
  case pct::ExprKind::And: case pct::ExprKind::Or: case pct::ExprKind::Xor:
  case pct::ExprKind::Shl: case pct::ExprKind::LShr: case pct::ExprKind::AShr:

    // Binary relational operators
  case pct::ExprKind::Equal: case pct::ExprKind::Distinct:
  case pct::ExprKind::Ult: case pct::ExprKind::Ule:
  case pct::ExprKind::Ugt: case pct::ExprKind::Uge:
  case pct::ExprKind::Slt: case pct::ExprKind::Sle:
  case pct::ExprKind::Sgt: case pct::ExprKind::Sge:
  case pct::ExprKind::LOr: case pct::ExprKind::LAnd: {
    deserializeToQsymExpr(protoExpr.children(0), child0);
    deserializeToQsymExpr(protoExpr.children(1), child1);
    qsymExpr = g_expr_builder->createBinaryExpr(
        static_cast<qsym::Kind>(to_underlying(exprKind)), child0, child1);
    break;
  }
  case pct::ExprKind::Ite: {
    deserializeToQsymExpr(protoExpr.children(0), child0);
    deserializeToQsymExpr(protoExpr.children(1), child1);
    deserializeToQsymExpr(protoExpr.children(2), child2);
    qsymExpr = g_expr_builder->createIte(child0, child1, child2);
    break;
  }

    // Floating-point arithmetic operators

    // Unknown operators
  case pct::ExprKind::Rol:
  case pct::ExprKind::Ror:
  case pct::ExprKind::Invalid:
    qsym::LOG_FATAL("Unsupported expression kind in deserialization");
    break; // to silence the compiler warning
  default:
    qsym::LOG_FATAL("Unknown expression kind in deserialization");
    break;
  }
  protoCached.insert(make_pair(hashValue, qsymExpr));
}

void ExecutionTree::updatePCTree(
    const fs::path &constraint_file, const fs::path &input) {
  ifstream inputf(constraint_file, std::ofstream::in | std::ofstream::binary);
  if (inputf.fail()){
    std::cerr << "Unable to open a file ["
              << constraint_file <<"] to update Path Constaint Tree\n";
    return;
  }

  pct::ConstraintSequence cs;
  cs.ParseFromIstream(&inputf);

  qsym::ExprRef pathCons;
  TreeNode *currNode = getRoot();
  for (int i = 0; i < cs.node_size(); i++) {
    const pct::SequenceNode &pnode = cs.node(i);
    if (!pnode.has_constraint())
      continue;

    bool branchTaken = pnode.taken() > 0;

    deserializeToQsymExpr(pnode.constraint(), pathCons);

//    std::cerr << "[zgf dbg] idx : " << i << " " << pathCons->toString() << "\n";
    PCTNode pctNode(pathCons, input, branchTaken, 0, pnode.b_id());

    currNode = updateTree(currNode, pctNode);
    if (currNode == getRoot())
      break;
  }

}

bool ExecutionTree::isFullyBuilt(const TreeNode* node) {
  if (fullCache.find(node) != fullCache.end()) {
    return true;
  }
  else if (node->isLeaf()) {
    if (node->status == WillbeVisit)
      return false;
    return true; // is terminal PC
  }
  else if (!node->left || !node->right) {
    return false;
  }
  bool isFull = isFullyBuilt(node->left) && isFullyBuilt((node->right));
  if (isFull)
    fullCache.insert(node);
  return isFull;
}

void ExecutionTree::printTree(uint32_t limitDepth, bool isFullPrint) {
  if (!root) {
    std::cerr << "(null root)\n";
    return;
  }
  printTree(root, 0, limitDepth, isFullPrint);
}

void ExecutionTree::printNodeWithIndent(const TreeNode* node, uint32_t depth) {
  if (!node->data.constraint)
    return;

  std::string indent(depth * 2, '-');
  std::string index   = "[" + std::to_string(depth) + "]";
  std::string taken   = node->data.taken   ? "[T]" : "[F]";
  std::string isFull  = isFullyBuilt(node) ? "[FULL]" : "[OOPS]";
  std::string status  = node->status == UnReachable ? "[un sat]" :
                        node->status == WillbeVisit ? "[will vis]" :
                        node->status == HasVisited  ? "[has vis]" :
                         "[diverse]";

  std::string constraintStr = node->data.constraint->toString();
  std::cerr << indent << index
            << taken  << " " << isFull
            << " " << status << " " << constraintStr;

  // 打印基本块信息
  std::cerr << "  (BB:" << node->data.currBB << ")";
  std::cerr << '\n';
}

void ExecutionTree::printTree(const TreeNode* node, uint32_t depth,
                              uint32_t limitDepth, bool isFullPrint) {
  if (!node || depth > limitDepth) return;

  // 先处理左子树（taken = false）
  if (node->left) {
    printNodeWithIndent(node->left, depth);
    if (isFullPrint || !isFullyBuilt(node->left))
      printTree(node->left, depth + 1, limitDepth, isFullPrint);
  }

  // 再处理右子树（taken = true）
  if (node->right) {
    printNodeWithIndent(node->right, depth);
    if (isFullPrint || !isFullyBuilt(node->right))
      printTree(node->right, depth + 1, limitDepth, isFullPrint);
  }
}

////////////////////////

TreeNode *ExecutionTree::updateTree(TreeNode *currNode, const PCTNode& pctNode){

  currNode->status = HasVisited;

  if (pctNode.taken) { /// left is the true branch
    if (currNode->left) {
      if (currNode->left->data.constraint->hash() != pctNode.constraint->hash()) {
        // if path is divergent, try to rebuild it !
        currNode->isDiverse = true;
        currNode->left = constructTreeNode(currNode, pctNode);

//        std::cerr << "[PCT] left Divergent : "
//                  << currNode->depth << " " << currNode->data.currBB << "\n";
        fullCache.clear();
      }

      currNode->left->data.taken = true;
    } else {
      currNode->left = constructTreeNode(currNode, pctNode);
    }

    if (!currNode->right) {
      currNode->right = constructTreeNode(currNode, pctNode);
      currNode->right->data.taken = false;
    }

    currNode = currNode->left;
  } else {
    if (currNode->right) {
      if (currNode->right->data.constraint->hash() != pctNode.constraint->hash()) {
        // if path is divergent, try to rebuild it !
        currNode->isDiverse = true;
        currNode->right = constructTreeNode(currNode, pctNode);

//        std::cerr << "[PCT] right Divergent : "
//                  << currNode->depth << " " << currNode->data.currBB << "\n";
        fullCache.clear();
      }

      currNode->right->data.taken = false;
    } else {
      currNode->right = constructTreeNode(currNode, pctNode);
    }

    if (!currNode->left) {
      currNode->left = constructTreeNode(currNode, pctNode);
      currNode->left->data.taken = true;
    }

    currNode = currNode->right;
  }

  currNode->status = HasVisited;
  return currNode;
}

std::vector<TreeNode *> ExecutionTree::selectTerminalNodes(uint32_t depth) {
  std::vector<TreeNode*> hasVisited;
  if (!root) return hasVisited;

  std::queue<TreeNode*> worklist;
  worklist.push(root);

  while (!worklist.empty()) {
    TreeNode* node = worklist.front();
    worklist.pop();

    if (node->depth > depth ||
        node->isDiverse)
      continue;

    if (node->status == HasVisited && node->isLeaf()){
      // no expand, kill early
      hasVisited.push_back(node);
      continue;
    }

    if (node->left)  worklist.push(node->left);
    if (node->right) worklist.push(node->right);
  }

  return hasVisited;
}


std::vector<TreeNode *> ExecutionTree::selectWillBeVisitedNodes(uint32_t depth) {
  std::vector<TreeNode*> willbeVisited;
  if (!root) return willbeVisited;

  std::queue<TreeNode*> worklist;
  worklist.push(root);

  while (!worklist.empty()) {
    TreeNode *node = worklist.front();
    worklist.pop();

    if (isFullyBuilt(node) ||
        node->isDiverse ||
        node->depth > depth)
      continue;

    if (node->status == WillbeVisit && node != root)
      willbeVisited.push_back(node);

    if (node->left)  worklist.push(node->left);
    if (node->right) worklist.push(node->right);
  }

  return willbeVisited;
}

std::vector<qsym::ExprRef> ExecutionTree::getConstraints(const TreeNode *srcNode){
  std::vector<qsym::ExprRef> constraints;

  auto currNode = srcNode;
  while (currNode != getRoot()) {
    qsym::ExprRef expr = currNode->data.constraint;

    if (!currNode->data.taken)
      expr = g_expr_builder->createLNot(expr);
    constraints.push_back(expr);

    currNode = currNode->parent;
  }
  return constraints;
}

std::string ExecutionTree::generateTestCase(TreeNode *node){
  fs::path input_file = node->data.input_file;
  //assert(node->status == WillbeVisit);

  std::vector<qsym::ExprRef> constraints = getConstraints(node);

//  std::cerr << "[" << constraints.size() << ", " << node->depth << "]\n";

  g_solver->reset();
  g_solver->setInputFile(input_file);
  for (const auto& cond : constraints)
    g_solver->add(cond->toZ3Expr());

  std::string new_case = g_solver->fetchTestcase();

  // No Solution, set the node status to UNSAT
  // SAT, record the testcase,
  // NOTE ! the HasVisited must set in UPDATETREE
  if (new_case.empty())
    node->status = UnReachable;

  return new_case;
}

/*
std::vector<TreeNode *> ExecutionTree::selectWillBeVisitedNodes(uint32_t N){
  // re-compute the tobe visited nodes
  std::vector<TreeNode *> allNodes = getWillBeVisitedNodes(N);
  size_t total = allNodes.size();
  if (total < N)
    return allNodes;

  // Step 1: 按 depth 分组，同一 depth 内保持原始顺序（或可排序）
  std::map<uint32_t, std::vector<TreeNode*>> depthGroups;
  for (auto node : allNodes) {
    depthGroups[node->depth].push_back(node);
  }

  // 可选：对每个 depth 组内部按 id 排序，确保确定性
  for (auto& pair : depthGroups) {
    std::sort(pair.second.begin(), pair.second.end(),
              [](TreeNode* a, TreeNode* b) {
                return a->id < b->id; // 或其他稳定排序依据
              });
  }

  // Step 2: round-robin 采样
  std::vector<TreeNode*> result;
  result.reserve(N);

  // 记录每个 depth 下一次要取的索引（初始为 0）
  std::map<uint32_t, size_t> nextIndex;
  for (const auto& pair : depthGroups) {
    nextIndex[pair.first] = 0;
  }

  // 持续采样直到取满 N 个
  while (result.size() < N) {
    bool madeProgress = false;
    // 遍历所有 depth（按升序：浅→深；若想优先深，可用 rbegin/rend）
    for (const auto& pair : depthGroups) {
      uint32_t depth = pair.first;
      const auto& nodes = pair.second;
      size_t& idx = nextIndex[depth];

      if (idx < nodes.size()) {
        result.push_back(nodes[idx]);
        idx++;
        madeProgress = true;

        if (result.size() >= N) break;
      }
    }

    // 如果一轮下来一个都没取到，说明已无更多节点
    if (!madeProgress) break;
  }

  return result;
}
*/