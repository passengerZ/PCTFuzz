//
// Created by Zhenbang Chen on 2020-03-22.
//

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

/////////////////////

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
  std::string takenStr = node->data.taken   ? "[T]" : "[F]";
  std::string isFull   = isFullyBuilt(node) ? "[FULL]" : "[OOPS]";
  std::string status   = node->status == UnReachable ? "[un sat]" :
                         node->status == WillbeVisit ? "[will vis]" :
                         node->status == HasVisited  ? "[has vis]" :
                         "[diverse]";

  std::string constraintStr = node->data.constraint->toString();
  std::cerr << indent << takenStr << " " << isFull
            << " " << status << " " << constraintStr;

  // 打印基本块信息
  std::cerr << "  (BB:" << node->data.currBB
            << " -> " << (node->data.taken ? node->data.leftBB : node->data.rightBB)
            << ")";
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
        currNode->left = constructTreeNode(currNode, pctNode);

        std::cerr << "[PCT] left Divergent : "
                  << currNode->depth << " " << currNode->data.currBB << "\n";
        fullCache.clear();
        divergtNodes.push_back(currNode);
      }

      currNode->left->data.taken = true;
    } else {
      currNode->left = constructTreeNode(currNode, pctNode);
    }

    if (!currNode->right) {
      currNode->right = constructTreeNode(currNode, pctNode);
      currNode->right->data.taken = false;
    }else{
      // update the input file
      if (currNode->right->status == WillbeVisit)
        currNode->right->data.input_file = pctNode.input_file;
    }

    currNode = currNode->left;
  } else {
    if (currNode->right) {
      if (currNode->right->data.constraint->hash() != pctNode.constraint->hash()) {
        // if path is divergent, try to rebuild it !
        currNode->right = constructTreeNode(currNode, pctNode);

        std::cerr << "[PCT] right Divergent : "
                  << currNode->depth << " " << currNode->data.currBB << "\n";
        fullCache.clear();
        divergtNodes.push_back(currNode);
      }

      currNode->right->data.taken = false;
    } else {
      currNode->right = constructTreeNode(currNode, pctNode);
    }

    if (!currNode->left) {
      currNode->left = constructTreeNode(currNode, pctNode);
      currNode->left->data.taken = true;
    }else{
      // update the input file
      if (currNode->left->status == WillbeVisit)
        currNode->left->data.input_file = pctNode.input_file;
    }

    currNode = currNode->right;
  }
  currNode->status = HasVisited;
  return currNode;
}

std::vector<TreeNode *> ExecutionTree::getWillBeVisitedNodes() {
  std::vector<TreeNode*> willbeVisited;
  if (!root) return willbeVisited;

  std::queue<TreeNode*> worklist;
  worklist.push(root);

  while (!worklist.empty()) {
    TreeNode *node = worklist.front();
    worklist.pop();

    if (isFullyBuilt(node))
      continue;

    if (node->status == WillbeVisit)
      willbeVisited.push_back(node);

    if (node->left)
      worklist.push(node->left);
    if (node->right)
      worklist.push(node->right);
  }

  return willbeVisited;
}

std::vector<TreeNode *> ExecutionTree::getHasVisitedLeafNodes(uint32_t depth) {
  std::vector<TreeNode*> hasVisited;
  if (!root) return hasVisited;

  std::queue<TreeNode*> worklist;
  worklist.push(root);

  while (!worklist.empty()) {
    TreeNode* node = worklist.front();
    worklist.pop();

    if (node->depth > depth)
      continue;

    if (isFullyBuilt(node)){
      // no expand, kill early
      hasVisited.push_back(node);
      continue;
    }

    if (node->left)  worklist.push(node->left);
    if (node->right) worklist.push(node->right);
  }

  return hasVisited;
}

std::vector<TreeNode *> ExecutionTree::selectWillBeVisitedNodes(uint32_t N){
  int LeftSize = N;
  std::vector<TreeNode*> willbeVisited;
  std::set<uint32_t> selectNodesIDs;

  // re-compute the tobe visited nodes
  std::vector<TreeNode *> allNodes = getWillBeVisitedNodes();
  if ((int)allNodes.size() < LeftSize)
    return allNodes;

  // extract equality nodes
  std::map<uint32_t, uint32_t> selectBBCnt;
  while (LeftSize > 0){
    selectBBCnt.clear();
    for (auto node : allNodes){
      uint32_t BBID = node->data.currBB;
      if (selectNodesIDs.count(node->id) == 0 &&
          selectBBCnt[BBID] < BBWeight[BBID] + 1){
        // if a BB is more weight, give more chance to it !
        willbeVisited.push_back(node);
        selectNodesIDs.insert(node->id);

        selectBBCnt[BBID] ++;

        LeftSize --;
        if (LeftSize == 0) return willbeVisited;
      }
    }
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

std::vector<qsym::ExprRef> ExecutionTree::getRelaConstraints(
    const TreeNode *srcNode, std::set<trace> *relaBranchTraces){
  std::vector<qsym::ExprRef> constraints;
  auto currNode = srcNode;
  while (currNode != getRoot()) {
    trace tobeTrace = getTrace(currNode);
    if (relaBranchTraces->count(tobeTrace)){
      qsym::ExprRef expr = currNode->data.constraint;
      if (!currNode->data.taken)
        expr = g_expr_builder->createLNot(expr);
      constraints.push_back(expr);
    }
    currNode = currNode->parent;
  }
  return constraints;
}

std::string ExecutionTree::generateTestCase(TreeNode *node){
  fs::path input_file = node->data.input_file;
  assert(node->status == WillbeVisit);

  std::vector<qsym::ExprRef> constraints = getConstraints(node);

  g_solver->reset();
  g_solver->setInputFile(input_file);

  for (const auto& cond : constraints)
    g_solver->add(cond->toZ3Expr());

  std::string new_case = g_solver->fetchTestcase();

  // No Solution, set the node status to UNSAT
  // SAT, record the testcase
  if (new_case.empty())
    node->status = UnReachable;
  else
    node->status = HasVisited;

  return new_case;
}