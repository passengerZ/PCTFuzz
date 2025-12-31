//
// Created by Zhenbang Chen on 2020-03-22.
//

#ifndef EX2_BINARYTREE_H
#define EX2_BINARYTREE_H

#include <cassert>
#include <filesystem>
#include <iostream>
#include <new>
#include <queue>
#include <utility>

#include "expr.h"
#include "expr_builder.h"
#include "solver.h"

namespace fs = std::filesystem;
typedef std::pair<uint32_t, uint32_t> trace;

enum NodeStatus {
  UnReachable = 0,
  WillbeVisit = 1,
  HasVisited  = 2
};

template<typename T>
class Node {
 public:

  Node<T> *parent, *left, *right;
  T data;

  NodeStatus status = WillbeVisit;  // -1:unsat, 0:no-visit, 1:visited
  uint32_t depth = 0;

  Node() : parent(NULL), left(NULL), right(NULL) {
    parent = NULL;
    left = NULL;
    right = NULL;
  }

  Node(T data, Node<T> *parent, Node<T> *left, Node<T> *right) :
      parent(parent), left(left), right(right), data(data) {
    depth = parent->depth + 1;
  }

  static void walk(const Node<T> *tree);
  static Node<T> *find(Node<T> *tree, T value);
  static Node<T> *minimum(Node<T> *tree);
  static Node<T> *maximum(Node<T> *tree);
  static Node<T> *successor(Node<T> *tree);

  // Always returns the root of the tree, whether it had to be modified
  // or not
  static Node<T> *insertNode(Node<T> *tree, Node<T> *node);
  static Node<T> *deleteNode(Node<T> *tree, Node<T> *node);

 private:
  static Node<T> *transplant(Node<T> *tree, Node<T> *u, Node<T> *v);
};

struct PCTreeNode {
  PCTreeNode() : constraint(nullptr), taken(false) {}

  PCTreeNode(qsym::ExprRef expr, fs::path input_file,
             bool taken, uint32_t currBB, uint32_t leftBB, uint32_t rightBB)
      : constraint(std::move(expr)), input_file(input_file),
        taken(taken), currBB(currBB), leftBB(leftBB), rightBB(rightBB){}
  qsym::ExprRef constraint;
  fs::path input_file;
  bool taken  = false;

  // Record basic block successor
  uint32_t currBB = -1;
  uint32_t leftBB = -1;
  uint32_t rightBB = -1;
};

typedef struct PCTreeNode PCTNode;
typedef Node<PCTNode> TreeNode;

class ExecutionTree {
public:
  unsigned varSizeLowerBound = 0;

  ExecutionTree(qsym::Solver *solver, qsym::ExprBuilder *expr_builder) :
    g_solver(solver), g_expr_builder(expr_builder) {
    root = new TreeNode();
  }

  ~ExecutionTree() { delete root; }

  TreeNode *getRoot() { return root; }

  TreeNode *updateTree(TreeNode *currNode, const PCTNode& pctNode){
    currNode->status = HasVisited;

    if (pctNode.taken) { /// left is the true branch
      if (currNode->left) {
        if (currNode->left->data.constraint->hash() != pctNode.constraint->hash()) {
          // if path is divergent, try to rebuild it !
          currNode->left = constructTreeNode(currNode, pctNode);
          std::cerr << "[zgf dbg] left Divergent !!!\n";
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
          currNode->right = constructTreeNode(currNode, pctNode);
          std::cerr << "[zgf dbg] right Divergent !!!\n";
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

  TreeNode *constructTreeNode(TreeNode *parent, PCTNode n) {
    TreeNode *newNode = new Node<PCTNode>(std::move(n), parent, nullptr, nullptr);
    BBToNode[newNode->data.currBB].insert(newNode);
    return newNode;
  }

  std::vector<TreeNode *> getToBeExploredNodes() {
    std::vector<TreeNode*> result;
    if (!root) return result;

    std::queue<TreeNode*> worklist;
    worklist.push(root);

    while (!worklist.empty()) {
      TreeNode* node = worklist.front();
      worklist.pop();
      if (node->status == WillbeVisit)
        result.push_back(node);

      if (node->left)  worklist.push(node->left);
      if (node->right) worklist.push(node->right);
    }
    return result;
  }

  int getLeftNodeSize() {
    return static_cast<int>(getToBeExploredNodes().size());
  }

  trace getTrace(const TreeNode* node){
    uint32_t dst = node->data.taken ? node->data.leftBB : node->data.rightBB;
    return std::make_pair(node->data.currBB, dst);
  }

  std::set<TreeNode*> getBBNodes(trace targetTrace){
    std::set<TreeNode*> willVisitBB;
    for (auto node : BBToNode[targetTrace.first]){
      trace tobeTrace = getTrace(node);
      if (tobeTrace == targetTrace && node->status == WillbeVisit)
        willVisitBB.insert(node);
    }
    return willVisitBB;
  }

  std::vector<qsym::ExprRef> getConstraints(const TreeNode *srcNode){
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

  std::vector<qsym::ExprRef> getRelaConstraints(
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

  std::string generateTestCase(TreeNode *node){
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

  void printTree(bool isFullPrint = false) {
    if (!root) {
      std::cout << "(null root)\n";
      return;
    }
    printTree(root, 0, isFullPrint);
  }

private:
  qsym::Solver *g_solver;
  qsym::ExprBuilder *g_expr_builder;

  TreeNode *root;
  std::set<const TreeNode*> fullCache;
  std::map<uint32_t, std::set<TreeNode*>> BBToNode;

  bool isFullyBuilt(const TreeNode* node) {
    if (node->status == UnReachable ||
        fullCache.find(node) != fullCache.end()) {
      fullCache.insert(node);
      return true;
    }
    else if (!node->left && !node->right) {
      if (node->status == HasVisited)
        return true; // is terminal PC
      return false;
    }
    else if (!node->left || !node->right) {
      return false;
    }
    bool isFull = isFullyBuilt(node->left) && isFullyBuilt((node->right));
    if (isFull)
      fullCache.insert(node);
    return isFull;
  }

  void printNodeWithIndent(const TreeNode* node, int depth) {
    if (!node->data.constraint)
      return;

    std::string indent(depth * 2, ' '); // 2 空格缩进每层
    std::string takenStr = node->data.taken   ? "[T]" : "[F]";
    std::string isFull   = isFullyBuilt(node) ? "[FULL]" : "[OOPS]";
    std::string status   = node->status == HasVisited  ? "[has vis]" :
                           node->status == WillbeVisit ? "[will vis]" : "[un sat]";

    std::string constraintStr = node->data.constraint->toString();
    std::cout << indent << takenStr << " " << isFull
              << " " << status << " " << constraintStr;

    // 打印基本块信息
    std::cout << "  (BB:" << node->data.currBB
              << " -> " << (node->data.taken ? node->data.leftBB : node->data.rightBB)
              << ")";
    std::cout << '\n';
  }

  void printTree(const TreeNode* node, int depth, bool isFullPrint) {
    if (!node) return;

    // 先处理左子树（taken = false）
    if (node->left) {
      printNodeWithIndent(node->left, depth);
      if (isFullPrint || !isFullyBuilt(node->left))
        printTree(node->left, depth + 1, isFullPrint);
    }

    // 再处理右子树（taken = true）
    if (node->right) {
      printNodeWithIndent(node->right, depth);
      if (isFullPrint || !isFullyBuilt(node->right))
        printTree(node->right, depth + 1, isFullPrint);
    }
  }
};

#endif //EX2_BINARYTREE_H
