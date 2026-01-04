//
// Created by Guofeng Zhang on 2025-12-22.
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

  bool isLeaf() const { return !left && !right; }

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
             bool taken, uint32_t varBytes,
             uint32_t currBB, uint32_t leftBB, uint32_t rightBB)
      : constraint(std::move(expr)), input_file(std::move(input_file)),
        taken(taken), varBytes(varBytes),
        currBB(currBB), leftBB(leftBB), rightBB(rightBB){}
  qsym::ExprRef constraint;
  fs::path input_file;
  bool taken  = false;

  uint32_t varBytes = 0;
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

  TreeNode *getRoot() const { return root; }

  int getLeftNodeSize() {
    return static_cast<int>(getWillBeVisitedNodes().size());
  }

  trace getTrace(const TreeNode* node){
    uint32_t dst = node->data.taken ? node->data.leftBB : node->data.rightBB;
    return std::make_pair(node->data.currBB, dst);
  }

  TreeNode *updateTree(TreeNode *currNode, const PCTNode& pctNode);

  TreeNode *constructTreeNode(TreeNode *parent, PCTNode n) {
    TreeNode *newNode = new Node<PCTNode>(std::move(n), parent, nullptr, nullptr);
    BBToNode[newNode->data.currBB].insert(newNode);
    return newNode;
  }

  // Export all unvisited leaf nodes
  std::vector<TreeNode *> getWillBeVisitedNodes() const;

  // Export all visited leaf nodes with a depth within N
  std::vector<TreeNode *> getHasVisitedLeafNodes(unsigned int depth) const;

  std::set<TreeNode*> getBBNodes(trace targetTrace){
    std::set<TreeNode*> willVisitBB;
    for (auto node : BBToNode[targetTrace.first]){
      trace tobeTrace = getTrace(node);
      if (tobeTrace == targetTrace && node->status == WillbeVisit)
        willVisitBB.insert(node);
    }
    return willVisitBB;
  }

  std::vector<qsym::ExprRef> getConstraints(const TreeNode *srcNode);
  std::vector<qsym::ExprRef> getRelaConstraints(
      const TreeNode *srcNode, std::set<trace> *relaBranchTraces);
  std::string generateTestCase(TreeNode *node);

  void printTree(bool isFullPrint = false);

private:
  qsym::Solver *g_solver;
  qsym::ExprBuilder *g_expr_builder;

  TreeNode *root;
  std::set<const TreeNode*> fullCache;
  std::map<uint32_t, std::set<TreeNode*>> BBToNode;

  bool isFullyBuilt(const TreeNode* node);

  void printNodeWithIndent(const TreeNode* node, int depth);
  void printTree(const TreeNode* node, int depth, bool isFullPrint);
};

#endif //EX2_BINARYTREE_H
