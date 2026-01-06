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
#include "SearchStrategy.h"

namespace fs = std::filesystem;
typedef std::pair<uint32_t, uint32_t> trace;

enum NodeStatus {
  UnReachable = 0,
  WillbeVisit = 1,
  HasVisited  = 2
};

static uint32_t g_id = 1;
template<typename T>
class Node {
public:

  Node<T> *parent, *left, *right;
  T data;

  NodeStatus status = WillbeVisit;
  uint32_t id = 0, depth = 0;

  Node() : parent(NULL), left(NULL), right(NULL) {
    parent = NULL;
    left = NULL;
    right = NULL;
  }

  Node(T data, Node<T> *parent, Node<T> *left, Node<T> *right) :
      parent(parent), left(left), right(right), data(data) {
    depth = parent->depth + 1;
    id = g_id;
    g_id ++;
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

  ExecutionTree(qsym::Solver *solver,
                qsym::ExprBuilder *expr_builder,
                SearchStrategy *searcher) :
    g_solver(solver), g_expr_builder(expr_builder), g_searcher(searcher) {
    root = new TreeNode();
  }

  ~ExecutionTree() { delete root; }
  TreeNode *getRoot() const { return root; }

  int getLeftNodeSize() {
    return static_cast<int>(getWillBeVisitedNodes().size());
  }

  bool updateCovTrace(trace& newVis) {
    return g_searcher->updateCovTrace(newVis);
  }

  static trace getTrace(const TreeNode* node){
    uint32_t dst = node->data.taken ? node->data.leftBB : node->data.rightBB;
    return std::make_pair(node->data.currBB, dst);
  }

  TreeNode *updateTree(TreeNode *currNode, const PCTNode& pctNode);

  static TreeNode *constructTreeNode(TreeNode *parent, PCTNode n) {
    return new Node<PCTNode>(std::move(n), parent, nullptr, nullptr);
  }

  // Export all unvisited leaf nodes
  std::vector<TreeNode *> getWillBeVisitedNodes();

  // Export all visited leaf nodes with a depth within N
  std::vector<TreeNode *> getHasVisitedLeafNodes(uint32_t depth);

  std::vector<TreeNode *> selectWillBeVisitedNodes(uint32_t N);

  std::vector<qsym::ExprRef> getConstraints(const TreeNode *srcNode);
  std::vector<qsym::ExprRef> getRelaConstraints(
      const TreeNode *srcNode, std::set<trace> *relaBranchTraces);
  std::string generateTestCase(TreeNode *node);

  void printTree(uint32_t limitDepth, bool isFullPrint = false);

private:
  qsym::Solver *g_solver;
  qsym::ExprBuilder *g_expr_builder;
  SearchStrategy *g_searcher;

  TreeNode *root;
  std::set<const TreeNode*> fullCache;
  std::map<trace, std::set<TreeNode*>> TraceToNode;

  bool isFullyBuilt(const TreeNode* node);

  void printNodeWithIndent(const TreeNode* node, uint32_t depth);
  void printTree(const TreeNode* node, uint32_t depth,
                 uint32_t limitDepth, bool isFullPrint);
};

#endif //EX2_BINARYTREE_H
