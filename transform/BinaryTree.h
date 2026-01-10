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
#include "logging.h"
#include "SearchStrategy.h"
#include "qsymExpr.pb.h"

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
  bool isDiverse = false;
  uint32_t id = 0, depth = 0;

  Node() : parent(NULL), left(NULL), right(NULL) {
    parent = NULL;
    left = NULL;
    right = NULL;
  }

  Node(Node<T> *parent, T data) :
      parent(parent), left(NULL), right(NULL), data(data) {
    depth = parent->depth + 1;
    id = g_id;
    g_id ++;
  }

  bool isLeaf() const { return !left && !right; }
};

struct PCTreeNode {
  PCTreeNode() : constraint(nullptr), taken(false) {}

  PCTreeNode(qsym::ExprRef expr, fs::path input_file,
             bool taken, uint32_t varBytes, uint32_t currBB)
      : constraint(std::move(expr)), input_file(std::move(input_file)),
        taken(taken), varBytes(varBytes),currBB(currBB){}
  qsym::ExprRef constraint;
  fs::path input_file;
  bool taken  = false;

  uint32_t varBytes = 0;
  // Record basic block successor
  uint32_t currBB = -1;
};

typedef struct PCTreeNode PCTNode;
typedef Node<PCTNode> TreeNode;

class ExecutionTree {
public:
  ExecutionTree(qsym::ExprBuilder *expr_builder) :
    g_expr_builder(expr_builder){
    root = new TreeNode();
  }

  ~ExecutionTree() { delete root; }
  TreeNode *getRoot() const { return root; }

//  int getLeftNodeSize() {
//    return static_cast<int>(getWillBeVisitedNodes(0).size());
//  }

  void updatePCTree(const fs::path &constraint_file, const fs::path &input);

  static TreeNode *constructTreeNode(TreeNode *parent, PCTNode n) {
    return new Node<PCTNode>(parent, std::move(n));
  }

  // Export all visited leaf nodes with a depth within N
  std::vector<TreeNode *> selectTerminalNodes(uint32_t depth);

  // Export all unvisited leaf nodes
//  std::vector<TreeNode *> getWillBeVisitedNodes(uint32_t N);
//  std::vector<TreeNode *> selectWillBeVisitedNodes(uint32_t N);
//
//  std::vector<qsym::ExprRef> getConstraints(const TreeNode *srcNode);
//  std::vector<qsym::ExprRef> getRelaConstraints(
//      const TreeNode *srcNode, std::set<trace> *relaBranchTraces);
//  std::string generateTestCase(TreeNode *node);

  void printTree(uint32_t limitDepth, bool isFullPrint = false);

private:
  qsym::ExprBuilder *g_expr_builder;

  TreeNode *root;

  std::map<UINT32, qsym::ExprRef> protoCached;

  std::set<const TreeNode*> fullCache;

  void deserializeToQsymExpr(
      const pct::SymbolicExpr &protoExpr, qsym::ExprRef &qsymExpr);
  TreeNode *updateTree(TreeNode *currNode, const PCTNode& pctNode);

  bool isFullyBuilt(const TreeNode* node);

  void printNodeWithIndent(const TreeNode* node, uint32_t depth);
  void printTree(const TreeNode* node, uint32_t depth,
                 uint32_t limitDepth, bool isFullPrint);
};

#endif //EX2_BINARYTREE_H
