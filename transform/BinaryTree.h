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

#define MAX_FSIZE 64*64

typedef std::pair<uint32_t, uint32_t> trace;

enum NodeStatus {
  UnReachable = 0,
  WillbeVisit = 1,
  HasVisited  = 2,
  HasSolved   = 3
};

static uint32_t g_id = 1;
template<typename T>
class Node {
public:

  Node<T> *parent;
  std::vector<Node<T> *> lefts, rights;
  T data;

  NodeStatus status = WillbeVisit;
  uint32_t id = 0, depth = 0;

  Node() : parent(NULL){
    parent = NULL;
  }

  Node(Node<T> *parent, T data) :
      parent(parent), data(data) {
    depth = parent->depth + 1;
    id = g_id;
    g_id ++;
  }

  bool isLeaf() const { return lefts.empty() && rights.empty(); }
  bool isDiverse() const { return lefts.size() > 1 || rights.size() > 1; }
};

struct PCTreeNode {
  PCTreeNode() : constraint(nullptr), taken(false) {}

  PCTreeNode(qsym::ExprRef expr, fs::path input_file,
             bool taken, uint32_t currBB, uint32_t maxRead)
      : constraint(std::move(expr)), input_file(std::move(input_file)),
        taken(taken), currBB(currBB), maxRead(maxRead) {}

  qsym::ExprRef constraint;
  fs::path input_file;
  bool taken  = false;

  // Record basic block
  uint32_t currBB = -1;
  uint32_t maxRead = 0;
};

typedef struct PCTreeNode PCTNode;
typedef Node<PCTNode> TreeNode;

class ExecutionTree {
public:
  ExecutionTree(qsym::ExprBuilder *expr_builder,
                qsym::Solver *solver,
                SearchStrategy *searcher) :
    g_expr_builder(expr_builder), g_solver(solver), g_searcher(searcher){
    root = new TreeNode();
  }

  ~ExecutionTree() { delete root; }
  TreeNode *getRoot() const { return root; }
  SearchStrategy *getSearcher() const {return g_searcher;}

  void updatePCTree(const fs::path &constraint_file, const fs::path &input);

  TreeNode *constructTreeNode(TreeNode *parent, PCTNode n) {
    TreeNode *newNode = new Node<PCTNode>(parent, std::move(n));
    tobeVisited[newNode->depth].push_back(newNode);
    return newNode;
  }

  // Export all visited leaf nodes with a depth within N
  std::vector<TreeNode *> selectTerminalNodes(uint32_t depth);

  std::vector<TreeNode *> selectWillBeVisitedNodes(uint32_t depth);

  std::vector<TreeNode *> selectDeadNode(uint32_t depth);

  void updateTobeVisited();
  std::vector<TreeNode *> selectNodesFromDepth(
      uint32_t evaluator_depth);
  std::vector<TreeNode *> selectNodesFromGroup(
      uint32_t N);
  std::vector<TreeNode *> selectNodesFromDist(
      uint32_t N);
  TreeNode *selectBestVisitedNode(std::set<uint32_t> selectedID, uint32_t maxRead);


  std::string generateTestCase(TreeNode *node);
  std::vector<UINT8> generateValues(TreeNode *node);
  std::vector<std::vector<uint8_t>> sampleValues(
      TreeNode *node, const std::set<uint32_t>& index, uint32_t N);

  void printTree(uint32_t limitDepth, bool isFullPrint = false);

private:
  qsym::ExprBuilder *g_expr_builder;
  qsym::Solver *g_solver;
  SearchStrategy *g_searcher;

  TreeNode *root;
  std::map<uint32_t, std::vector<TreeNode *>> tobeVisited;
  std::map<UINT32, qsym::ExprRef> protoCached;

  void deserializeToQsymExpr(
      const pct::SymbolicExpr &protoExpr, qsym::ExprRef &qsymExpr, uint32_t *max_read);
  TreeNode *updateTree(TreeNode *currNode, const PCTNode& pctNode);

  std::vector<qsym::ExprRef> getConstraints(const TreeNode *srcNode);

  std::set<uint32_t> findReadIdx(qsym::ExprRef e);
  bool isDeadNodeStrict(TreeNode *node);

  bool isFullyBuilt(const TreeNode* node);
  bool isFullyVisited(const TreeNode* node, uint32_t depth);

  void printNodeWithIndent(const TreeNode* node, uint32_t depth);
  void printTree(const TreeNode* node, uint32_t depth,
                 uint32_t limitDepth, bool isFullPrint);
};

#endif //EX2_BINARYTREE_H
