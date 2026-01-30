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
};

struct PCTreeNode {
  PCTreeNode() : constraint(nullptr), taken(false) {}

  PCTreeNode(qsym::ExprRef expr, fs::path input_file,
             bool taken, uint32_t currBB)
      : constraint(std::move(expr)), input_file(std::move(input_file)),
        taken(taken), currBB(currBB) {
    hash = constraint->hash();
    if (!taken) hash = hash >> 1;
  }

  qsym::ExprRef constraint;
  fs::path input_file;
  bool taken  = false;

  // Record basic block
  uint32_t currBB = -1;
  uint32_t hash = 0;

  std::set<uint32_t> idx;
};

typedef struct PCTreeNode PCTNode;
typedef Node<PCTNode> TreeNode;

class DeadZone{
public:
  uint32_t srcBBID = 0;
  std::vector<TreeNode *> domNodes;
  DeadZone(uint32_t srcBBID) : srcBBID(srcBBID) {}

  bool equal(DeadZone *other) const {
    if (srcBBID != other->srcBBID) return false;
    if (domNodes.size() != other->domNodes.size()) return false;
    for (uint32_t i = 0; i < domNodes.size(); i++)
      if (domNodes[i]->data.hash != other->domNodes[i]->data.hash)
        return false;
    return true;
  }
};

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

  std::vector<TreeNode *> tobeVisited;

  std::map<uint32_t, std::set<uint32_t>> unsatNode;

  bool fastUnsatCheck(TreeNode *node){
    bool isUnsat = false;
    auto it2 = unsatNode.find(node->data.currBB);
    if (it2 != unsatNode.end()){
      if (it2->second.count(node->data.hash) != 0){
        node->status = UnReachable;
        isUnsat = true;
      }
    }
    return isUnsat;
  }

  bool updatePCTree(const fs::path &constraint_file, const fs::path &input);

  TreeNode *constructTreeNode(TreeNode *parent, PCTNode n) {
    TreeNode *newNode = new Node<PCTNode>(parent, std::move(n));
    if (!fastUnsatCheck(newNode))
      tobeVisited.push_back(newNode);
    return newNode;
  }

  // Export all visited leaf nodes with a depth within N
  std::vector<TreeNode *> selectDeepestNodes(uint32_t N);
  std::vector<TreeNode *> selectWillBeVisitedNodes(std::set<uint32_t> *deadBB, uint32_t N);
  std::vector<TreeNode *> selectDeadNode();

  std::set<uint32_t> findReadIdx(qsym::ExprRef e);

  std::string generateTestCase(TreeNode *node);
  std::vector<std::vector<uint8_t>> sampleDeadValues(
      const DeadZone *zone, const std::set<uint32_t>& index, uint32_t N);

  void printTree(uint32_t limitDepth, bool isFullPrint = false);

  bool isFullyBuilt(const TreeNode* node);
  bool isFullyVisited(const TreeNode* node);

private:
  qsym::ExprBuilder *g_expr_builder;
  qsym::Solver *g_solver;
  SearchStrategy *g_searcher;

  TreeNode *root;
  size_t select_offset = 0, current_bucket = 0;

  std::set<const TreeNode *> fullVisitCache;
  std::map<uint32_t, qsym::ExprRef> protoCached;

  bool deserializeToQsymExpr(
      const pct::SymbolicExpr &protoExpr, qsym::ExprRef &qsymExpr, uint32_t *max_read);
  TreeNode *updateTree(TreeNode *currNode, const PCTNode& pctNode, bool *isNew);

  std::vector<qsym::ExprRef> getRelaConstraints(const TreeNode *srcNode);
  std::vector<qsym::ExprRef> getDomConstraints(const TreeNode *srcNode);

  void printNodeWithIndent(const TreeNode* node, uint32_t depth);
  void printTree(const TreeNode* node, uint32_t depth,
                 uint32_t limitDepth, bool isFullPrint);
};

#endif //EX2_BINARYTREE_H
