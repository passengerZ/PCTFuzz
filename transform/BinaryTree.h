//
// Created by Zhenbang Chen on 2020-03-22.
//

#ifndef EX2_BINARYTREE_H
#define EX2_BINARYTREE_H

#include <iostream>
#include <new>
#include <cassert>
#include <utility>

#include "expr.h"

template<typename T>
class Node {
 public:

  Node<T> *parent, *left, *right;
  T data;

  Node() : parent(NULL), left(NULL), right(NULL) {
    parent = NULL;
    left = NULL;
    right = NULL;
  }

  Node(T data) : parent(NULL), left(NULL), right(NULL), data(data) {}

  Node(T data, Node<T> *parent, Node<T> *left, Node<T> *right) :
      parent(parent), left(left), right(right), data(data) {
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

  PCTreeNode(qsym::ExprRef expr, bool taken, bool isLast,
             uint32_t currBB, uint32_t leftBB, uint32_t rightBB)
      : constraint(std::move(expr)), taken(taken), isLast(isLast),
        currBB(currBB), leftBB(leftBB), rightBB(rightBB){}
  qsym::ExprRef constraint;
  bool taken  = false;
  bool isLast = false;

  // Record basic block successor
  uint32_t currBB = -1;
  uint32_t leftBB = -1;
  uint32_t rightBB = -1;
};

typedef struct PCTreeNode PCTNode;
typedef Node<PCTNode> TreeNode;

class ExecutionTree {
public:
  ExecutionTree() {
    root = new TreeNode();
  }

  ~ExecutionTree() { delete root; }

  TreeNode *getRoot() { return root; }

  TreeNode *constructTreeNode(TreeNode *parent, PCTNode n) {
    return new Node<PCTNode>(std::move(n), parent, nullptr, nullptr);
  }

  void addToBeExploredNodes(TreeNode *newNode) {
    toBeExploredNodes.push_back(*newNode);
  }

  std::vector<TreeNode> *getToBeExploredNodes() {
    return &toBeExploredNodes;
  }

  int getLeftNodeSize() { return toBeExploredNodes.size(); }

  void printTree(bool isFullPrint = false) {
    if (!root) {
      std::cout << "(null root)\n";
      return;
    }
    printTree(root, 0, isFullPrint);
  }

private:
  TreeNode *root;
  std::vector<TreeNode> toBeExploredNodes;
  std::set<const TreeNode*> fullCache;

  bool isFullyBuilt(const TreeNode* node) {
    if (node->data.isLast ||
        fullCache.find(node) != fullCache.end()) {
      fullCache.insert(node);
      return true;
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
    if (!node->data.constraint) {
      return;
    }

    std::string indent(depth * 2, ' '); // 2 空格缩进每层
    std::string takenStr = node->data.taken ? "[T]" : "[F]";
    std::string isFull = isFullyBuilt(node) ? "[FULL]" : "[OOPS]";

    // 假设 qsym::ExprRef 支持 toString()
    std::string constraintStr = node->data.constraint->toString();

    std::cout << indent << takenStr << " " << isFull << " " << constraintStr;

    // 可选：打印基本块信息
    std::cout << "  (BB:" << node->data.currBB
              << " -> " << (node->data.taken ? node->data.rightBB : node->data.leftBB)
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
