//
// Created by Zhenbang Chen on 2020-03-22.
//

#include "BinaryTree.h"

template <typename T> void Node<T>::walk(const Node<T> *tree) {
    if (tree == NULL) return;

    walk(tree -> left);
    std::cout << tree -> data << "\n";
    walk(tree -> right);
}

template <typename T> Node<T> *Node<T>::insertNode(Node<T> *tree, Node<T> *node) {
    if (!tree) {
        tree = node;
        node -> parent = NULL;
    } else {
        Node<T> *parent, *search = tree;
        bool left = false;
        while (search != NULL) {
            parent = search;
            if (node -> data <= search -> data) {
                search = search -> left;
                left = true;
            } else {
                search = search -> right;
                left = false;
            }
        }
        node -> parent = parent;
        if (left) parent -> left = node;
        else parent -> right = node;
    }

    return tree;
}

template <typename T> Node<T> *Node<T>::find(Node<T> *tree, T value) {
    if (!tree || tree -> data == value) return tree;
    if (value < tree -> data) return find(tree -> left, value);
    else return find(tree -> right, value);
}

template <typename T> Node<T> *Node<T>::minimum(Node<T> *tree) {
    if (!tree) return NULL;

    while (tree -> left) {
        tree = tree -> left;
    }

    return tree;
}

template <typename T> Node<T> *Node<T>::maximum(Node<T> *tree) {
    if (!tree) return NULL;

    while (tree -> right) {
        tree = tree -> right;
    }

    return tree;
}

template <typename T> Node<T> *Node<T>::successor(Node<T> *node) {
    if (!node) return NULL;

    if (node -> right) {
        return minimum(node -> right);
    } else {
        // We need to traverse upwards in the tree to find a node where
        // the node is the left child of a parent
        // parent is the successor

        Node<T> *parent = node -> parent;
        while(parent && node != parent -> left) {
            node = parent;
            parent = node -> parent;
        }

        return parent;
    }

}

// make node U's paarent have node v has its child
template <typename T> Node<T> *Node<T>::transplant(Node<T> *tree, Node<T> *u, Node<T> *v) {
    if (!u -> parent) tree = v;
    else if (u -> parent -> left == u) {
        u -> left = v;
    } else if (u -> parent -> right == u) {
        u -> right = v;
    }
    if (v) v -> parent = u -> parent;
    return tree;
}

template <typename T> Node<T> *Node<T>::deleteNode(Node<T> *tree, Node<T> *node) {
    if (!node -> left) {
        tree = transplant(tree, node, node -> right);
    } else if (!node -> right) {
        tree = transplant(tree, node, node -> left);
    } else {
        // Has two children -- successor must be on the right
        Node <int> *successor = minimum(node -> right);
        assert(successor -> left == NULL);
        if (successor != node -> right) {
            tree = transplant(tree, successor, successor -> right);
            successor -> right = node -> right;
            successor -> right -> parent = successor;
        }

        tree = transplant(tree, node, successor);
        successor -> left = node -> left;
        successor -> left -> parent = successor;
    }
    return tree;
}


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
        fullCache.clear();
        std::cerr << "[zgf dbg] left Divergent : "
                  << currNode->depth << " " << currNode->data.currBB << "\n";
        return root;
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
        fullCache.clear();
        std::cerr << "[PCT] right Divergent : "
                  << currNode->depth << " " << currNode->data.currBB << "\n";
        return root;
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

std::vector<TreeNode *> ExecutionTree::getWillBeVisitedNodes() {
  std::vector<TreeNode*> willbeVisited;
  if (!root) return willbeVisited;

  std::queue<TreeNode*> worklist;
  worklist.push(root);

  while (!worklist.empty()) {
    TreeNode* node = worklist.front();
    worklist.pop();

    if (isFullyBuilt(node))
      continue;

    if (node->status == WillbeVisit)
      willbeVisited.push_back(node);

    if (node->left)  worklist.push(node->left);
    if (node->right) worklist.push(node->right);
  }

  TraceToNode.clear();
  for (auto node : willbeVisited){
    trace t = getTrace(node);
    TraceToNode[t].insert(node);
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
  uint32_t LeftSize = N;
  std::vector<TreeNode*> willbeVisited;

  // re-compute the tobe visited nodes
  std::vector<TreeNode *> allNodes = getWillBeVisitedNodes();
  if (allNodes.size() < LeftSize)
    return allNodes;

  std::set<uint32_t> selectBB, selectNodesIDs;
  while (LeftSize > 0){
    selectBB.clear();
    for (auto node : allNodes){
      trace t = getTrace(node);
      if (selectNodesIDs.count(node->id) == 0 &&
          selectBB.count(t.second) == 0){
        willbeVisited.push_back(node);
        selectBB.insert(t.second);
        selectNodesIDs.insert(node->id);
      }
    }
    LeftSize -= selectBB.size();
  }


  /*
  // get the multi-object uncovered edges map : <uncovered : <rela edge>>
  std::map<trace, std::set<trace>> targetEdges =
      g_searcher->recomputeGuidance();

  // compute each edge's weight, if weight higher, select more nodes
  std::map<trace, uint32_t> weights;
  uint32_t totalWeight = 0;
  for(const auto& it : targetEdges){
    for (auto t : it.second){
      if (TraceToNode.count(t) == 0)
        continue;
      weights[t] += 1;
      totalWeight ++;
    }
  }

  // to sample TreeNode from TraceToNode map
  std::vector<std::pair<trace, uint32_t>> sorted_weights(weights.begin(), weights.end());

  // sort as weight, from big to small
  std::sort(sorted_weights.begin(), sorted_weights.end(),
            [](const auto& a, const auto& b) {
              return a.second > b.second;});

  for (const auto& pair : sorted_weights) {
    trace t = pair.first;
    uint32_t weight = pair.second;
    std::set<TreeNode*> *nodes = &TraceToNode[t];
    std::cerr << "[PCT] important trace: " << t.first << "->" << t.second
              << ", weight: " << weight << std::endl;
    if (LeftSize >= nodes->size()){
      willbeVisited.insert(willbeVisited.end(), nodes->begin(), nodes->end());
      LeftSize -= nodes->size();
    }else if (LeftSize > 0){
      for (auto node : *nodes){
        if (LeftSize == 0) break;
        willbeVisited.push_back(node);
        LeftSize --;
      }
    }
  }

  // random select some nodes
  std::set<uint32_t> nodeIDs;  // avoid to select the same node multiple!
  for (auto node : willbeVisited)
    nodeIDs.insert(node->id);
  if (LeftSize > 0){
    for (auto node : allNodes){
      if (LeftSize == 0) break;
      if (nodeIDs.count(node->id)) continue;

      willbeVisited.push_back(node);
      LeftSize --;
    }
  }*/

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