#include "BinaryTree.h"

template<typename T> std::ostream &operator<<(std::ostream &output, Node<T> node);

template<typename T> std::ostream &operator<<(std::ostream &output, Node<T> node) {
    output << "Value: " << node.data;
    if (node.parent) output << " Parent: " << node.parent -> data;
    if (!node.lefts.empty()) output << " Left: " << node.lefts.size();
    if (!node.rights.empty()) output << " Right: " << node.rights.size();
    output << "\n";
    return output;
}

template <typename E> constexpr auto to_underlying(E e) noexcept {
  return static_cast<std::underlying_type_t<E>>(e);
}

bool has_intersection(const std::set<uint32_t>& A, const std::set<uint32_t>& B) {
  auto itA = A.begin();
  auto itB = B.begin();

  while (itA != A.end() && itB != B.end()) {
    if (*itA < *itB) {
      ++itA;
    } else if (*itB < *itA) {
      ++itB;
    } else {
      return true;
    }
  }
  return false;
}

/////////////////////

bool ExecutionTree::deserializeToQsymExpr(
     const pct::SymbolicExpr &protoExpr, qsym::ExprRef &qsymExpr, uint32_t *max_read) {
  UINT32 hashValue = protoExpr.hash();
  auto it = protoCached.find(hashValue);
  if (it != protoCached.end()) {
    qsymExpr = it->second;
    return true;
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
    if (idx > *max_read)
      *max_read = idx;
    break;
  }
  case pct::ExprKind::Extract: {
    if (!deserializeToQsymExpr(protoExpr.children(0), child0, max_read))
      return false;
    qsymExpr = g_expr_builder->createExtract(
        child0, protoExpr.value() & 0xFFFFFFFF, protoExpr.bits());
    break;
  }
  case pct::ExprKind::ZExt: {
    uint32_t bits = protoExpr.bits();
    if (!deserializeToQsymExpr(protoExpr.children(0), child0, max_read))
      return false;
    qsymExpr = g_expr_builder->createZExt(child0, bits);
    break;
  }
  case pct::ExprKind::SExt: {
    uint32_t bits = protoExpr.bits();
    if (!deserializeToQsymExpr(protoExpr.children(0), child0, max_read))
      return false;
    qsymExpr = g_expr_builder->createSExt(child0, bits);
    break;
  }
  case pct::ExprKind::Neg: case pct::ExprKind::Not:
  case pct::ExprKind::LNot: {
    if (!deserializeToQsymExpr(protoExpr.children(0), child0, max_read))
      return false;
    qsymExpr = g_expr_builder->createUnaryExpr(
        static_cast<qsym::Kind>(to_underlying(exprKind)), child0);
    break;
  }
  case pct::ExprKind::Concat:{
    if (protoExpr.children_size() < 2) return false;
    if (!deserializeToQsymExpr(protoExpr.children(0), child0, max_read))
      return false;
    if (!deserializeToQsymExpr(protoExpr.children(1), child1, max_read))
      return false;
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
    if (protoExpr.children_size() < 2) return false;
    if (!deserializeToQsymExpr(protoExpr.children(0), child0, max_read))
      return false;
    if (!deserializeToQsymExpr(protoExpr.children(1), child1, max_read))
      return false;
    qsymExpr = g_expr_builder->createBinaryExpr(
        static_cast<qsym::Kind>(to_underlying(exprKind)), child0, child1);
    break;
  }
  case pct::ExprKind::Ite: {
    if (protoExpr.children_size() < 3) return false;
    if (!deserializeToQsymExpr(protoExpr.children(0), child0, max_read))
      return false;
    if (!deserializeToQsymExpr(protoExpr.children(1), child1, max_read))
      return false;
    if (!deserializeToQsymExpr(protoExpr.children(2), child2, max_read))
      return false;
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
  return true;
}

bool ExecutionTree::updatePCTree(
     const fs::path &constraint_file, const fs::path &input) {

  // resize the input into limit MAX_FSIZE
  uint32_t fsize = std::filesystem::file_size(input);
  if (fsize > MAX_FSIZE)
    std::filesystem::resize_file(input, MAX_FSIZE);

  ifstream inputf(constraint_file, std::ofstream::in | std::ofstream::binary);
  if (inputf.fail()){
    std::cerr << "Unable to open a file ["
              << constraint_file <<"] to update Path Constaint Tree\n";
    return false;
  }

  pct::ConstraintSequence cs;
  cs.ParseFromIstream(&inputf);

  uint32_t bbSize = cs.visbb_size();
  for (uint32_t i = 0; i < bbSize; i++)
    g_searcher->updateVisBB(cs.visbb(i));

  uint32_t max_read = 0;
  bool isNew = false;

  qsym::ExprRef pathCons;
  std::vector<qsym::ExprRef> constriants;

  TreeNode *currNode = getRoot();
  for (int i = 0; i < cs.node_size(); i++) {
    const pct::SequenceNode &pnode = cs.node(i);

    if (!pnode.has_constraint()) continue;

    bool branchTaken = pnode.taken() > 0;
    bool success = deserializeToQsymExpr(
        pnode.constraint(), pathCons, &max_read);
    if (!success) return isNew; // avoid protobuf deserialize error

    if (pathCons->isBool() || pathCons->isConstant()) continue;
    g_searcher->updateVisBB(pnode.b_id());

    qsym::ExprRef negativeCond =
        branchTaken ? pathCons : g_expr_builder->createLNot(pathCons);

//    g_solver->push();
//    auto res = g_solver->check();
//    g_solver->pop();
//
//    if (g_solver->check() == z3::unsat)
//      continue;

    PCTNode pctNode(pathCons, input, branchTaken, pnode.b_id());

    auto idx = findReadIdx(pathCons);
    pctNode.idx.insert(idx.begin(), idx.end());

    currNode = updateTree(currNode, pctNode, &isNew);
//    std::cerr << "[zgf dbg] [" << i << "] " << branchTaken << " " << pnode.b_id()
//              << " " << currNode->data.constraint->toString() << "\n";
  }
  return isNew;
}

bool ExecutionTree::isFullyBuilt(const TreeNode* node) {
  if (node->isLeaf()) {
    if (node->status == WillbeVisit || node->status == HasSolved)
      return false;
    return true; // is terminal PC
  }
  else if (node->lefts.empty() || node->rights.empty()) {
    return false;
  }
  bool isFull = true;

  for (auto left : node->lefts) isFull &= isFullyBuilt(left);
  if (!isFull) return isFull;

  for (auto right : node->rights) isFull &= isFullyBuilt(right);
  return isFull;
}

bool ExecutionTree::isFullyVisited(const TreeNode* node) {
  if (fullVisitCache.count(node))
    return true;

  if (node->isLeaf()) {
    if (node->depth >= 300) // reach the max constraints
      return false;

    if (node->status == HasVisited)
      return true;
    return false; // is terminal PC
  }
  else if (node->lefts.empty() || node->rights.empty()) {
    return false;
  }

  bool isFull = true;

  for (auto left : node->lefts) isFull &= isFullyVisited(left);
  if (!isFull) return isFull;

  for (auto right : node->rights) isFull &= isFullyVisited(right);

  if (isFull)
    fullVisitCache.insert(node);

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
                         "[has solved]";

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
  for (const TreeNode *left : node->lefts){
    printNodeWithIndent(left, depth);
    if (isFullPrint || !isFullyBuilt(left))
      printTree(left, depth + 1, limitDepth, isFullPrint);
  }

  // 再处理右子树（taken = true）
  for (const TreeNode *right : node->rights){
    printNodeWithIndent(right, depth);
    if (isFullPrint || !isFullyBuilt(right))
      printTree(right, depth + 1, limitDepth, isFullPrint);
  }
}

////////////////////////

TreeNode *ExecutionTree::updateTree(
    TreeNode *currNode, const PCTNode& pctNode, bool *isNew){

  currNode->status = HasVisited;
  TreeNode *nextNode = root;

  if (pctNode.taken) { /// left is the true branch
    if (!currNode->lefts.empty()) {
      // find matched left node
      for (TreeNode *left : currNode->lefts){
        if (left->data.currBB != pctNode.currBB) continue;

        if (left->data.constraint->hash() == pctNode.constraint->hash()){
          nextNode = left;
          break;
        }
      }

      // no match, currNode is diverse
      if (nextNode == root){
        TreeNode *newLeft = constructTreeNode(currNode, pctNode);
        *isNew = true;
        currNode->lefts.push_back(newLeft);
        nextNode = newLeft;
      }

    } else {
      TreeNode *newLeft = constructTreeNode(currNode, pctNode);
      *isNew = true;
      currNode->lefts.push_back(newLeft);
      nextNode = newLeft;
    }

    if (currNode->rights.empty()) {
      TreeNode *newRight = constructTreeNode(currNode, pctNode);
      *isNew = true;
      newRight->data.taken = false;
      currNode->rights.push_back(newRight);
    }

    nextNode->data.taken = true;

  } else {
    if (!currNode->rights.empty()) {
      // find matched right node
      for (TreeNode *right : currNode->rights){
        if (right->data.currBB != pctNode.currBB) continue;

        if (right->data.constraint->hash() == pctNode.constraint->hash()){
          nextNode = right;
          break;
        }
      }

      // no match, currNode is diverse
      if (nextNode == root){
        TreeNode *newRight = constructTreeNode(currNode, pctNode);
        *isNew = true;
        currNode->rights.push_back(newRight);
        nextNode = newRight;
      }

    } else {
      TreeNode *newRight = constructTreeNode(currNode, pctNode);
      *isNew = true;
      currNode->rights.push_back(newRight);
      nextNode = newRight;
    }

    if (currNode->lefts.empty()) {
      TreeNode *newLeft = constructTreeNode(currNode, pctNode);
      *isNew = true;
      newLeft->data.taken = true;
      currNode->lefts.push_back(newLeft);
    }

    nextNode->data.taken = false;
  }

  nextNode->status = HasVisited;
  return nextNode;
}


std::set<uint32_t> ExecutionTree::findReadIdx(qsym::ExprRef e){
  std::vector<qsym::ExprRef> stack;
  std::set<uint32_t> index;

  stack.push_back(e);

  while (!stack.empty()) {
    qsym::ExprRef top = stack.back();
    stack.pop_back();

    std::shared_ptr<qsym::ReadExpr> re = qsym::castAs<qsym::ReadExpr>(top);
    if (re != NULL) {
      index.insert(re->index());
    } else {
      for (INT32 i = 0; i < top->num_children(); i++) {
        qsym::ExprRef k = top->getChild(i);
        stack.push_back(k);
      }
    }
  }
  return index;
}

std::vector<TreeNode *> ExecutionTree::selectDeadNode() {
  std::vector<TreeNode*> deadNode;
  if (!root) return deadNode;

  std::queue<TreeNode*> worklist;
  worklist.push(root);

  while (!worklist.empty()) {
    TreeNode* node = worklist.front();
    worklist.pop();

    if (node->depth > 50)
      continue;

    if (node != root && isFullyVisited(node)){
      bool isEqual = node->data.constraint->kind() == qsym::Equal &&
                     node->data.taken;

      auto idx = findReadIdx(node->data.constraint);
      bool isInbound = true;
      for (auto id : idx)
        if (id > 100) isInbound = false;

      // do not check out bound constrinats
      if (!isEqual && isInbound)
        deadNode.push_back(node);
      continue;
    }

    for (auto left : node->lefts) worklist.push(left);
    for (auto right : node->rights) worklist.push(right);
  }

  return deadNode;
}

std::vector<TreeNode *> ExecutionTree::selectWillBeVisitedNodes(
    std::set<uint32_t> *deadBB, uint32_t N) {
  std::vector<TreeNode*> willbeVisited;
  if (!root) return willbeVisited;

  std::set<uint32_t> selectedBB;
  std::queue<TreeNode*> worklist;
  worklist.push(root);

  while (!worklist.empty()) {
    TreeNode *node = worklist.front();
    worklist.pop();

    if (node->status == WillbeVisit &&
        node != root &&
        deadBB->count(node->data.currBB) == 0 &&
        selectedBB.count(node->data.currBB) == 0){

      willbeVisited.push_back(node);
      selectedBB.insert(node->data.currBB);

      if (willbeVisited.size() >= N)
        return willbeVisited;

      continue;
    }

    for (auto left : node->lefts) worklist.push(left);
    for (auto right : node->rights) worklist.push(right);
  }

  return willbeVisited;
}

std::vector<TreeNode *> ExecutionTree::selectDeepestNodes(uint32_t N) {
  if (current_bucket == 0)
    cleanTobeVisited();

  std::vector<TreeNode*> result;
  if (tobeVisited.empty() || N == 0) return result;

  const size_t size = tobeVisited.size();

  // ====== 2. 计算当前桶范围（向上取整确保全覆盖）======
  size_t bucket_size = ((size + 9) / 10) << 2; // 每桶最小大小
  size_t start_idx = current_bucket * bucket_size;
  size_t end_idx = std::min((current_bucket + 1) * bucket_size, size);

  // 安全处理：桶索引超出范围时回绕（应对size动态变化）
  if (start_idx >= size) {
    current_bucket = 0; // 重置避免卡死
    start_idx = 0;
    end_idx = std::min(bucket_size, size);
  }

  // ====== 3. 桶内循环采样（避免总是取桶开头）======
  size_t len = end_idx - start_idx;
  size_t bucket_offset = select_offset % (len + 1);
  bool taken_enough = false;

  for (size_t step = 0; step < size - start_idx && result.size() < N; ++step) {
    size_t idx = start_idx + (bucket_offset + step) % len;
    if (idx >= size) break;
    TreeNode* node = tobeVisited[idx];

    if (node->status == WillbeVisit &&
        !fastUnsatCheck(node)) {

      result.push_back(node);

      if (result.size() >= N) {
        // 记录下次桶内起始偏移
        select_offset = (bucket_offset + step + 1) % (len + 1);
        taken_enough = true;
        break;
      }
    }
  }

  // 未取满时推进桶内偏移（避免下次从同位置开始）
  if (!taken_enough && (end_idx > start_idx)) {
    select_offset  = (select_offset + 1) % (len + 1);
    // 推进到下一个桶（核心：实现N%区间轮询）
    current_bucket = (current_bucket + 1) % 10;
  }

  // ====== 4. 推进到下一个桶（核心：实现10%区间轮询）======
//  current_bucket = (current_bucket + 1) % 10;

  return result;
}

std::vector<qsym::ExprRef> ExecutionTree::getRelaConstraints(
    const TreeNode *srcNode){
  std::vector<qsym::ExprRef> constraints;
  std::set<uint32_t> idx(srcNode->data.idx);

  auto currNode = srcNode;
  while (currNode != getRoot()) {
    // do not collect unrelative constraints
    if (has_intersection(idx, currNode->data.idx)){
      idx.insert(currNode->data.idx.begin(), currNode->data.idx.end());

      qsym::ExprRef expr = currNode->data.constraint;
      if (!currNode->data.taken)
        expr = g_expr_builder->createLNot(expr);
      constraints.push_back(expr);
    }
    currNode = currNode->parent;
  }
  return constraints;
}

std::vector<qsym::ExprRef> ExecutionTree::getDomConstraints(
    const TreeNode *srcNode){
  std::vector<qsym::ExprRef> andConds;
//  qsym::ExprRef lastCond = srcNode->data.constraint;
//  if (!srcNode->data.taken)
//    lastCond = g_expr_builder->createLNot(lastCond);

  qsym::ExprRef lastCond;
  std::set<uint32_t> domBB = g_searcher->computeDominatorsFor(srcNode->data.currBB);
  std::set<uint32_t> idx(srcNode->data.idx);
  uint32_t srcBBID = srcNode->data.currBB;

  // optimal solving
  if (domBB.empty()){
    qsym::ExprRef expr = srcNode->data.constraint;
    if (!srcNode->data.taken)
      expr = g_expr_builder->createLNot(expr);
    andConds.push_back(expr);
    return andConds;
  }

  auto currNode = srcNode;
  while (currNode != root) {
    // only collect dominate constraints
    if (domBB.count(currNode->data.currBB)){
      qsym::ExprRef expr = currNode->data.constraint;
      if (!currNode->data.taken)
        expr = g_expr_builder->createLNot(expr);

      if (currNode == srcNode){
        lastCond = expr;
      }else if (currNode->data.currBB == srcBBID){
        expr = g_expr_builder->createLNot(expr);
        lastCond = g_expr_builder->createLOr(lastCond, expr);
      }else if (has_intersection(idx, currNode->data.idx)){
        idx.insert(currNode->data.idx.begin(), currNode->data.idx.end());
        andConds.push_back(expr);
      }
    }

    currNode = currNode->parent;
  }

  if (!domBB.empty())
    andConds.push_back(lastCond);
  return andConds;
}

std::string ExecutionTree::generateTestCase(TreeNode *node, uint32_t *domSize){

//  std::cerr << node->depth << " " << node->data.currBB
//            << " " << node->data.taken << node->data.hash
//            << " " << node->data.constraint->toString() << "\n";

  fs::path input = node->data.input_file;
  std::vector<qsym::ExprRef> constraints = getRelaConstraints(node);

  g_solver->setInputFile(input);
  g_solver->push();
  for (const auto& cond : constraints)
    g_solver->add(cond->toZ3Expr());

  std::string new_case = g_solver->fetchTestcase();
  g_solver->pop();

//  std::cerr << "[zgf dbg] rela " << (new_case.empty() ? "UNSAT " : "SAT ") << constraints.size() << "\n";

  // No Solution, set the node status to UNSAT
  // SAT, record the testcase,
  if (new_case.empty())
    node->status = UnReachable;
  else{
    node->status = HasSolved;
    return new_case;
  }

  // use optimal solving
  constraints = getDomConstraints(node);
  g_solver->push();
  for (const auto& cond : constraints)
    g_solver->add(cond->toZ3Expr());

  new_case = g_solver->fetchTestcase();
  g_solver->pop();

//  std::cerr << "[zgf dbg] dom " << (new_case.empty() ? "UNSAT " : "SAT ") << constraints.size() << "\n";

  *domSize = constraints.size();

  return new_case;
}

std::vector<std::vector<uint8_t>> ExecutionTree::sampleDeadValues(
    const DeadZone *zone, const std::set<uint32_t>& index, uint32_t N){
  TreeNode *leafNode = zone->domNodes[0];
  fs::path input   = leafNode->data.input_file;
  uint32_t srcBBID = leafNode->data.currBB;

  std::vector<qsym::ExprRef> andNodes;
  qsym::ExprRef lastCond;

  for (uint32_t i = 0; i < zone->domNodes.size(); i++){
    auto node = zone->domNodes[i];
    qsym::ExprRef cond = node->data.constraint;
    if (!node->data.taken)
      cond = g_expr_builder->createLNot(cond);

    if (i == 0){
      // negetive the last condition
      lastCond = g_expr_builder->createLNot(cond);
      continue;
    }

    if (node->data.currBB == srcBBID){
      cond = g_expr_builder->createLNot(cond);
      lastCond = g_expr_builder->createLOr(lastCond, cond);
    }
    else{
      std::set<uint32_t> currIdxs = findReadIdx(node->data.constraint);
      if (has_intersection(index, currIdxs)) {
        andNodes.push_back(cond);
      }
    }
  }

  std::vector<std::vector<uint8_t>> sampleIndexValues;

  // push basic constraints
  g_solver->push();
  g_solver->setInputFile(input);

  g_solver->add(lastCond->toZ3Expr());
  for (const auto& cond : andNodes){
    g_solver->add(cond->toZ3Expr());
  }

  std::vector<UINT8> new_case = g_solver->fetchValues();

  uint32_t sampleCnt = 0;
  while(!new_case.empty()){
    std::vector<uint8_t> currSample;
    qsym::ExprRef sampleCons;
    for (uint32_t id : index){
      currSample.push_back(new_case[id]);
      qsym::ExprRef value = g_expr_builder->createConstant(new_case[id], 8);
      qsym::ExprRef readExpr = g_expr_builder->createRead(id);
      qsym::ExprRef oneEqual = g_expr_builder->createEqual(value, readExpr);
      if (sampleCons)
        sampleCons = g_expr_builder->createAnd(sampleCons, oneEqual);
      else
        sampleCons = oneEqual;
    }

    sampleIndexValues.push_back(currSample);
    g_solver->add(g_expr_builder->createLNot(sampleCons)->toZ3Expr());
    new_case = g_solver->fetchValues();

    sampleCnt ++;
    if (sampleCnt >= N)
      break;
  }

  g_solver->pop();

  return sampleIndexValues;
}
