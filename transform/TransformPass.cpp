#include "TransformPass.h"

#include <ctype.h>
#include <list>
#include <set>

namespace PCT {

TransformPass::TransformPass() {
  program = std::make_shared<CXXProgram>();

  // Setup early exit code block
  earlyExitBlock = std::make_shared<CXXCodeBlock>(program.get());
  auto returnStmt =
      std::make_shared<CXXReturnIntStatement>(earlyExitBlock.get(), 0);
  earlyExitBlock->statements.push_front(returnStmt);
  entryPointMainBlock = nullptr;
}

std::string getBVTypeStr(uint32_t bits, bool isSign){
  std::string typeString = isSign ? "int" : "uint";
  uint32_t formal_bits = 64;
  if (bits <= 8)
    formal_bits = 8;
  else if (bits <= 32)
    formal_bits = 32;
  else if (bits <= 64)
    formal_bits = 64;
  typeString += std::to_string(formal_bits) + "_t";
  return typeString;
}

CXXTypeRef TransformPass::getBVTy(uint32_t bits, bool isSign){
  // Make const type so that Compiler enforces SSA.
  auto ty = std::make_shared<CXXType>(
      program.get(), getBVTypeStr(bits, isSign), false);
  return ty;
}

CXXTypeRef TransformPass::getOrInsertTy(ExprRef e) {
  if (isBoolType(e)){
    return std::make_shared<CXXType>(
        program.get(), "bool", /*isConst=*/true);
  }else if (isBVType(e)){
    return getBVTy(e->bits(), isSigned(e));
  }else{
    llvm::errs() << "[PCT] Unhandle Expr : " << e->toString() << "\n";
    llvm_unreachable("Unhandled sort");
  }
}

void TransformPass::insertHeaderIncludes() {
  // Runtime header includes
  // FIXME: We should probe the query and only emit these header includes
  // if we actually need them.

  // Int types header for LibFuzzer entry point definition.
  program->appendDecl(std::make_shared<CXXIncludeDecl>(
      program.get(),"stdint.h",/*systemHeader=*/true));
  program->appendDecl(std::make_shared<CXXIncludeDecl>(
      program.get(),"stdlib.h",/*systemHeader=*/true));
  program->appendDecl(std::make_shared<CXXIncludeDecl>(
      program.get(),"string.h",/*systemHeader=*/true));
  program->appendDecl(std::make_shared<CXXIncludeDecl>(
      program.get(),"math.h",/*systemHeader=*/true));
  program->appendDecl(std::make_shared<CXXIncludeDecl>(
      program.get(),"stdbool.h",/*systemHeader=*/true));
  program->appendDecl(std::make_shared<CXXIncludeDecl>(
      program.get(),"time.h",/*systemHeader=*/true));

  program->appendDecl(std::make_shared<CXXGenericStatement>(
      program.get(),
      "#define CONCAT(high_byte, low_val, low_width) "
      "(((uint64_t)(high_byte)<< (low_width))|(low_val))"));
  program->appendDecl(std::make_shared<CXXGenericStatement>(
      program.get(),
      "#define EXTRACT(val, hi, lo) "
      "(((val) >> (lo)) & ((1ULL << ((hi) - (lo) + 1)) - 1))"));
}

CXXFunctionDeclRef TransformPass::buildEntryPoint() {
  // Build entry point for LibFuzzer
  auto retTy = std::make_shared<CXXType>(
      program.get(), "unsigned char");
  auto firstArgTy = std::make_shared<CXXType>(
      program.get(), "uint8_t*");
  auto secondArgTy = std::make_shared<CXXType>(
      program.get(), "size_t");
  entryPointFirstArgName = insertSymbol("data");
  auto firstArg = std::make_shared<CXXFunctionArgument>(
      program.get(), entryPointFirstArgName, firstArgTy);
  entryPointSecondArgName = insertSymbol("size");
  auto secondArg = std::make_shared<CXXFunctionArgument>(
      program.get(), entryPointSecondArgName, secondArgTy);
  auto funcArguments = std::vector<CXXFunctionArgumentRef>();
  funcArguments.push_back(firstArg);
  funcArguments.push_back(secondArg);
  auto funcDefn = std::make_shared<CXXFunctionDecl>(
      program.get(), "pct_evaluate_input", retTy, funcArguments,
      /*hasCVisibility=*/false);
  auto funcBody = std::make_shared<CXXCodeBlock>(funcDefn.get());
  funcDefn->defn = funcBody; // FIXME: shouldn't be done like this
  program->appendDecl(funcDefn);
  return funcDefn;
}

void TransformPass::insertBufferSizeGuard(CXXCodeBlockRef cb, uint32_t byteWidth) {
  if (byteWidth == 0)
    return;

  std::string underlyingString;
  llvm::raw_string_ostream condition(underlyingString);
  condition << "size < " << byteWidth;
  condition.flush();
  auto ifStatement =
      std::make_shared<CXXIfStatement>(cb.get(), underlyingString);
  underlyingString.clear();

  auto wrongSizeExitBlock = std::make_shared<CXXCodeBlock>(program.get());

  auto returnStmt =
      std::make_shared<CXXReturnIntStatement>(
          earlyExitBlock.get(), 1);
  wrongSizeExitBlock->statements.push_back(returnStmt);

  ifStatement->trueBlock = wrongSizeExitBlock;
  cb->statements.push_back(ifStatement);
}

std::string
TransformPass::getSanitizedVariableName(const std::string& name) {
  assert(name.find("UINT64") == std::string::npos);

  // NOTE: Z3's implementation doesn't include the `|` in quoted symbol
  // names. So both quoted and un-quoted symbols are handled in the same
  // way.
  if (name.size() == 0) {
    // This is silly but SMT-LIB seems to allow the empty string (when quoted
    // i.e-> `||`) as a symbol name so pick our own name for this.
    return "jfs__empty__";
  }
  std::string buffer;
  // Walkthrough string copying across allowed characters
  // and replacing disallowed characters
  bool requiredChange = false;
  for (const auto& character : name) {
    if (isalnum(character) || character == '_') {
      buffer += character;
      continue;
    }
    requiredChange = true;
    // Valid Simple symbol character in SMT-LIBv2 but not
    // valid for use as an identifier in C++.
    switch (character) {
#define ACTION(SEARCH, REPL)                                                   \
  case SEARCH:                                                                 \
    buffer += REPL;                                                            \
    continue;
      ACTION('~', "_t_");
      ACTION('!', "_ex_");
      ACTION('@', "_at_");
      ACTION('$', "_ds_");
      ACTION('%', "_pc_");
      ACTION('^', "_c_");
      ACTION('&', "_a_");
      ACTION('*', "_s_");
      ACTION('-', "_m_");
      ACTION('+', "_p_");
      ACTION('=', "_e_");
      ACTION('<', "_lt_");
      ACTION('>', "_gt_");
      ACTION('.', "_d_");
      ACTION('?', "_q_");
      ACTION('/', "_fs_");
#undef ACTION
    default:
      // In all other cases just use `_`.
      buffer += '_';
    }
  }

  if (!requiredChange) {
    assert(name.size() > 0);
    return name;
  }

  // FIXME: We need to avoid clashes with our own internal symbols names
  // and C++ keywords.
  assert(buffer.size() > 0);
  return buffer;
}

llvm::StringRef
TransformPass::insertSymbol(const std::string& symbolName) {
  std::string sanitizedName = getSanitizedVariableName(symbolName);
  // Check the sanitized name isn't already used. If it is
  // apply naive algorithm
  if (usedSymbols.count(sanitizedName) > 0) {
    sanitizedName += "_";
    ssize_t indexToStartAt = sanitizedName.size() - 1;
    char toWrite = '0';
    do {
      if (toWrite == '0') {
        sanitizedName += 'X'; // Write place holder
        ++indexToStartAt;
      }
      sanitizedName[indexToStartAt] = toWrite;
      ++toWrite;
      if (toWrite == ('9' + 1)) {
        // Wrap around
        toWrite = '0';
      }
    } while (usedSymbols.count(sanitizedName) > 0);
  }
  auto statusPair = usedSymbols.insert(sanitizedName);
  assert(statusPair.second && "cannot insert already used symbolName");
  return llvm::StringRef(*(statusPair.first));
}

llvm::StringRef TransformPass::insertSSASymbolForExpr(
    ExprRef e, const std::string& symbolName) {
  llvm::StringRef symbolNameRef = insertSymbol(symbolName);
  auto statusPair = exprToSymbolName.insert(std::make_pair(e, symbolNameRef));
  assert(statusPair.second && "expr already has symbol");
  return symbolNameRef;
}

void TransformPass::insertBranchForConstraint(
    ExprRef constraint) {
  // TODO: investigate whether it is better to construct
  // if (!e) { return 0; }
  // or
  // if (e) {} else { return 0;}

  // Construct all SSA variables to get the constraint as a symbol
  doDFSPostOrderTraversal(constraint);
  assert(exprToSymbolName.count(constraint) > 0);
  llvm::StringRef symbolForConstraint = getSymbolFor(constraint);
  auto ifStatement = std::make_shared<CXXIfStatement>(
      getCurrentBlock().get(), symbolForConstraint);
  ifStatement->trueBlock = nullptr;
  ifStatement->falseBlock = earlyExitBlock;
  getCurrentBlock()->statements.push_back(ifStatement);
}

void TransformPass::insertFuzzingTarget(CXXCodeBlockRef cb) {
  CXXCodeBlockRef blockForAbort = cb;
  blockForAbort->statements.push_back(
      std::make_shared<CXXCommentBlock>(cb.get(), "Fuzzing target"));
  blockForAbort->statements.push_back(
      std::make_shared<CXXGenericStatement>(cb.get(), "return 1;"));
}

std::set<uint32_t> TransformPass::findReadIdx(ExprRef e){
  std::vector<ExprRef> stack;
  std::set<uint32_t> index;

  stack.push_back(e);

  while (!stack.empty()) {
    ExprRef top = stack.back();
    stack.pop_back();

    std::shared_ptr<ReadExpr> re = castAs<ReadExpr>(top);
    if (re != NULL) {
      index.insert(re->index());
    } else {
      for (INT32 i = 0; i < top->num_children(); i++) {
        ExprRef k = top->getChild(i);
        stack.push_back(k);
      }
    }
  }
  return index;
}

std::vector<uint8_t> TransformPass::readInput(std::string input_file, uint32_t N) {
  std::vector<uint8_t> input;
  std::ifstream ifs (input_file, std::ifstream::in | std::ifstream::binary);
  if (ifs.fail()) {
    LOG_FATAL("Cannot open an input file :" + input_file + "\n");
    exit(-1);
  }

  char ch;
  uint32_t cnt = 0;
  while (ifs.get(ch)){
    input.push_back((UINT8)ch);
    cnt ++;
    if (N != 0 && cnt >= N) break;
  }

  return input;
}

std::vector<uint8_t> TransformPass::validInput(
    ExecutionTree * executionTree, TreeNode *leafNode) {
  TreeNode *nagetiveNode = leafNode->parent->lefts[0];
  if (nagetiveNode == leafNode)
    nagetiveNode = leafNode->parent->rights[0];

  assert(nagetiveNode->status != UnReachable);

  std::vector<uint8_t> newInput;

  // get solution from SMT solver
  newInput = executionTree->generateValues(nagetiveNode);
  return newInput;
}

bool TransformPass::buildEvaluator(ExecutionTree *executionTree,
                                   std::vector<TreeNode *> *deadNodes) {
  program = std::make_shared<CXXProgram>();

  if (deadNodes->size() < 2)
    return false;

  insertHeaderIncludes();

  auto fuzzFn = buildEntryPoint();
  entryPointMainBlock = fuzzFn->defn;

  auto srandStmt = std::make_shared<CXXGenericStatement>(
      getCurrentBlock().get(), "srand((uint8_t)time(NULL));");
  getCurrentBlock()->statements.push_back(srandStmt);

  std::string forStr = "for(int i=0; i<" +
                       std::to_string(deadNodes->size())
                       + "; i++){";
  auto forBeginStmt = std::make_shared<CXXGenericStatement>(
      getCurrentBlock().get(), forStr);
  getCurrentBlock()->statements.push_back(forBeginStmt);

  uint32_t g_read_idx = 0, curr_read_max = 0;

  // Generate constraint branches
  uint32_t leafIndex = 1;
  uint32_t SAMPLE_MAX = 16;
  std::set<uint32_t> selectedBestID;
  for (TreeNode *leafNode : *deadNodes){

    auto currNode = leafNode;

    // build the byte size guard
    curr_read_max = 0;
    std::set<uint32_t> relativeIndex;
    while (currNode != executionTree->getRoot()) {
      auto index = findReadIdx(currNode->data.constraint);
      for (uint32_t id : index)
        if (id > curr_read_max)
          curr_read_max = id;
      relativeIndex.insert(index.begin(), index.end());
      currNode = currNode->parent;
    }

    // check nagetive node can be reached ?
    std::vector<std::vector<uint8_t>> sampledInputs =
        executionTree->sampleValues(leafNode, relativeIndex, SAMPLE_MAX);

    // soft constriants, don't need to check
    if (sampledInputs.size() == SAMPLE_MAX) continue;

    if (curr_read_max > g_read_idx){
      g_read_idx = curr_read_max;
      insertBufferSizeGuard(getCurrentBlock(), g_read_idx + 1);
    }

    // build the conditions
    currNode = leafNode;
    std::vector<std::string> conditions;
    while (currNode != executionTree->getRoot()) {
      qsym::ExprRef expr = currNode->data.constraint;

      doDFSPostOrderTraversal(expr);

      std::string condition(getSymbolFor(expr));
      if (!currNode->data.taken)
        condition = "!" + condition;
      conditions.push_back(condition);

      currNode = currNode->parent;
    }

    if (conditions.empty()) continue;

    // build the condition statement
    std::string exitIfCondition;
    unsigned idx = conditions.size() - 1;
    for (; idx > 0; idx --)
      exitIfCondition += conditions[idx] + " && ";
    exitIfCondition += conditions[idx];

    auto ifStatement = std::make_shared<CXXIfStatement>(
        getCurrentBlock().get(), exitIfCondition);
    auto trueBlock = std::make_shared<CXXCodeBlock>(program.get());

    /*
    // select fixed best node
    TreeNode *bestNode =
        executionTree->selectBestVisitedNode(selectedBestID, curr_read_max);
    selectedBestID.insert(bestNode->id);

    // build the repaired code block
    auto deadInput = readInput(leafNode->data.input_file, curr_read_max);
    auto bestInput = readInput(bestNode->data.input_file, curr_read_max);
    for (uint32_t readID = 0; readID <= curr_read_max; readID++){
//      if (deadInput[readID] == bestInput[readID])
//        continue;

      std::string repairStr = "data[" + std::to_string(readID) + "] = "
                              + std::to_string(bestInput[readID]) + ";";
      auto repairStmt = std::make_shared<CXXGenericStatement>(
          trueBlock.get(), repairStr);
      trueBlock->statements.push_back(repairStmt);
    }

    auto continueStmt = std::make_shared<CXXGenericStatement>(
        trueBlock.get(), "continue;");
    trueBlock->statements.push_back(continueStmt);
    */

    // build the fix code
    if (sampledInputs.empty()) {
      // nagetive path unsat, return 0
      auto returnStmt = std::make_shared<CXXGenericStatement>(
          trueBlock.get(), "return 0;");
      trueBlock->statements.push_back(returnStmt);

    } else if (sampledInputs.size() == 1) {

      for (auto id : relativeIndex){
        std::string repairStr = "data[" + std::to_string(id) + "] = "
                                + std::to_string(sampledInputs[0][id]) + ";";
        auto repairStmt  = std::make_shared<CXXGenericStatement>(
            trueBlock.get(), repairStr);
        trueBlock->statements.push_back(repairStmt);
      }

      auto continueStmt = std::make_shared<CXXGenericStatement>(
          trueBlock.get(), "continue;");
      trueBlock->statements.push_back(continueStmt);

    }else {
      // may have strict constraints (maybe relational)

      // static const uint8_t vals[][2] = {{16, 17}, {31, 32}, {47, 48}, {111, 222}};
      // int idx = rand() % 4;
      // data[4] = vals[idx][0];
      // data[5] = vals[idx][1];
      // continue;

      std::string sampleStr  = std::to_string(sampledInputs.size());
      std::string varSizeStr = std::to_string(relativeIndex.size());
      std::string arrDefine = "static const uint8_t vals["
        + sampleStr + "]["  + varSizeStr + "] = {";
      for (const auto& inputs : sampledInputs)
        for (uint8_t val : inputs)
          arrDefine += std::to_string(val) + ", ";
      arrDefine += "};";
      std::string randDefine = "int idx = rand() % " + sampleStr + ";";

      auto arrStmt  = std::make_shared<CXXGenericStatement>(
          trueBlock.get(), arrDefine);
      auto randStmt  = std::make_shared<CXXGenericStatement>(
          trueBlock.get(), randDefine);
      trueBlock->statements.push_back(arrStmt);
      trueBlock->statements.push_back(randStmt);

      uint32_t cnt = 0;
      for (auto id : relativeIndex){
        std::string repairStr = "data[" + std::to_string(id) + "] = vals[idx]["
                                + std::to_string(cnt) + "];";
        auto repairStmt  = std::make_shared<CXXGenericStatement>(
            trueBlock.get(), repairStr);
        trueBlock->statements.push_back(repairStmt);
        cnt ++;
      }

      auto continueStmt = std::make_shared<CXXGenericStatement>(
          trueBlock.get(), "continue;");
      trueBlock->statements.push_back(continueStmt);
    }

    // build the enter 'if statement'
    ifStatement->trueBlock = trueBlock;
    ifStatement->falseBlock = nullptr;
    getCurrentBlock()->statements.push_back(ifStatement);

    leafIndex ++;
  }

  insertFuzzingTarget(fuzzFn->defn);

  auto forEndStmt = std::make_shared<CXXGenericStatement>(
      getCurrentBlock().get(), "}");
  auto returnStmt = std::make_shared<CXXGenericStatement>(
      getCurrentBlock().get(), "return 0;");
  getCurrentBlock()->statements.push_back(forEndStmt);
  getCurrentBlock()->statements.push_back(returnStmt);

//  program->print(llvm::errs());
//  llvm::errs() << "========\n";
  return true;
}

void TransformPass::dumpEvaluator(const std::string &path){
  std::error_code EC;
  llvm::raw_fd_ostream file_out(path, EC);

  if (!EC) {
    program->print(file_out);
    file_out.flush();
  } else {
    llvm::errs() << "Failed to open file: " << EC.message() << "\n";
  }
}

////////////////////////

std::string TransformPass::getBoolConstantStr(ExprRef e) const {
  shared_ptr<BoolExpr> boolConstExpr = castAs<BoolExpr>(e);
  assert(boolConstExpr->bits() == 1);

  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  if (boolConstExpr->value())
    ss << "true";
  else
    ss << "false";
  ss.flush();
  return underlyingString;
}

std::string TransformPass::getBVConstantStr(ExprRef e) const {
  ConstantExprRef bvConstExpr = castAs<ConstantExpr>(e);
  assert(bvConstExpr != nullptr);

  unsigned bitWidth = e->bits();
  assert(bitWidth <= 64 && "Support for wide bitvectors not implemented");
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);

  // Get constant
  uint64_t value = bvConstExpr->value().getZExtValue();
  ss << value;
  ss.flush();
  return underlyingString;
}

std::string TransformPass::getFreshSymbol() {
  // TODO: Do something more sophisticatd
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  ss << "ssa_" << counter;
  ss.flush();
  counter++;
  assert(usedSymbols.count(underlyingString) == 0);
  return underlyingString;
}

void TransformPass::insertSSAStmt(ExprRef e, llvm::StringRef expr,
                                  llvm::StringRef preferredSymbolName) {
  auto assignmentTy = getOrInsertTy(e);
  std::string requestedSymbolName;
  if (preferredSymbolName.data() == nullptr) {
    requestedSymbolName = getFreshSymbol();
  } else {
    requestedSymbolName = preferredSymbolName;
    if (usedSymbols.count(requestedSymbolName) > 0) {
      requestedSymbolName = getFreshSymbol();
    }
  }
  llvm::StringRef usedSymbol = insertSSASymbolForExpr(e, requestedSymbolName);
  auto assignmentStmt = std::make_shared<CXXDeclAndDefnVarStatement>(
      getCurrentBlock().get(), assignmentTy, usedSymbol, expr);
  getCurrentBlock()->statements.push_back(assignmentStmt);
}

void TransformPass::insertVoidStmt(ExprRef e, llvm::StringRef expr) {
  auto assignmentTy = getOrInsertTy(e);
  std::string requestedSymbolName = getFreshSymbol();
  insertSSASymbolForExpr(e, requestedSymbolName);
  auto voidStmt = std::make_shared<CXXGenericStatement>(
      getCurrentBlock().get(), expr);
  getCurrentBlock()->statements.push_back(voidStmt);
}

bool TransformPass::hasBeenVisited(ExprRef e) const {
  return exprToSymbolName.count(e) > 0;
}

void TransformPass::doDFSPostOrderTraversal(ExprRef e) {
  // Do post-order DFS traversal. We do this non-recursively to avoid
  // hitting any recursion bounds.
  std::list<ExprRef> queue;
  // Used to keep track of when we examine a node with children
  // for a second time. This indicates that the children have been
  // travsersed so that we can now do the "post order" visit
  std::list<ExprRef> traversingBackUpQueue;
  queue.push_front(e);
  while (!queue.empty()) {
    ExprRef node = queue.front();

    // Check for leaf node
    if (node->num_children() == 0) {
      queue.pop_front();
      // Do "post order" visit
      if (!hasBeenVisited(node)) {
        visit(node);
      }
      continue;
    }

    // Must be an internal node
    if (!traversingBackUpQueue.empty() &&
        traversingBackUpQueue.front() == node) {
      // We are visiting the node for a second time. Do "post order" visit
      queue.pop_front();
      traversingBackUpQueue.pop_front();
      if (!hasBeenVisited(node)) {
        visit(node);
      }
      continue;
    }
    // Visit an internal node for the first time. Add the children to the front
    // of the queue but don't pop this node from the stack so we can visit it a
    // second time when are walking back up the tree.
    traversingBackUpQueue.push_front(node);
    const unsigned numKids = node->num_children();
    for (unsigned index = 0; index < numKids; ++index) {
      // Add the operands from right to left so that they popped
      // off in left to right order
      ExprRef childExpr = node->getChild((numKids - 1) - index);
      
      // Only add the child expr to the queue if it has not been visited
      // before. This is to avoid traversing down a large AST subtree
      // that we've visited before.
      if (!hasBeenVisited(childExpr)) {
        queue.push_front(childExpr);
      }
    }
  }
  assert(traversingBackUpQueue.size() == 0);
}

llvm::StringRef TransformPass::getSymbolFor(ExprRef e) {
  // This is a helper for visitor methods so they can grab symbols without
  // having to check themselves that the key is present. Due to the post
  // order DFS traversal the abort should never be called unless there's
  // a bug in the DFS traversal or visitor methods.
  auto it = exprToSymbolName.find(e);
  if (it != exprToSymbolName.end()) {
    return it->second;
  }

  llvm::errs()
      << "(error attempt to use symbol before it has been defined)\n"
      << "  expr:"<< e->toString() <<"\n";
  abort();
}

void TransformPass::visitConstant(ExprRef e) {
  auto it = exprToSymbolName.find(e);
  if (it != exprToSymbolName.end()) {
    // link the constExpr to ExprRef
    exprToSymbolName.insert(std::make_pair(e, it->second));
    return;
  }

  if (e->kind() == qsym::Bool){
    exprToSymbolName.insert(std::make_pair(e, getBoolConstantStr(e)));
  }
  else if (e->kind() == qsym::Constant){
    exprToSymbolName.insert(std::make_pair(e, getBVConstantStr(e)));
  }
  else{
    llvm::errs()
        << "(error attempt to generate non-constant expr)\n"
        << "  expr:"<< e->toString() <<"\n";
    abort();
  }
}

void TransformPass::visitRead(ExprRef e) {
  std::shared_ptr<ReadExpr> re = castAs<ReadExpr>(e);

  // here to initial read variable
  auto it = exprToSymbolName.find(e);
  if (it == exprToSymbolName.end()) {
    std::string readString;
    llvm::raw_string_ostream readSS(readString);

    readSS << "data[" << re->index() << "]";
    readSS.flush();

    exprToSymbolName.insert(std::make_pair(re, readString));
  }

  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  ss << getSymbolFor(re);
  ss.flush();
}

void TransformPass::visitEqual(ExprRef e) {
  auto arg0 = e->getChild(0);
  auto arg1 = e->getChild(1);
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  ss << getSymbolFor(arg0) << " == " << getSymbolFor(arg1);
  insertSSAStmt(e, ss.str());
}

void TransformPass::visitDistinct(ExprRef e) {
  const unsigned numArgs = e->num_children();
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);

  // FIXME: This is terrible and quadratically explodes.  It also doesn't look
  // like the rest of our "three address code" style statements.
  // Output pairwise `!=` combinations.
  bool isFirst = true;
  for (unsigned firstArgIndex = 0; firstArgIndex < numArgs; ++firstArgIndex) {
    for (unsigned secondArgIndex = firstArgIndex + 1; secondArgIndex < numArgs;
         ++secondArgIndex) {
      auto arg0 = e->getChild(firstArgIndex);
      auto arg1 = e->getChild(secondArgIndex);
      if (isFirst) {
        isFirst = false;
      } else {
        ss << " && ";
      }
      ss << "( " << getSymbolFor(arg0) << " != " << getSymbolFor(arg1) << " )";
    }
  }
  insertSSAStmt(e, ss.str());
}

void TransformPass::visitIfThenElse(ExprRef e) {
  assert(e->num_children() == 3);
  auto condition = e->getChild(0);
  auto trueExpr  = e->getChild(1);
  auto falseExpr = e->getChild(2);
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  ss << "(" << getSymbolFor(condition) << ")?(" << getSymbolFor(trueExpr)
     << "):(" << getSymbolFor(falseExpr) << ")";
  insertSSAStmt(e, ss.str());
}

void TransformPass::visitBvNot(ExprRef e) {
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  auto arg0 = e->getChild(0);
  ss << "!(" << getSymbolFor(arg0) << ")";
  insertSSAStmt(e, ss.str());
}

void TransformPass::visitBvNeg(ExprRef e) {
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  auto arg0 = e->getChild(0);
  ss << "-(" << getSymbolFor(arg0) << ")";
  insertSSAStmt(e, ss.str());
}

// Convenience macro to avoid writing lots of duplicate code
#define BV_BIN_OP(NAME, CALL_NAME)                                              \
  void TransformPass::NAME(ExprRef e) {                                         \
    auto arg0 = e->getChild(0);                                                 \
    auto arg1 = e->getChild(1);                                                 \
    std::string underlyingString;                                               \
    llvm::raw_string_ostream ss(underlyingString);                              \
    ss << getSymbolFor(arg0) << " " #CALL_NAME " "                              \
       << getSymbolFor(arg1);                                                   \
    insertSSAStmt(e, ss.str());                                                 \
  }

#define BV_NARY_OP(NAME, CALL_NAME)                                             \
  void TransformPass::NAME(ExprRef e) {                                         \
    const unsigned numArgs = e->num_children();                                 \
    std::string underlyingString;                                               \
    llvm::raw_string_ostream ss(underlyingString);                              \
    auto arg0 = e->getChild(0);                                                 \
    /* Correct number of opening braces*/                                       \
    for (unsigned index = 2; index < numArgs; ++index) {                        \
      ss << "(";                                                                \
    }                                                                           \
    for (unsigned index = 1; index < numArgs; ++index) {                        \
      if (index == 1) {                                                         \
        ss << getSymbolFor(arg0);                                               \
      }                                                                         \
      auto argN = e->getChild(index);                                           \
      if (index > 1) {                                                          \
        /* Closing brace for previous operation */                              \
        ss << ")";                                                              \
      }                                                                         \
      ss << " " #CALL_NAME " " << getSymbolFor(argN);                           \
    }                                                                           \
    insertSSAStmt(e, ss.str());                                                 \
  }

BV_BIN_OP(visitBvAdd,  +)
BV_BIN_OP(visitBvMul,  *)
BV_BIN_OP(visitBvSub,  -)
BV_BIN_OP(visitBvSDiv, /)
BV_BIN_OP(visitBvUDiv, /)
BV_BIN_OP(visitBvSRem, %)
BV_BIN_OP(visitBvURem, %)
BV_BIN_OP(visitBvULE,  <=)
BV_BIN_OP(visitBvSLE,  <=)
BV_BIN_OP(visitBvUGE,  >=)
BV_BIN_OP(visitBvSGE,  >=)
BV_BIN_OP(visitBvULT,  <)
BV_BIN_OP(visitBvSLT,  <)
BV_BIN_OP(visitBvUGT,  >)
BV_BIN_OP(visitBvSGT,  >)
BV_BIN_OP(visitBvShl,  <<)
BV_BIN_OP(visitBvLShr, >>)

void TransformPass::visitBvAShr(ExprRef e) {
  auto arg0 = e->getChild(0);
  auto arg1 = e->getChild(1);
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  std::string eType = getBVTypeStr(e->bits(), isSigned(e));
  ss << "((" << eType << ")" << getSymbolFor(arg0) << ") >> " << getSymbolFor(arg1);
  insertSSAStmt(e, ss.str());
}

// Bitvector NAry operations. Even though in SMT-LIBv2 these ops are binary Z3
// allows n-ary versions which could be introduced by its simplication steps.
// We assume these operations are associative so it doesn't matter the order we
// apply them in.
BV_NARY_OP(visitBvOr,  |)
BV_NARY_OP(visitBvAnd, &)
BV_NARY_OP(visitBvXor, ^)

#undef BV_BIN_OP
#undef BV_NARY_OP

void TransformPass::visitBvConcat(ExprRef e) {
  const unsigned numArgs = e->num_children();
  assert(numArgs == 2);
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  auto arg0 = e->getChild(0);
  auto arg1 = e->getChild(1);

  std::string eType = getBVTypeStr(e->bits(), isSigned(e));
  ss << "CONCAT(" << getSymbolFor(arg0) << ", "
     << getSymbolFor(arg1) << ", " << arg1->bits() << ")";
  ss.flush();
  insertSSAStmt(e, ss.str());
}

void TransformPass::visitBvSignExtend(ExprRef e) {
  // The extension amount is not an argument
  assert(e->num_children() == 1);
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  auto arg0 = e->getChild(0);

  std::string eType = getBVTypeStr(e->bits(), isSigned(e));
  ss << "(" << eType << ")" << getSymbolFor(arg0);
  insertSSAStmt(e, ss.str());
}

void TransformPass::visitBvZeroExtend(ExprRef e) {
  // The same as sign extend
  visitBvSignExtend(e);
}

void TransformPass::visitBvExtract(ExprRef e) {
  // The bit indices are not arguments
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);

  std::shared_ptr<ExtractExpr> EE = castAs<ExtractExpr>(e);
  auto arg0 = e->getChild(0);
  unsigned offset = EE->index();
  unsigned width  = EE->bits();

  // actually no extract
  if (arg0->bits() == width) {
    ss << getSymbolFor(arg0);
  }else {
    // Get the indicies
    // Get the extension count. This is a paramter on the function
    // declaration rather an argument in the application
    unsigned lowBit  = offset;
    unsigned highBit = lowBit + width - 1;

    assert(highBit >= lowBit);

    std::string eType = getBVTypeStr(e->bits(), isSigned(e));
    ss << "(" << eType << ") EXTRACT(" << getSymbolFor(arg0) << ", "
       << highBit << ", " << lowBit << ")";
    ss.flush();
  }
  insertSSAStmt(e, ss.str());
}

}