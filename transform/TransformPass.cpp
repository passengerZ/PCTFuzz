#include "TransformPass.h"

#include <ctype.h>
#include <list>
#include <set>

namespace PCT {

TransformPass::TransformPass() : counterTy(nullptr) {
  program = std::make_shared<CXXProgram>();

  // Setup early exit code block
  earlyExitBlock = std::make_shared<CXXCodeBlock>(program.get());
  auto returnStmt =
      std::make_shared<CXXReturnIntStatement>(earlyExitBlock.get(), 0);
  earlyExitBlock->statements.push_front(returnStmt);
  entryPointMainBlock = nullptr;

  if (isTrackingNumConstraintsSatisfied()) {
    numConstraintsSatisfiedSymbolName = insertSymbol("jfs_num_const_sat");
  }
  libFuzzerCustomCounterArraySymbolName =
      insertSymbol("jfs_libfuzzer_custom_counter");
}

CXXCodeBlockRef TransformPass::getConstraintIsFalseBlock() {
  return earlyExitBlock;
  /*if (options->getBranchEncoding() ==
      CXXProgramBuilderOptions::BranchEncodingTy::FAIL_FAST) {
    return earlyExitBlock;
  }
  // No-op block
  return nullptr;*/
}

bool TransformPass::isTrackingNumConstraintsSatisfied() const {
  /*return isTrackingMaxNumConstraintsSatisfied() ||
         options->getBranchEncoding() ==
             CXXProgramBuilderOptions::BranchEncodingTy::TRY_ALL;*/
  return false;
}

bool TransformPass::isTrackingMaxNumConstraintsSatisfied() const {
  /*return options->getRecordMaxNumSatisfiedConstraints() ||
         options->getTraceIncreaseMaxNumSatisfiedConstraints() ||
         options->getBranchEncoding() ==
             CXXProgramBuilderOptions::BranchEncodingTy::TRY_ALL_IMNCSF;*/
  return false;
}

bool TransformPass::isTrackingWithLibFuzzerCustomCounter() const {
  // This is a little nasty. Unlikely other `isTracking*()` functions this
  // function will only return the correct value after `build(Query)` is called
  // because until then we don't know how many constraints there are.
  /*return numberOfConstraints > 0 &&
         options->getBranchEncoding() ==
             CXXProgramBuilderOptions::BranchEncodingTy::TRY_ALL_IMNCSF;*/
  return false;
}

bool TransformPass::isUpdatingMaxNumConstraintsSatisfiedAtEnd() const {
  /*if (!isTrackingMaxNumConstraintsSatisfied()) {
    return false;
  }
  if (options->getBranchEncoding() ==
      CXXProgramBuilderOptions::BranchEncodingTy::FAIL_FAST) {
    return false;
  }
  // All other encodings can update the "maximum number of satisfied
  // constraints" counter after evaluating all constraints.
  return true;*/
  return false;
}

bool TransformPass::isTrackingNumberOfInputsTried() const {
  /*return options->getRecordNumberOfInputs();*/
  return false;
}

bool TransformPass::isTrackingNumberOfWrongSizedInputsTried() const {
  /*return options->getRecordNumberOfWrongSizedInputs();*/
  return false;
}

bool TransformPass::isRecordingStats() const {
  // Note we can't use `isTrackingMaxNumConstraintsSatisfied()` because
  // that is used for other encodings even when stats are not being recorded.
  /*return options->getRecordMaxNumSatisfiedConstraints() ||
         isTrackingNumberOfInputsTried() ||
         isTrackingNumberOfWrongSizedInputsTried();*/
  return false;
}

bool TransformPass::isTracing() const {
  /*return options->getTraceIncreaseMaxNumSatisfiedConstraints() ||
         options->getTraceWrongSizedInputs();*/
  return false;
}

CXXCodeBlockRef TransformPass::getConstraintIsTrueBlock() {
  if (!isTrackingNumConstraintsSatisfied()) {
    // Empty block (no-op)
    return nullptr;
  }
  if (trueBlock != nullptr) {
    return trueBlock;
  }
  // HACK: We cheat because we can re-use the same codeblock for
  // all constraint `CXXIfStatement`, so we just make the parent
  // nullptr.
  trueBlock = std::make_shared<CXXCodeBlock>(nullptr);
  // Add statement to increment the local constraint counter.
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  ss << "++" << numConstraintsSatisfiedSymbolName;
  trueBlock->statements.push_back(
      std::make_shared<CXXGenericStatement>(
          trueBlock.get(), ss.str()));
  if (isTrackingMaxNumConstraintsSatisfied() &&
      !isUpdatingMaxNumConstraintsSatisfiedAtEnd()) {
    insertUpdateMaxNumConstraintsSatisfiedToBlock(trueBlock);
  }
  return trueBlock;
}

void TransformPass::insertUpdateMaxNumConstraintsSatisfiedToBlock(
    CXXCodeBlockRef cb) {
  // Emit code to increment `maxNumConstraintsSatisfiedSymbolName`
  // if the number of constraints satisfied so far is greater than
  // what had been observed previously.
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  ss << maxNumConstraintsSatisfiedSymbolName << " < "
     << numConstraintsSatisfiedSymbolName;
  auto maxNumGuard = std::make_shared<CXXIfStatement>(
      cb.get(), ss.str());
  maxNumGuard->falseBlock = nullptr; // Do nothing is condition false.
  // Construct block with code to update
  // `maxNumConstraintsSatisfiedSymbolName`
  auto incrementMaxNumConstraintsSatisfiedBlock =
      std::make_shared<CXXCodeBlock>(maxNumGuard.get());
  underlyingString.clear();

//  if (options->getTraceIncreaseMaxNumSatisfiedConstraints()) {
//    ss << "jfs_info(\"Max num constraints satisfied increased from %" PRId64
//          " to %" PRId64 " (out of %" PRId64 ")\\n\","
//       << maxNumConstraintsSatisfiedSymbolName << ","
//       << numConstraintsSatisfiedSymbolName << ","
//       << "UINT64_C(" << numberOfConstraints << "))";
//    incrementMaxNumConstraintsSatisfiedBlock->statements.push_back(
//        std::make_shared<CXXGenericStatement>(
//            incrementMaxNumConstraintsSatisfiedBlock.get(), ss.str()));
//    underlyingString.clear();
//  }

  // HACK: Do assign. We should make a CXXDecl to do this.
  ss << maxNumConstraintsSatisfiedSymbolName << " = "
     << numConstraintsSatisfiedSymbolName;
  incrementMaxNumConstraintsSatisfiedBlock->statements.push_back(
      std::make_shared<CXXGenericStatement>(
          incrementMaxNumConstraintsSatisfiedBlock.get(), ss.str()));

  maxNumGuard->trueBlock = incrementMaxNumConstraintsSatisfiedBlock;
  cb->statements.push_back(maxNumGuard);
}


CXXTypeRef TransformPass::getCounterTy() {
  if (counterTy != nullptr)
    return counterTy;
  counterTy = std::make_shared<CXXType>(
      program.get(), "uint64_t", false);
  return counterTy;
}

CXXTypeRef TransformPass::getBVTy(uint32_t bits){
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  ss << "INT" << bits << "";
  ss.flush();
  // Make const type so that Compiler enforces SSA.
  auto ty = std::make_shared<CXXType>(
      program.get(), underlyingString, true);
  return ty;
}

CXXTypeRef TransformPass::getOrInsertTy(ExprRef e) {
  if (isBoolType(e)){
    return std::make_shared<CXXType>(
        program.get(), "bool", /*isConst=*/true);
  }else if (isBVType(e)){
    return getBVTy(e->bits());
  }else if (isFPType(e)){
    std::string underlyingString = e->bits() == 64 ? "double" : "float";
    auto ty = std::make_shared<CXXType>(
        program.get(), underlyingString, /*isConst=*/true);
    return ty;
  }else{
    llvm_unreachable("Unhandled sort");
  }
}

void TransformPass::insertHeaderIncludes() {
  // Runtime header includes
  // FIXME: We should probe the query and only emit these header includes
  // if we actually need them.
  program->appendDecl(std::make_shared<CXXIncludeDecl>(
      program.get(),"SMTLIB/Core.h",/*systemHeader=*/false));
  program->appendDecl(std::make_shared<CXXIncludeDecl>(
      program.get(), "SMTLIB/BitVector.h", /*systemHeader=*/false));
  program->appendDecl(std::make_shared<CXXIncludeDecl>(
      program.get(), "SMTLIB/Float.h", /*systemHeader=*/false));

  if (isRecordingStats()) {
    program->appendDecl(std::make_shared<CXXIncludeDecl>(
        program.get(), "SMTLIB/Logger.h", /*systemHeader=*/false));
  }

  if (isTracing()) {
    program->appendDecl(std::make_shared<CXXIncludeDecl>(
        program.get(), "SMTLIB/Messages.h", /*systemHeader=*/false));
  }

  // Int types header for LibFuzzer entry point definition.
  program->appendDecl(std::make_shared<CXXIncludeDecl>(
      program.get(),"stdint.h",/*systemHeader=*/true));
  program->appendDecl(std::make_shared<CXXIncludeDecl>(
      program.get(),"stdlib.h",/*systemHeader=*/true));

  // jfs add by zgf to include math.h
  program->appendDecl(std::make_shared<CXXIncludeDecl>(
      program.get(),"math.h",/*systemHeader=*/true));
}

CXXFunctionDeclRef TransformPass::buildEntryPoint() {
  // Build entry point for LibFuzzer
  auto retTy = std::make_shared<CXXType>(
      program.get(), "int");
  auto firstArgTy = std::make_shared<CXXType>(
      program.get(), "const uint8_t*");
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
      program.get(), "LLVMFuzzerTestOneInput", retTy, funcArguments,
      /*hasCVisibility=*/true);
  auto funcBody = std::make_shared<CXXCodeBlock>(funcDefn.get());
  funcDefn->defn = funcBody; // FIXME: shouldn't be done like this
  program->appendDecl(funcDefn);
  return funcDefn;
}

void TransformPass::insertMaxNumConstraintsSatisfiedCounterInit() {
  if (!isTrackingMaxNumConstraintsSatisfied())
    return;
  // Add global variable to track the maximum number of constraints that
  // have been satisfied.
  auto initDecl = std::make_shared<CXXDeclAndDefnVarStatement>(
      program.get(), getCounterTy(), maxNumConstraintsSatisfiedSymbolName, "0");
  program->appendDecl(initDecl);
}

void TransformPass::insertNumInputsCounterInit() {
  if (!isTrackingNumberOfInputsTried())
    return;
  // Add global variable to track the number of inputs tried
  auto initDecl = std::make_shared<CXXDeclAndDefnVarStatement>(
      program.get(), getCounterTy(), numInputsTriedSymbolName, "0");
  program->appendDecl(initDecl);
}

void TransformPass::insertNumWrongSizedInputsCounterInit() {
  if (!isTrackingNumberOfWrongSizedInputsTried())
    return;
  // Add global variable to track the number of inputs tried
  auto initDecl = std::make_shared<CXXDeclAndDefnVarStatement>(
      program.get(), getCounterTy(), numWrongSizedInputsTriedSymbolName, "0");
  program->appendDecl(initDecl);
}

void TransformPass::insertAtExitHandler() {
  if (!isRecordingStats())
    return;
  auto retTy = std::make_shared<CXXType>(program.get(), "void");
  std::vector<CXXFunctionArgumentRef> funcArguments;
  // FIXME: LibFuzzer doesn't support this yet.
  auto funcDefn = std::make_shared<CXXFunctionDecl>(
      program.get(), "LLVMFuzzerAtExit", retTy, funcArguments,
      /*hasCVisibility=*/true);
  auto funcBody = std::make_shared<CXXCodeBlock>(funcDefn.get());
  funcDefn->defn = funcBody; // FIXME: shouldn't be done like this
  program->appendDecl(funcDefn);
  auto loggerTy = std::make_shared<CXXType>(program.get(), "jfs_nr_logger_ty");
  const char* loggerSymbolName = "logger";
  // Add statement to create a logger
  funcBody->statements.push_back(
      std::make_shared<CXXDeclAndDefnVarStatement>(
          funcBody.get(), loggerTy, loggerSymbolName,"jfs_nr_mk_logger_from_env()"));

  // Add statement to log the observed maxNumConstraintsSatisfied
  // value.
  // HACK
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  if (isTrackingMaxNumConstraintsSatisfied()) {
    ss << "jfs_nr_log_uint64(" << loggerSymbolName << ","
       << "\"" << maxNumConstraintsSatisfiedSymbolName << "\","
       << maxNumConstraintsSatisfiedSymbolName << ")";
    funcBody->statements.push_back(
        std::make_shared<CXXGenericStatement>(funcBody.get(), ss.str()));
    underlyingString.clear();
  }

  // Add statement to log the observed number of inputs tried
  if (isTrackingNumberOfInputsTried()) {
    ss << "jfs_nr_log_uint64(" << loggerSymbolName << ","
       << "\"" << numInputsTriedSymbolName << "\"," << numInputsTriedSymbolName
       << ")";
    funcBody->statements.push_back(
        std::make_shared<CXXGenericStatement>(funcBody.get(), ss.str()));
    underlyingString.clear();
  }

  // Add statement to log the observed number of wrong size inputs tried
  if (isTrackingNumberOfWrongSizedInputsTried()) {
    ss << "jfs_nr_log_uint64(" << loggerSymbolName << ","
       << "\"" << numWrongSizedInputsTriedSymbolName << "\","
       << numWrongSizedInputsTriedSymbolName << ")";
    funcBody->statements.push_back(
        std::make_shared<CXXGenericStatement>(funcBody.get(), ss.str()));
    underlyingString.clear();
  }

  ss << "jfs_nr_del_logger(" << loggerSymbolName << ")";
  funcBody->statements.push_back(
      std::make_shared<CXXGenericStatement>(funcBody.get(), ss.str()));
}

void TransformPass::insertBufferSizeGuard(CXXCodeBlockRef cb) {
  if (bufferWidthInBytes == 0)
    return;

  std::string underlyingString;
  llvm::raw_string_ostream condition(underlyingString);
  condition << "size != " << bufferWidthInBytes;
  condition.flush();
  auto ifStatement =
      std::make_shared<CXXIfStatement>(cb.get(), underlyingString);
  underlyingString.clear();

  auto wrongSizeExitBlock = std::make_shared<CXXCodeBlock>(program.get());
  if (isTrackingNumberOfWrongSizedInputsTried()) {
    // Add code to increment counter that tracks the number of wrong
    // sized inputs tried.
    llvm::raw_string_ostream ss(underlyingString);
    ss << "++" << numWrongSizedInputsTriedSymbolName;
    wrongSizeExitBlock->statements.push_back(
        std::make_shared<CXXGenericStatement>(
            wrongSizeExitBlock.get(),ss.str()));
    underlyingString.clear();
  }

//  if (options->getTraceWrongSizedInputs()) {
//    // FIXME: Due to LibFuzzer's implementation it tries a zero size input
//    // once during INIT. We'll emit a spurious warning then. It would be
//    // better if we didn't do this.
//    wrongSizeExitBlock->statements.push_back(
//        std::make_shared<CXXGenericStatement>(
//            wrongSizeExitBlock.get(),
//            "jfs_warning(\"Wrong sized input tried.\\n\")"));
//  }

  auto returnStmt =
      std::make_shared<CXXReturnIntStatement>(
          earlyExitBlock.get(), 0);
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

  // avoid to alloc constantExpr multiple
  ConstantExprRef CE = castAs<ConstantExpr>(e);
  if (CE != NULL)
    constToSymbolName.insert(std::make_pair(e->toString(), symbolNameRef));
  return symbolNameRef;
}

void TransformPass::insertFreeVariableConstruction(
    CXXCodeBlockRef cb) {

  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  // Insert bufferRef.
  // FIXME: We should probably just use C++'s constructor syntax
  // BufferRef<const uint8_t> jfs_buffer_ref<const uint8_t>(data, size)
  auto bufferRefTy =
      std::make_shared<CXXType>(program.get(), "BufferRef<const uint8_t>");
  // Build `BufferRef<uint8_t>(data, size)` string.
  ss << bufferRefTy->getName() << "(" << entryPointFirstArgName << ", "
     << entryPointSecondArgName << ")";
  ss.flush();

  unsigned currentBufferBit = 0;
  for (auto const &readExpr : allVarRead) {
    std::shared_ptr<ReadExpr> re = castAs<ReadExpr>(readExpr);

    // construct variable
    std::string initString;
    llvm::raw_string_ostream tempSS(initString);

    unsigned readBits = re->bits();
    unsigned endBufferBit = currentBufferBit + readBits - 1;
    tempSS << "data[" << re->index() << "]";
    tempSS.flush();

    exprToSymbolName.insert(std::make_pair(readExpr, initString));

    currentBufferBit = endBufferBit + 1;
  }
}

void TransformPass::insertNumConstraintsSatisifedCounterInit(
    CXXCodeBlockRef cb) {
  if (!isTrackingNumConstraintsSatisfied())
    return;
  auto initDecl = std::make_shared<CXXDeclAndDefnVarStatement>(
      cb.get(), getCounterTy(), numConstraintsSatisfiedSymbolName, "0");
  cb->statements.push_back(initDecl);
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
  ifStatement->trueBlock = getConstraintIsTrueBlock();
  ifStatement->falseBlock = getConstraintIsFalseBlock();
  getCurrentBlock()->statements.push_back(ifStatement);
}

void TransformPass::insertFuzzingTarget(CXXCodeBlockRef cb) {
  // FIXME: Replace this with something that we can use to
  // communicate LibFuzzer's outcome
  CXXCodeBlockRef blockForAbort = cb;
//  CXXProgramBuilderOptions::BranchEncodingTy bet = options->getBranchEncoding();
//  if (bet == CXXProgramBuilderOptions::BranchEncodingTy::TRY_ALL ||
//      bet == CXXProgramBuilderOptions::BranchEncodingTy::TRY_ALL_IMNCSF) {
//    // In these encodings we need to guard the abort to make sure all
//    // the constraints are satisfied
//    std::string underlyingString;
//    llvm::raw_string_ostream ss(underlyingString);
//    ss << numConstraintsSatisfiedSymbolName << " == " << numberOfConstraints;
//    auto ifStatement = std::make_shared<CXXIfStatement>(cb.get(), ss.str());
//    blockForAbort = std::make_shared<CXXCodeBlock>(cb.get());
//    ifStatement->trueBlock = blockForAbort;
//    // This is necessary so we don't fall off the end of the function without
//    // returning a value.
//    ifStatement->falseBlock = earlyExitBlock;
//    cb->statements.push_back(ifStatement);
//  }
  blockForAbort->statements.push_back(
      std::make_shared<CXXCommentBlock>(cb.get(), "Fuzzing target"));
  blockForAbort->statements.push_back(
      std::make_shared<CXXGenericStatement>(cb.get(), "abort()"));
}

void TransformPass::insertNumInputsTriedIncrement(CXXCodeBlockRef cb) {
  if (!isTrackingNumberOfInputsTried())
    return;
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  ss << "++" << numInputsTriedSymbolName;
  cb->statements.push_back(
      std::make_shared<CXXGenericStatement>(cb.get(), ss.str()));
}

void TransformPass::insertLibFuzzerCustomCounterDecl() {
  if (!isTrackingWithLibFuzzerCustomCounter()) {
    return;
  }
  assert(numberOfConstraints > 0 && "array can't be zero sized");
  // Emit LibFuzzer specific custom counters. These are only supported
  // on Linux.
  // HACK:
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  ss << "#ifdef "
        "__linux__\n__attribute__((section(\"__libfuzzer_extra_counters\")))\n#"
        "endif\n"
        "static uint8_t "
     << libFuzzerCustomCounterArraySymbolName << "[" << numberOfConstraints
     << "]";
  program->appendDecl(
      std::make_shared<CXXGenericStatement>(program.get(), ss.str()));
}

void TransformPass::insertLibFuzzerCustomCounterInc(
    CXXCodeBlockRef cb) {
  if (!isTrackingWithLibFuzzerCustomCounter()) {
    return;
  }

  // We emit
  //
  // if (jfs_max_num_const_sat > 1) {
  //   jfs_libfuzzer_custom_counter[jfs_max_num_const_sat -1] = 1
  // }
  //
  // In `jfs_libfuzzer_custom_counter` each byte at index `i` is used as a flag
  // to indicate that `i+1` constraints have been satisfied. The
  // `jfs_libfuzzer_custom_counter` array is special in that it gets reset to
  // all zeros on every call and that changing an element to a non-zero value
  // is treated by LibFuzzer as a "feature" (more coverage).
  //
  // This is not very efficient (i.e->  wasting 7 bits) but we can't use a more
  // compact representation because LibFuzzer's treatment of counter values is
  // such that not every bit is treated as a feature.
  //
  // See https://reviews.llvm.org/D40565
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  ss << maxNumConstraintsSatisfiedSymbolName << " > 0";
  auto ifStatement = std::make_shared<CXXIfStatement>(cb.get(), ss.str());
  cb->statements.push_back(ifStatement);
  auto currTrueBlock = std::make_shared<CXXCodeBlock>(ifStatement.get());
  ifStatement->trueBlock = currTrueBlock;

  underlyingString.clear();
  ss << libFuzzerCustomCounterArraySymbolName << "["
     << maxNumConstraintsSatisfiedSymbolName << " -1] = 1";
  currTrueBlock->statements.push_back(
      std::make_shared<CXXGenericStatement>(currTrueBlock.get(), ss.str()));
}

void TransformPass::extractVariables(const std::vector<ExprRef> &constraints){
  for (const auto& e : constraints){
    std::vector<ExprRef> stack;
    std::set<ExprRef> visited;

    if (e->kind() != qsym::Kind::Constant &&
        e->kind() != qsym::Kind::Bool &&
        e->kind() != qsym::Kind::Float) {
      visited.insert(e);
      stack.push_back(e);
    }

    while (!stack.empty()) {
      ExprRef top = stack.back();
      stack.pop_back();

      std::shared_ptr<ReadExpr> re = castAs<ReadExpr>(top);
      if (re != NULL) {
        allVarRead.insert(top);
      } else {
        for (INT32 i = 0; i < top->num_children(); i++) {
          ExprRef k = top->getChild(i);
          if (visited.insert(k).second)
            stack.push_back(k);
        }
      }
    }
  }
  for (const auto& readExpr : allVarRead){
    unsigned readBits = readExpr->bits();
    Variable v(readExpr, bufferWidthInBytes, bufferWidthInBytes + readBits);
    variables.insert(std::make_pair(readExpr, v));
    bufferWidthInBytes += readBits;
  }
}

void TransformPass::build(const std::vector<ExprRef> &constraints) {
  numberOfConstraints = constraints.size();
  program = std::make_shared<CXXProgram>();
  // Record if stats are going to be tracked.
  program->setRecordsRuntimeStats(isRecordingStats());

  extractVariables(constraints);

  insertHeaderIncludes();
//  insertMaxNumConstraintsSatisfiedCounterInit();
//  insertNumInputsCounterInit();
//  insertNumWrongSizedInputsCounterInit();

  insertAtExitHandler();
//  insertLibFuzzerCustomCounterDecl();
  auto fuzzFn = buildEntryPoint();
  entryPointMainBlock = fuzzFn->defn;

  insertBufferSizeGuard(fuzzFn->defn);
  // Note we insert this after the buffer guard check
  // so that we only count correctly sized inputs.
//  insertNumInputsTriedIncrement(fuzzFn->defn);

  insertFreeVariableConstruction(fuzzFn->defn);

//  insertConstantAssignments(fuzzFn->defn);
  insertNumConstraintsSatisifedCounterInit(fuzzFn->defn);

  // Generate constraint branches
  for (const auto& e : constraints)
    insertBranchForConstraint(e);

  insertLibFuzzerCustomCounterInc(fuzzFn->defn);
  insertFuzzingTarget(fuzzFn->defn);

  program->print(llvm::errs());
  llvm::errs() << "========\n";
}

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

std::string TransformPass::getFPConstantStr(ExprRef e) const {
  ConstantFloatExprRef fpConstExpr = castAs<ConstantFloatExpr>(e);
  assert(fpConstExpr->bits() == 32 || fpConstExpr->bits() == 64);
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  llvm::APFloat apf = fpConstExpr->value();

  if (fpConstExpr->bits() == 64){
    ss << "(" << apf.convertToDouble() << ")";
  }else{
    ss << "(" << apf.convertToFloat() << ")";
  }
  ss.flush();
  return underlyingString;
}

std::string TransformPass::getFreshSymbol() const {
  // TODO: Do something more sophisticatd
  static uint64_t counter = 0;
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  ss << "ssa_" << counter;
  ss.flush();
  ++counter;
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

ExprRef TransformPass::convertToBV(ExprRef e){
//  if (isFPType(e)){
//    ref<FPToSIExpr> convertExpr = FPToSIExpr::create(e, e->bits());
//    visitConvertToSignedBitVectorFromFloat(convertExpr);
//    return convertExpr;
//  }
  return e;
}

ExprRef TransformPass::convertToFP(ExprRef e){
//  if (!isFPType(e)){
//    ref<SIToFPExpr> convertExpr = SIToFPExpr::create(e, e->bits());
//    visitConvertToFloatFromSignedBitVector(convertExpr);
//    return convertExpr;
//  }
  return e;
}

void TransformPass::visitConstant(ExprRef e) {
  auto it = constToSymbolName.find(e->toString());
  if (it != constToSymbolName.end()) {
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
  else if (e->kind() == qsym::Float){
    exprToSymbolName.insert(std::make_pair(e, getFPConstantStr(e)));
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
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  ss << getSymbolFor(re);
  ss.flush();
  insertSSAStmt(e, ss.str());
}

void TransformPass::visitEqual(ExprRef e) {
  auto arg0 = convertToBV(e->getChild(0));
  auto arg1 = convertToBV(e->getChild(1));
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
      auto arg0 = convertToBV(e->getChild(firstArgIndex));
      auto arg1 = convertToBV(e->getChild(secondArgIndex));
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
  auto condition = convertToBV(e->getChild(0));
  auto trueExpr  = convertToBV(e->getChild(1));
  auto falseExpr = convertToBV(e->getChild(2));
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  ss << "(" << getSymbolFor(condition) << ")?(" << getSymbolFor(trueExpr)
     << "):(" << getSymbolFor(falseExpr) << ")";
  insertSSAStmt(e, ss.str());
}

void TransformPass::visitBvNot(ExprRef e) {
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  auto arg0 = convertToBV(e->getChild(0));
  ss << "!(" << getSymbolFor(arg0) << ")";
  insertSSAStmt(e, ss.str());
}

void TransformPass::visitBvNeg(ExprRef e) {
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  auto arg0 = convertToBV(e->getChild(0));
  ss << "-(" << getSymbolFor(arg0) << ")";
  insertSSAStmt(e, ss.str());
}

// Convenience macro to avoid writing lots of duplicate code
#define BV_BIN_OP(NAME, CALL_NAME)                                              \
  void TransformPass::NAME(ExprRef e) {                                       \
    auto arg0 = convertToBV(e->getChild(0));                                      \
    auto arg1 = convertToBV(e->getChild(1));                                      \
    std::string underlyingString;                                               \
    llvm::raw_string_ostream ss(underlyingString);                              \
    ss << getSymbolFor(arg0) << "." #CALL_NAME "("                              \
       << getSymbolFor(arg1)<< ")";                                             \
    insertSSAStmt(e, ss.str());                                                 \
  }

#define BV_NARY_OP(NAME, CALL_NAME)                                            \
  void TransformPass::NAME(ExprRef e) {                                      \
    const unsigned numArgs = e->num_children();                                  \
    std::string underlyingString;                                              \
    llvm::raw_string_ostream ss(underlyingString);                             \
    auto arg0 = convertToBV(e->getChild(0));                                     \
    /* Correct number of opening braces*/                                      \
    for (unsigned index = 2; index < numArgs; ++index) {                       \
      ss << "(";                                                               \
    }                                                                          \
    for (unsigned index = 1; index < numArgs; ++index) {                       \
      if (index == 1) {                                                        \
        ss << getSymbolFor(arg0);                                              \
      }                                                                        \
      auto argN = convertToBV(e->getChild(index));                               \
      if (index > 1) {                                                         \
        /* Closing brace for previous operation */                             \
        ss << ")";                                                             \
      }                                                                        \
      ss << " " #CALL_NAME " " << getSymbolFor(argN);                          \
    }                                                                          \
    insertSSAStmt(e, ss.str());                                                \
  }

BV_BIN_OP(visitBvAdd, bvadd)
BV_NARY_OP(visitBvMul, bvmul)
BV_BIN_OP(visitBvSub, bvsub)
BV_BIN_OP(visitBvSDiv, bvsdiv)
BV_BIN_OP(visitBvUDiv, bvudiv)
BV_BIN_OP(visitBvSRem, bvsrem)
BV_BIN_OP(visitBvURem, bvurem)
BV_BIN_OP(visitBvULE, bvule)
BV_BIN_OP(visitBvSLE, bvsle)
BV_BIN_OP(visitBvUGE, bvuge)
BV_BIN_OP(visitBvSGE, bvsge)
BV_BIN_OP(visitBvULT, bvult)
BV_BIN_OP(visitBvSLT, bvslt)
BV_BIN_OP(visitBvUGT, bvugt)
BV_BIN_OP(visitBvSGT, bvsgt)
BV_BIN_OP(visitBvShl, bvshl)
BV_BIN_OP(visitBvLShr, bvlshr)
BV_BIN_OP(visitBvAShr, bvashr)

// Bitvector NAry operations. Even though in SMT-LIBv2 these ops are binary Z3
// allows n-ary versions which could be introduced by its simplication steps.
// We assume these operations are associative so it doesn't matter the order we
// apply them in.
BV_NARY_OP(visitBvOr, bvor)
BV_NARY_OP(visitBvAnd, bvand)
BV_NARY_OP(visitBvXor, bvxor)

#undef BV_BIN_OP
#undef BV_NARY_OP

void TransformPass::visitBvConcat(ExprRef e) {
  const unsigned numArgs = e->num_children();
  assert(numArgs >= 2);
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  auto arg0 = convertToBV(e->getChild(0));

  // Correct number of opening braces
  for (unsigned index = 2; index < numArgs; ++index) {
    ss << "(";
  }

  for (unsigned index = 1; index < numArgs; ++index) {
    if (index == 1) {
      ss << getSymbolFor(arg0);
    }
    auto argN = convertToBV(e->getChild(index));
    if (index > 1) {
      // Closing brace for previous concat
      ss << ")";
    }
    ss << ".concat(" << getSymbolFor(argN) << ")";
  }
  insertSSAStmt(e, ss.str());
}

void TransformPass::visitBvSignExtend(ExprRef e) {
  // The extension amount is not an argument
  assert(e->num_children() == 1);
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  auto arg0 = convertToBV(e->getChild(0));

  // Get the extension count. This is a paramter on the function
  // declaration rather an argument in the application
  int numberOfNewBits = e->bits() - arg0->bits();

  ss << getSymbolFor(arg0) << ".signExtend<" << numberOfNewBits << ">()";
  insertSSAStmt(e, ss.str());
}

void TransformPass::visitBvZeroExtend(ExprRef e) {
  // The extension amount is not an argument
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  auto arg0 = convertToBV(e->getChild(0));

  // Get the extension count. This is a paramter on the function
  // declaration rather an argument in the application
  int numberOfNewBits = e->bits() - arg0->bits();

  ss << getSymbolFor(arg0) << ".zeroExtend<" << numberOfNewBits << ">()";
  insertSSAStmt(e, ss.str());
}

void TransformPass::visitBvExtract(ExprRef e) {
  // The bit indices are not arguments
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);

  std::shared_ptr<ExtractExpr> EE = castAs<ExtractExpr>(e);
  auto arg0 = convertToBV(e->getChild(0));
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

    ss << getSymbolFor(arg0) << ".extract<" << width << ">("
       << highBit << "," << lowBit << ")";
  }
  insertSSAStmt(e, ss.str());
}

// Floating point
#define FP_UNARY_OP(NAME, CALL_NAME)                                            \
  void TransformPass::NAME(ExprRef e) {                                         \
    auto arg = convertToFP(e->getChild(0));                                     \
    std::string underlyingString;                                               \
    llvm::raw_string_ostream ss(underlyingString);                              \
    ss << getSymbolFor(arg) << "." #CALL_NAME "()";                             \
    insertSSAStmt(e, ss.str());                                                 \
  }
//FP_UNARY_OP(visitFloatIsNaN, isNaN)
//FP_UNARY_OP(visitFloatIsNormal, isNormal)
//FP_UNARY_OP(visitFloatIsSubnormal, isSubnormal)
//FP_UNARY_OP(visitFloatIsZero, isZero)
//FP_UNARY_OP(visitFloatIsPositive, isPositive)
//FP_UNARY_OP(visitFloatIsNegative, isNegative)
//FP_UNARY_OP(visitFloatIsInfinite, isInfinite)
//FP_UNARY_OP(visitFloatNeg, neg)
FP_UNARY_OP(visitFloatAbs, abs)


#undef FP_UNARY_OP

#define FP_BIN_OP(NAME, CALL_NAME)                                              \
  void TransformPass::NAME(ExprRef e) {                                         \
    auto lhs = convertToFP(e->getChild(0));                                     \
    auto rhs = convertToFP(e->getChild(1));                                     \
    std::string underlyingString;                                               \
    llvm::raw_string_ostream ss(underlyingString);                              \
    ss << getSymbolFor(lhs) << "." #CALL_NAME "("                               \
       << getSymbolFor(rhs) << ")";                                             \
    insertSSAStmt(e, ss.str());                                                 \
  }

FP_BIN_OP(visitFloatIEEEEquals, ieeeEquals)
FP_BIN_OP(visitFloatLessThan, fplt)
FP_BIN_OP(visitFloatLessThanOrEqual, fpleq)
FP_BIN_OP(visitFloatGreaterThan, fpgt)
FP_BIN_OP(visitFloatGreaterThanOrEqual, fpgeq)
FP_BIN_OP(visitFloatRem, rem)
//FP_BIN_OP(visitFloatMin, min)
//FP_BIN_OP(visitFloatMax, max)

#undef FP_BIN_OP

#define FP_BIN_WITH_RM_OP(NAME, CALL_NAME)                                     \
  void TransformPass::NAME(ExprRef e) {                                        \
    auto lhs = convertToFP(e->getChild(0));                                    \
    auto rhs = convertToFP(e->getChild(1));                                    \
    std::string underlyingString;                                              \
    llvm::raw_string_ostream ss(underlyingString);                             \
    ss << getSymbolFor(lhs) << "." #CALL_NAME "(JFS_RM_RNE, "                  \
       << getSymbolFor(rhs) << ")";                                            \
    insertSSAStmt(e, ss.str());                                                \
  }
FP_BIN_WITH_RM_OP(visitFloatAdd, add)
FP_BIN_WITH_RM_OP(visitFloatSub, sub)
FP_BIN_WITH_RM_OP(visitFloatMul, mul)
FP_BIN_WITH_RM_OP(visitFloatDiv, div)
#undef FP_BIN_WITH_RM_OP


void TransformPass::visitConvertToFloatFromFloat(ExprRef e) {
  auto arg = e->getChild(0);

  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  if (e->bits() == 64)
    ss << getSymbolFor(arg) << ".convertToFloat<11,53>(JFS_RM_RNE)";
  else
    ss << getSymbolFor(arg) << ".convertToFloat<8,24>(JFS_RM_RNE)";
  insertSSAStmt(e, ss.str());
}

void TransformPass::visitConvertToFloatFromUnsignedBitVector(ExprRef e) {
  auto arg = e->getChild(0);
  std::string underlyingString;
  llvm::raw_string_ostream ss(underlyingString);
  auto cxxType = getOrInsertTy(e);
  ss << cxxType->getName() << "::convertFromUnsignedBV<"
     << e->bits()<< ">(JFS_RM_RNE, "
     << getSymbolFor(arg) << ")";
  insertSSAStmt(e, ss.str());
}

void TransformPass::visitConvertToFloatFromSignedBitVector(ExprRef e) {
  // has been converted before
  if (exprToSymbolName.find(e) != exprToSymbolName.end())
    return;

  auto arg = e->getChild(0);
  std::string underlyingString;
  auto cxxType = getOrInsertTy(e);
  llvm::raw_string_ostream ss(underlyingString);
  ss << cxxType->getName() << "::convertFromSignedBV<"
     << e->bits() << ">(JFS_RM_RNE, "
     << getSymbolFor(arg) << ")";
  insertSSAStmt(e, ss.str());
}

void TransformPass::visitConvertToIEEEBitVectorFromFloat(ExprRef e) {
  auto arg = e->getChild(0);
  std::string underlyingString;
  auto cxxType = getOrInsertTy(e);
  llvm::raw_string_ostream ss(underlyingString);
  ss << getSymbolFor(arg) << ".transferToBV<" << e->bits() << ">()";
  insertSSAStmt(e, ss.str());
}

void TransformPass::visitConvertToFloatFromIEEEBitVector(ExprRef e) {
  auto arg = e->getChild(0);
  std::string underlyingString;
  auto cxxType = getOrInsertTy(e);
  llvm::raw_string_ostream ss(underlyingString);
  ss << getSymbolFor(arg) << ".transferFromBV<" << e->bits() << ">()";
  insertSSAStmt(e, ss.str());
}


#define FP_CONVERT_TO_BV_OP(NAME, CALL_NAME)                                    \
  void TransformPass::NAME(ExprRef e) {                                       \
    if (exprToSymbolName.find(e) != exprToSymbolName.end())                     \
        return;                                                                 \
    auto arg = e->getChild(0);                                                    \
    std::string underlyingString;                                               \
    llvm::raw_string_ostream ss(underlyingString);                              \
    ss << getSymbolFor(arg) << "." #CALL_NAME "<"                               \
       << e->bits() << ">(JFS_RM_RTZ)";                                     \
    insertSSAStmt(e, ss.str());                                                 \
  }
FP_CONVERT_TO_BV_OP(visitConvertToUnsignedBitVectorFromFloat, convertToUnsignedBV)
FP_CONVERT_TO_BV_OP(visitConvertToSignedBitVectorFromFloat, convertToSignedBV)
#undef FP_CONVERT_TO_BV_OP
}