#ifndef PCT_TRANSFORM_PASS_H
#define PCT_TRANSFORM_PASS_H
#include <map>
#include <unordered_set>
#include <utility>

#include <llvm/Support/raw_ostream.h>

#include "CXXProgram.h"
#include "ExprASTVisitor.h"
#include "BinaryTree.h"

namespace PCT {

class TransformPass : public ExprASTVisitor {
public:
  TransformPass();

  bool buildEvaluator(ExecutionTree *executionTree,
                      std::vector<TreeNode *> *deadNodes);
  bool buildEvaluator(ExecutionTree *executionTree,
                      std::vector<DeadZone> *deadZones);
  void dumpEvaluator(const std::string &path);

  std::shared_ptr<CXXProgram> program;

private:
  CXXCodeBlockRef earlyExitBlock;
  CXXCodeBlockRef entryPointMainBlock;

  uint64_t counter = 0;
  std::map<ExprRef, std::string> exprToSymbolName; // References strings in `usedSymbols`.
  std::unordered_set<std::string> usedSymbols;
  llvm::StringRef entryPointFirstArgName;
  llvm::StringRef entryPointSecondArgName;
  CXXCodeBlockRef getCurrentBlock() { return entryPointMainBlock; }

  // Helpers for inserting SSA variables and types
  bool isBVType(ExprRef e) const {
    qsym::Kind k = e->kind();
    bool res = (qsym::Kind::Constant <= k && k <= qsym::Kind::AShr);
    return res;
  }
  bool isBoolType(ExprRef e) const {
    qsym::Kind k = e->kind();
    bool res = (qsym::Kind::Bool == k) ||
               (qsym::Kind::Equal <= k && k <= qsym::Kind::LNot);
    return res;
  }

  bool isSigned(ExprRef e) const {
    qsym::Kind k = e->kind();
    bool res = false;
    switch (k) {
      case qsym::Kind::SExt: case qsym::Kind::SDiv: case qsym::Kind::SRem:
      case qsym::Kind::AShr: case qsym::Kind::Slt: case qsym::Kind::Sle:
      case qsym::Kind::Sgt:  case qsym::Kind::Sge:
        res = true;
      default: break;
    }
    return res;
  }

  std::set<uint32_t> findReadIdx(ExprRef e);
  std::vector<uint8_t> readInput(std::string input_file, uint32_t N);
  std::vector<uint8_t> validInput(ExecutionTree * executionTree, TreeNode *leafNode);


  CXXTypeRef getOrInsertTy(ExprRef expr);
  CXXTypeRef getBVTy(uint32_t bits, bool isSign = false);
  std::string getSanitizedVariableName(const std::string& name);
  llvm::StringRef insertSymbol(const std::string& symbolName);
  llvm::StringRef insertSSASymbolForExpr(ExprRef e, const std::string& symbolName);

  // Function for building various parts of the CXXProgram
  CXXFunctionDeclRef buildEntryPoint();
  void insertHeaderIncludes();
  void insertBufferSizeGuard(CXXCodeBlockRef cb, uint32_t byteWidth);

  void insertBranchForConstraint(ExprRef constraint);
  void insertFuzzingTarget(CXXCodeBlockRef cb);

  // Visitor and ConstantAssignment helper methods
  std::string getBoolConstantStr(ExprRef e) const;
  std::string getBVConstantStr(ExprRef e) const;
  std::string getFreshSymbol();
  void insertSSAStmt(ExprRef e, llvm::StringRef expr,
                     llvm::StringRef preferredSymbolName);

  void insertSSAStmt(ExprRef e, llvm::StringRef expr) {
    insertSSAStmt(e, expr, llvm::StringRef());
  }
  void insertVoidStmt(ExprRef e, llvm::StringRef expr);

  void doDFSPostOrderTraversal(ExprRef e);
  bool hasBeenVisited(ExprRef e) const;
  llvm::StringRef getSymbolFor(ExprRef e);


  // Constants
  void visitConstant(ExprRef e)     override;
  void visitRead(ExprRef e)         override;
  void visitBvExtract(ExprRef e)    override;
  void visitBvConcat(ExprRef e)     override;
  void visitBvSignExtend(ExprRef e) override;
  void visitBvZeroExtend(ExprRef e) override;

  // Arithmetic BitVector operations
  void visitBvNot(ExprRef e)  override;
  void visitBvAdd(ExprRef e)  override;
  void visitBvSub(ExprRef e)  override;
  void visitBvMul(ExprRef e)  override;
  void visitBvSDiv(ExprRef e) override;
  void visitBvUDiv(ExprRef e) override;
  void visitBvSRem(ExprRef e) override;
  void visitBvURem(ExprRef e) override;
  void visitBvNeg(ExprRef e)  override;

  // Overloaded operations
  void visitEqual(ExprRef e)      override;
  void visitDistinct(ExprRef e)   override;
  void visitIfThenElse(ExprRef e) override;

  // Comparison BitVector operations
  void visitBvULE(ExprRef e) override;
  void visitBvSLE(ExprRef e) override;
  void visitBvUGE(ExprRef e) override;
  void visitBvSGE(ExprRef e) override;
  void visitBvULT(ExprRef e) override;
  void visitBvSLT(ExprRef e) override;
  void visitBvUGT(ExprRef e) override;
  void visitBvSGT(ExprRef e) override;

  // Bitwise BitVector operations
  void visitBvAnd(ExprRef e)  override;
  void visitBvOr(ExprRef e)   override;
  void visitBvXor(ExprRef e)  override;
  void visitBvShl(ExprRef e)  override;
  void visitBvLShr(ExprRef e) override;
  void visitBvAShr(ExprRef e) override;

  // Floating point
//  void visitFloatIEEEEquals(ExprRef e)         override;
//  void visitFloatLessThan(ExprRef e)           override;
//  void visitFloatLessThanOrEqual(ExprRef e)    override;
//  void visitFloatGreaterThan(ExprRef e)        override;
//  void visitFloatGreaterThanOrEqual(ExprRef e) override;
//
//  void visitFloatAdd(ExprRef e) override;
//  void visitFloatSub(ExprRef e) override;
//  void visitFloatMul(ExprRef e) override;
//  void visitFloatDiv(ExprRef e) override;
//  void visitFloatRem(ExprRef e) override;
//  void visitFloatAbs(ExprRef e) override;
//
//  void visitConvertToFloatFromFloat(ExprRef e) override;
//  void visitConvertToIEEEBitVectorFromFloat(ExprRef e) override;
//  void visitConvertToFloatFromIEEEBitVector(ExprRef e) override;
//  void visitConvertToFloatFromUnsignedBitVector(ExprRef e) override;
//  void visitConvertToFloatFromSignedBitVector(ExprRef e) override;
//  void visitConvertToUnsignedBitVectorFromFloat(ExprRef e) override;
//  void visitConvertToSignedBitVectorFromFloat(ExprRef e) override;

  /*void visitFloatNeg(ExprRef e) override;
  void visitFloatMin(ExprRef e) override;
  void visitFloatMax(ExprRef e) override;
  void visitFloatSqrt(ExprRef e) override;
  void visitFloatIsNaN(ExprRef e) override;
  void visitFloatIsNormal(ExprRef e) override;
  void visitFloatIsSubnormal(ExprRef e) override;
  void visitFloatIsZero(ExprRef e) override;
  void visitFloatIsPositive(ExprRef e) override;
  void visitFloatIsNegative(ExprRef e) override;
  void visitFloatIsInfinite(ExprRef e) override;*/
};
}
#endif
