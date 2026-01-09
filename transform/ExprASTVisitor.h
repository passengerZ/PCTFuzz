#ifndef PCT_EXPR_AST_VISITOR_H
#define PCT_EXPR_AST_VISITOR_H

#include "expr.h"

using namespace qsym;
namespace PCT {

// FIXME: This design only works for
// read only traversal. It needs rethinking
// for Z3AST modification and traversal order
class ExprASTVisitor {
public:
  ExprASTVisitor();
  virtual ~ExprASTVisitor();
  void visit(ExprRef e);

protected:
  // TODO: Add more methods for different Z3 application kinds
  
  // Constants
  virtual void visitConstant(ExprRef e) = 0;
  virtual void visitRead(ExprRef e) = 0;
  virtual void visitBvExtract(ExprRef e) = 0;
  virtual void visitBvConcat(ExprRef e) = 0;
  virtual void visitBvSignExtend(ExprRef e) = 0;
  virtual void visitBvZeroExtend(ExprRef e) = 0;

  // Arithmetic BitVector operations
  virtual void visitBvNot(ExprRef e) = 0;
  virtual void visitBvAdd(ExprRef e) = 0;
  virtual void visitBvSub(ExprRef e) = 0;
  virtual void visitBvMul(ExprRef e) = 0;
  virtual void visitBvSDiv(ExprRef e) = 0;
  virtual void visitBvUDiv(ExprRef e) = 0;
  virtual void visitBvSRem(ExprRef e) = 0;
  virtual void visitBvURem(ExprRef e) = 0;
  virtual void visitBvNeg(ExprRef e) = 0;

  // Bitwise BitVector operations
  virtual void visitBvAnd(ExprRef e) = 0;
  virtual void visitBvOr(ExprRef e) = 0;
  virtual void visitBvXor(ExprRef e) = 0;
  virtual void visitBvShl(ExprRef e) = 0;
  virtual void visitBvLShr(ExprRef e) = 0;
  virtual void visitBvAShr(ExprRef e) = 0;

  // Overloaded operations
  virtual void visitEqual(ExprRef e) = 0;
  virtual void visitDistinct(ExprRef e) = 0;
  // Comparison BitVector operations
  virtual void visitBvULE(ExprRef e) = 0;
  virtual void visitBvSLE(ExprRef e) = 0;
  virtual void visitBvUGE(ExprRef e) = 0;
  virtual void visitBvSGE(ExprRef e) = 0;
  virtual void visitBvULT(ExprRef e) = 0;
  virtual void visitBvSLT(ExprRef e) = 0;
  virtual void visitBvUGT(ExprRef e) = 0;
  virtual void visitBvSGT(ExprRef e) = 0;

  // Logical
  virtual void visitIfThenElse(ExprRef e) = 0;

  // Floating point operations
//  virtual void visitFloatIEEEEquals(ExprRef e) = 0;
//  virtual void visitFloatLessThan(ExprRef e) = 0;
//  virtual void visitFloatLessThanOrEqual(ExprRef e) = 0;
//  virtual void visitFloatGreaterThan(ExprRef e) = 0;
//  virtual void visitFloatGreaterThanOrEqual(ExprRef e) = 0;
//
//  virtual void visitFloatAbs(ExprRef e) = 0;
//  virtual void visitFloatAdd(ExprRef e) = 0;
//  virtual void visitFloatSub(ExprRef e) = 0;
//  virtual void visitFloatMul(ExprRef e) = 0;
//  virtual void visitFloatDiv(ExprRef e) = 0;
//  virtual void visitFloatRem(ExprRef e) = 0;
//
//  virtual void visitConvertToFloatFromFloat(ExprRef e) = 0;
//  virtual void visitConvertToIEEEBitVectorFromFloat(ExprRef e) = 0;
//  virtual void visitConvertToFloatFromIEEEBitVector(ExprRef e) = 0;
//  virtual void visitConvertToFloatFromUnsignedBitVector(ExprRef e) = 0;
//  virtual void visitConvertToFloatFromSignedBitVector(ExprRef e) = 0;
//  virtual void visitConvertToUnsignedBitVectorFromFloat(ExprRef e) = 0;
//  virtual void visitConvertToSignedBitVectorFromFloat(ExprRef e) = 0;

  /*
  virtual void visitFloatNeg(ExprRef e) = 0;
  virtual void visitFloatMin(ExprRef e) = 0;
  virtual void visitFloatMax(ExprRef e) = 0;
  virtual void visitFloatSqrt(ExprRef e) = 0;
  virtual void visitFloatIsNaN(ExprRef e) = 0;
  virtual void visitFloatIsNormal(ExprRef e) = 0;
  virtual void visitFloatIsSubnormal(ExprRef e) = 0;
  virtual void visitFloatIsZero(ExprRef e) = 0;
  virtual void visitFloatIsPositive(ExprRef e) = 0;
  virtual void visitFloatIsNegative(ExprRef e) = 0;
  virtual void visitFloatIsInfinite(ExprRef e) = 0;
   */
};
}
#endif
