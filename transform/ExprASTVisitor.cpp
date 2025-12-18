#include "ExprASTVisitor.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/Compiler.h"

using namespace qsym;
namespace PCT {

ExprASTVisitor::ExprASTVisitor() {}
ExprASTVisitor::~ExprASTVisitor() {}

// Macro to avoid accidental drop through and typos
#define ACTION(X)                                                              \
  {                                                                            \
    X;                                                                         \
    return;                                                                    \
  }
// Dispatch to appropriate visitor method
void ExprASTVisitor::visit(ExprRef e) {
  //printf("[zgf dbg] e : %s\n",e->toStr().c_str());
  switch (e->kind()) {
  case qsym::Kind::Bool:
  case qsym::Kind::Constant:
  case qsym::Kind::Float:
    ACTION(visitConstant(e))

  case qsym::Kind::Read:
    ACTION(visitRead(e))
  case qsym::Kind::Concat:
    ACTION(visitBvConcat(e))
  case qsym::Kind::Extract:
    ACTION(visitBvExtract(e))
  case qsym::Kind::ZExt:
    ACTION(visitBvZeroExtend(e))
  case qsym::Kind::SExt:
    ACTION(visitBvSignExtend(e))

  // Arithmetic
  case qsym::Kind::Add:
    ACTION(visitBvAdd(e))
  case qsym::Kind::Sub:
    ACTION(visitBvSub(e))
  case qsym::Kind::Mul:
    ACTION(visitBvMul(e))
  case qsym::Kind::SDiv:
    ACTION(visitBvSDiv(e))
  case qsym::Kind::UDiv:
    ACTION(visitBvUDiv(e))
  case qsym::Kind::SRem:
    ACTION(visitBvSRem(e))
  case qsym::Kind::URem:
    ACTION(visitBvURem(e))
  case qsym::Kind::Neg:
    ACTION(visitBvNeg(e))

  // Bit
  case qsym::Kind::Not: case qsym::Kind::LNot:
    ACTION(visitBvNot(e))
  case qsym::Kind::And: case qsym::Kind::LAnd:
    ACTION(visitBvAnd(e))
  case qsym::Kind::Or:  case qsym::Kind::LOr:
    ACTION(visitBvOr(e))
  case qsym::Kind::Xor:
    ACTION(visitBvXor(e))
  case qsym::Kind::Shl:
    ACTION(visitBvShl(e))
  case qsym::Kind::LShr:
    ACTION(visitBvLShr(e))
  case qsym::Kind::AShr:
    ACTION(visitBvAShr(e))

  // Compare
  case qsym::Kind::Equal:
    ACTION(visitEqual(e))
  case qsym::Kind::Distinct:
    ACTION(visitDistinct(e))
  case qsym::Kind::Ule:
    ACTION(visitBvULE(e))
  case qsym::Kind::Sle:
    ACTION(visitBvSLE(e))
  case qsym::Kind::Uge:
    ACTION(visitBvUGE(e))
  case qsym::Kind::Sge:
    ACTION(visitBvSGE(e))
  case qsym::Kind::Ult:
    ACTION(visitBvULT(e))
  case qsym::Kind::Slt:
    ACTION(visitBvSLT(e))
  case qsym::Kind::Ugt:
    ACTION(visitBvUGT(e))
  case qsym::Kind::Sgt:
    ACTION(visitBvSGT(e))

  // Special
  case qsym::Kind::Ite:
    ACTION(visitIfThenElse(e))

  // Floating point operations
  case qsym::Kind::FAdd:
    ACTION(visitFloatAdd(e))
  case qsym::Kind::FSub:
    ACTION(visitFloatSub(e))
  case qsym::Kind::FMul:
    ACTION(visitFloatMul(e))
  case qsym::Kind::FDiv:
    ACTION(visitFloatDiv(e))
  case qsym::Kind::FRem:
    ACTION(visitFloatRem(e))
  case qsym::Kind::FAbs:
    ACTION(visitFloatAbs(e))

  case qsym::Kind::FOeq: case qsym::Kind::FUeq:
    ACTION(visitFloatIEEEEquals(e))
  case qsym::Kind::FOlt: case qsym::Kind::FUlt:
    ACTION(visitFloatLessThan(e))
  case qsym::Kind::FOle: case qsym::Kind::FUle:
    ACTION(visitFloatLessThanOrEqual(e))
  case qsym::Kind::FOgt: case qsym::Kind::FUgt:
    ACTION(visitFloatGreaterThan(e))
  case qsym::Kind::FOge: case qsym::Kind::FUge:
    ACTION(visitFloatGreaterThanOrEqual(e))

  case qsym::Kind::FPToFP:
    ACTION(visitConvertToFloatFromFloat(e))
  case qsym::Kind::FPToBV:
    ACTION(visitConvertToIEEEBitVectorFromFloat(e))
  case qsym::Kind::BVToFP:
    ACTION(visitConvertToFloatFromIEEEBitVector(e))
  case qsym::Kind::FPToUI:
    ACTION(visitConvertToUnsignedBitVectorFromFloat(e))
  case qsym::Kind::FPToSI:
    ACTION(visitConvertToSignedBitVectorFromFloat(e))
  case qsym::Kind::UIToFP:
    ACTION(visitConvertToFloatFromUnsignedBitVector(e))
  case qsym::Kind::SIToFP:
    ACTION(visitConvertToFloatFromSignedBitVector(e))

  default:
    llvm_unreachable("unsupported kind");
  }
#undef ACTION
}
}
