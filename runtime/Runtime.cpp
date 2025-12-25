// This file is part of the SymCC runtime.
//
// The SymCC runtime is free software: you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// The SymCC runtime is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with SymCC. If not, see <https://www.gnu.org/licenses/>.

//
// Definitions that we need for the QSYM backend
//

// C++
#if __has_include(<filesystem>)
#define HAVE_FILESYSTEM 1
#elif __has_include(<experimental/filesystem>)
#define HAVE_FILESYSTEM 0
#else
#error "We need either <filesystem> or the older <experimental/filesystem>."
#endif

#include <atomic>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <unordered_set>
#include <variant>

#if HAVE_FILESYSTEM
#include <filesystem>
#else
#include <experimental/filesystem>
#endif

#ifdef DEBUG_RUNTIME
#include <chrono>
#endif

// C
#include <cstdint>
#include <cstdio>

// QSYM
#include <afl_trace_map.h>
#include <call_stack_manager.h>
#include <expr_builder.h>
#include <solver.h>

// LLVM
#include <llvm/ADT/APInt.h>
#include <llvm/ADT/ArrayRef.h>

// Runtime
#include "Config.h"
#include "LibcWrappers.h"
#include "Shadow.h"
#include "GarbageCollection.h"
#include "Runtime.h"

// Protobuf
#include "qsymExpr.pb.h"

namespace qsym {

ExprBuilder *g_expr_builder;
Solver *g_solver;
CallStackManager g_call_stack_manager;
z3::context *g_z3_context;

} // namespace qsym

using namespace pct;

namespace {

/// Indicate whether the runtime has been initialized.
std::atomic_flag g_initialized = ATOMIC_FLAG_INIT;

/// A mapping of all expressions that we have ever received from QSYM to the
/// corresponding shared pointers on the heap.
///
/// We can't expect C clients to handle std::shared_ptr, so we maintain a single
/// copy per expression in order to keep the expression alive. The garbage
/// collector decides when to release our shared pointer.
///
/// std::map seems to perform slightly better than std::unordered_map on our
/// workload.
std::map<SymExpr, qsym::ExprRef> allocatedExpressions;

std::vector<BranchNode> branchConstaints;
std::map<UINT32, SymbolicExpr> cached;

SymExpr registerExpression(const qsym::ExprRef &expr) {
  SymExpr rawExpr = expr.get();

  if (allocatedExpressions.count(rawExpr) == 0) {
    // We don't know this expression yet. Create a copy of the shared pointer to
    // keep the expression alive.
    allocatedExpressions[rawExpr] = expr;
  }

  return rawExpr;
}

/// The user-provided test case handler, if any.
///
/// If the user doesn't register a handler, we use QSYM's default behavior of
/// writing the test case to a file in the output directory.
TestCaseHandler g_test_case_handler = nullptr;

/// A QSYM solver that doesn't require the entire input on initialization.
class EnhancedQsymSolver : public qsym::Solver {
  // Warning!
  //
  // Before we can override methods of qsym::Solver, we need to declare them
  // virtual because the QSYM code refers to the solver with a pointer of type
  // qsym::Solver*; for non-virtual methods, it will always choose the
  // implementation of the base class. Beware that making a method virtual adds
  // a small performance overhead and requires us to change QSYM code.
  //
  // Subclassing the QSYM solver is ugly but helps us to avoid making too many
  // changes in the QSYM codebase.

public:
  EnhancedQsymSolver()
      : qsym::Solver("/dev/null", g_config.outputDir, g_config.aflCoverageMap) {
  }

  void pushInputByte(size_t offset, uint8_t value) {
    if (inputs_.size() <= offset)
      inputs_.resize(offset + 1);

    inputs_[offset] = value;
  }

  void saveValues(const std::string &suffix) override {
    if (auto handler = g_test_case_handler) {
      auto values = getConcreteValues();
      // The test-case handler may be instrumented, so let's call it with
      // argument expressions to meet instrumented code's expectations.
      // Otherwise, we might end up erroneously using whatever expression was
      // last registered for a function parameter.
      _sym_set_parameter_expression(0, nullptr);
      _sym_set_parameter_expression(1, nullptr);
      handler(values.data(), values.size());
    } else {
      Solver::saveValues(suffix);
    }
  }
};

EnhancedQsymSolver *g_enhanced_solver;

} // namespace

using namespace qsym;

#if HAVE_FILESYSTEM
namespace fs = std::filesystem;
#else
namespace fs = std::experimental::filesystem;
#endif

void _sym_initialize(void) {
  if (g_initialized.test_and_set())
    return;

  loadConfig();
  initLibcWrappers();
  std::cerr << "This is SymCC running with the QSYM backend" << std::endl;
  if (std::holds_alternative<NoInput>(g_config.input)) {
    std::cerr
        << "Performing fully concrete execution (i.e., without symbolic input)"
        << std::endl;
    return;
  }

  // Check the output directory
  if (!fs::exists(g_config.outputDir) ||
      !fs::is_directory(g_config.outputDir)) {
    std::cerr << "Error: the output directory " << g_config.outputDir
              << " (configurable via SYMCC_OUTPUT_DIR) does not exist."
              << std::endl;
    exit(-1);
  }

  g_z3_context = new z3::context{};
  g_enhanced_solver = new EnhancedQsymSolver{};
  g_solver = g_enhanced_solver; // for QSYM-internal use
  g_expr_builder = SymbolicExprBuilder::create();
}

SymExpr _sym_build_integer(uint64_t value, uint8_t bits) {
  // QSYM's API takes uintptr_t, so we need to be careful when compiling for
  // 32-bit systems: the compiler would helpfully truncate our uint64_t to fit
  // into 32 bits.
  if constexpr (sizeof(uint64_t) == sizeof(uintptr_t)) {
    // 64-bit case: all good.
    return registerExpression(g_expr_builder->createConstant(value, bits));
  } else {
    // 32-bit case: use the regular API if possible, otherwise create an
    // llvm::APInt.
    if (uintptr_t value32 = value; value32 == value)
      return registerExpression(g_expr_builder->createConstant(value32, bits));

    return registerExpression(
        g_expr_builder->createConstant({64, value}, bits));
  }
}

SymExpr _sym_build_integer128(uint64_t high, uint64_t low) {
  std::array<uint64_t, 2> words = {low, high};
  return registerExpression(g_expr_builder->createConstant({128, words}, 128));
}

SymExpr _sym_build_integer_from_buffer(void *buffer, unsigned num_bits) {
  assert(num_bits % 64 == 0);
  return registerExpression(g_expr_builder->createConstant(
      {num_bits, num_bits / 64, (uint64_t *)buffer}, num_bits));
}

SymExpr _sym_build_null_pointer() {
  return registerExpression(
      g_expr_builder->createConstant(0, sizeof(uintptr_t) * 8));
}

SymExpr _sym_build_true() {
  return registerExpression(g_expr_builder->createTrue());
}

SymExpr _sym_build_false() {
  return registerExpression(g_expr_builder->createFalse());
}

SymExpr _sym_build_bool(bool value) {
  return registerExpression(g_expr_builder->createBool(value));
}

#define DEF_BINARY_EXPR_BUILDER(name, qsymName)                                \
  SymExpr _sym_build_##name(SymExpr a, SymExpr b) {                            \
    return registerExpression(g_expr_builder->create##qsymName(                \
        allocatedExpressions.at(a), allocatedExpressions.at(b)));              \
  }

DEF_BINARY_EXPR_BUILDER(add, Add)
DEF_BINARY_EXPR_BUILDER(sub, Sub)
DEF_BINARY_EXPR_BUILDER(mul, Mul)
DEF_BINARY_EXPR_BUILDER(unsigned_div, UDiv)
DEF_BINARY_EXPR_BUILDER(signed_div, SDiv)
DEF_BINARY_EXPR_BUILDER(unsigned_rem, URem)
DEF_BINARY_EXPR_BUILDER(signed_rem, SRem)

DEF_BINARY_EXPR_BUILDER(shift_left, Shl)
DEF_BINARY_EXPR_BUILDER(logical_shift_right, LShr)
DEF_BINARY_EXPR_BUILDER(arithmetic_shift_right, AShr)

DEF_BINARY_EXPR_BUILDER(signed_less_than, Slt)
DEF_BINARY_EXPR_BUILDER(signed_less_equal, Sle)
DEF_BINARY_EXPR_BUILDER(signed_greater_than, Sgt)
DEF_BINARY_EXPR_BUILDER(signed_greater_equal, Sge)
DEF_BINARY_EXPR_BUILDER(unsigned_less_than, Ult)
DEF_BINARY_EXPR_BUILDER(unsigned_less_equal, Ule)
DEF_BINARY_EXPR_BUILDER(unsigned_greater_than, Ugt)
DEF_BINARY_EXPR_BUILDER(unsigned_greater_equal, Uge)
DEF_BINARY_EXPR_BUILDER(equal, Equal)
DEF_BINARY_EXPR_BUILDER(not_equal, Distinct)

DEF_BINARY_EXPR_BUILDER(bool_and, LAnd)
DEF_BINARY_EXPR_BUILDER(and, And)
DEF_BINARY_EXPR_BUILDER(bool_or, LOr)
DEF_BINARY_EXPR_BUILDER(or, Or)
DEF_BINARY_EXPR_BUILDER(bool_xor, Distinct)
DEF_BINARY_EXPR_BUILDER(xor, Xor)

DEF_BINARY_EXPR_BUILDER(fp_add, FAdd)
DEF_BINARY_EXPR_BUILDER(fp_sub, FSub)
DEF_BINARY_EXPR_BUILDER(fp_mul, FMul)
DEF_BINARY_EXPR_BUILDER(fp_div, FDiv)
DEF_BINARY_EXPR_BUILDER(fp_rem, FRem)

DEF_BINARY_EXPR_BUILDER(float_ordered_greater_than, FOgt)
DEF_BINARY_EXPR_BUILDER(float_ordered_greater_equal, FOge)
DEF_BINARY_EXPR_BUILDER(float_ordered_less_than, FOlt)
DEF_BINARY_EXPR_BUILDER(float_ordered_less_equal, FOle)
DEF_BINARY_EXPR_BUILDER(float_ordered_equal, FOeq)
DEF_BINARY_EXPR_BUILDER(float_ordered_not_equal, FOne)
DEF_BINARY_EXPR_BUILDER(float_ordered, FOrd)
DEF_BINARY_EXPR_BUILDER(float_unordered, FUno)
DEF_BINARY_EXPR_BUILDER(float_unordered_greater_than, FUgt)
DEF_BINARY_EXPR_BUILDER(float_unordered_greater_equal, FUge)
DEF_BINARY_EXPR_BUILDER(float_unordered_less_than, FUlt)
DEF_BINARY_EXPR_BUILDER(float_unordered_less_equal, FUle)
DEF_BINARY_EXPR_BUILDER(float_unordered_equal, FUeq)
DEF_BINARY_EXPR_BUILDER(float_unordered_not_equal, FUne)
#undef DEF_BINARY_EXPR_BUILDER

SymExpr _sym_build_neg(SymExpr expr) {
  return registerExpression(
      g_expr_builder->createNeg(allocatedExpressions.at(expr)));
}

SymExpr _sym_build_not(SymExpr expr) {
  return registerExpression(
      g_expr_builder->createNot(allocatedExpressions.at(expr)));
}

SymExpr _sym_build_ite(SymExpr cond, SymExpr a, SymExpr b) {
  return registerExpression(g_expr_builder->createIte(
      allocatedExpressions.at(cond), allocatedExpressions.at(a),
      allocatedExpressions.at(b)));
}

SymExpr _sym_build_sext(SymExpr expr, uint8_t bits) {
  if (expr == nullptr)
    return nullptr;

  return registerExpression(g_expr_builder->createSExt(
      allocatedExpressions.at(expr), bits + expr->bits()));
}

SymExpr _sym_build_zext(SymExpr expr, uint8_t bits) {
  if (expr == nullptr)
    return nullptr;

  return registerExpression(g_expr_builder->createZExt(
      allocatedExpressions.at(expr), bits + expr->bits()));
}

SymExpr _sym_build_trunc(SymExpr expr, uint8_t bits) {
  if (expr == nullptr)
    return nullptr;

  return registerExpression(
      g_expr_builder->createTrunc(allocatedExpressions.at(expr), bits));
}

SymExpr _sym_build_fp_abs(SymExpr expr) {
  return registerExpression(
      g_expr_builder->createFAbs(allocatedExpressions[expr]));
}

SymExpr _sym_build_int_to_float(SymExpr value, int is_double, int is_signed) {
  return registerExpression(g_expr_builder->intToFloat(
      allocatedExpressions[value], is_double, is_signed));
}

SymExpr _sym_build_float_to_float(SymExpr expr, int to_double) {
  return registerExpression(
      g_expr_builder->floatToFloat(allocatedExpressions[expr], to_double));
}

SymExpr _sym_build_bits_to_float(SymExpr expr, int to_double) {
  if (expr == nullptr)
    return nullptr;

  return registerExpression(
      g_expr_builder->bitsToFloat(allocatedExpressions[expr], to_double));
}

SymExpr _sym_build_float_to_bits(SymExpr expr) {
  if (expr == nullptr)
    return nullptr;

  return registerExpression(
      g_expr_builder->floatToBits(allocatedExpressions[expr]));
}

SymExpr _sym_build_float_to_signed_integer(SymExpr expr, uint8_t bits) {
  return registerExpression(
      g_expr_builder->floatToSignInt(allocatedExpressions[expr], bits));
}

SymExpr _sym_build_float_to_unsigned_integer(SymExpr expr, uint8_t bits) {
  return registerExpression(
      g_expr_builder->floatToUnsignInt(allocatedExpressions[expr], bits));
}

void _sym_push_path_constraint(SymExpr constraint, int taken,
                               uintptr_t site_id,
                               uintptr_t left_id,
                               uintptr_t right_id) {
  if (constraint == nullptr)
    return;
  BranchNode bNode(constraint, taken, site_id, left_id, right_id);
  branchConstaints.push_back(bNode);
  g_solver->addJcc(allocatedExpressions.at(constraint), taken != 0, site_id);
}

SymExpr _sym_get_input_byte(size_t offset, uint8_t value) {
  g_enhanced_solver->pushInputByte(offset, value);
  return registerExpression(g_expr_builder->createRead(offset));
}

SymExpr _sym_concat_helper(SymExpr a, SymExpr b) {
  return registerExpression(g_expr_builder->createConcat(
      allocatedExpressions.at(a), allocatedExpressions.at(b)));
}

SymExpr _sym_extract_helper(SymExpr expr, size_t first_bit, size_t last_bit) {
  return registerExpression(g_expr_builder->createExtract(
      allocatedExpressions.at(expr), last_bit, first_bit - last_bit + 1));
}

size_t _sym_bits_helper(SymExpr expr) { return expr->bits(); }

SymExpr _sym_build_bool_to_bit(SymExpr expr) {
  if (expr == nullptr)
    return nullptr;

  return registerExpression(
      g_expr_builder->boolToBit(allocatedExpressions.at(expr), 1));
}

//
// Floating-point operations (unsupported in QSYM)
//

// Even if we don't generally support operations on floats in this backend, we
// need dummy implementations of a few functions to help the parts of the
// instrumentation that deal with structures; if structs contain floats, the
// instrumentation expects to be able to create bit-vector expressions for
// them.

SymExpr _sym_build_float(double x, int is_double) {
  // We create an all-zeros bit vector, mainly to capture the length of the
  // value. This is compatible with our dummy implementation of
  // _sym_build_float_to_bits.
  llvm::APFloat val(x);
  return registerExpression(
      g_expr_builder->createConstantFloat(val, is_double ? 64 : 32));
}

#define UNSUPPORTED(prototype)                                                 \
  prototype { return nullptr; }

//UNSUPPORTED(SymExpr _sym_build_fp_add(SymExpr, SymExpr))
//UNSUPPORTED(SymExpr _sym_build_fp_sub(SymExpr, SymExpr))
//UNSUPPORTED(SymExpr _sym_build_fp_mul(SymExpr, SymExpr))
//UNSUPPORTED(SymExpr _sym_build_fp_div(SymExpr, SymExpr))
//UNSUPPORTED(SymExpr _sym_build_fp_rem(SymExpr, SymExpr))
//UNSUPPORTED(SymExpr _sym_build_fp_abs(SymExpr))
UNSUPPORTED(SymExpr _sym_build_fp_neg(SymExpr))
//UNSUPPORTED(SymExpr _sym_build_float_ordered_greater_than(SymExpr, SymExpr))
//UNSUPPORTED(SymExpr _sym_build_float_ordered_greater_equal(SymExpr, SymExpr))
//UNSUPPORTED(SymExpr _sym_build_float_ordered_less_than(SymExpr, SymExpr))
//UNSUPPORTED(SymExpr _sym_build_float_ordered_less_equal(SymExpr, SymExpr))
//UNSUPPORTED(SymExpr _sym_build_float_ordered_equal(SymExpr, SymExpr))
//UNSUPPORTED(SymExpr _sym_build_float_ordered_not_equal(SymExpr, SymExpr))
//UNSUPPORTED(SymExpr _sym_build_float_ordered(SymExpr, SymExpr))
//UNSUPPORTED(SymExpr _sym_build_float_unordered(SymExpr, SymExpr))
//UNSUPPORTED(SymExpr _sym_build_float_unordered_greater_than(SymExpr, SymExpr))
//UNSUPPORTED(SymExpr _sym_build_float_unordered_greater_equal(SymExpr, SymExpr))
//UNSUPPORTED(SymExpr _sym_build_float_unordered_less_than(SymExpr, SymExpr))
//UNSUPPORTED(SymExpr _sym_build_float_unordered_less_equal(SymExpr, SymExpr))
//UNSUPPORTED(SymExpr _sym_build_float_unordered_equal(SymExpr, SymExpr))
//UNSUPPORTED(SymExpr _sym_build_float_unordered_not_equal(SymExpr, SymExpr))
//UNSUPPORTED(SymExpr _sym_build_int_to_float(SymExpr, int, int))
//UNSUPPORTED(SymExpr _sym_build_float_to_float(SymExpr, int))
//UNSUPPORTED(SymExpr _sym_build_bits_to_float(SymExpr, int))
//UNSUPPORTED(SymExpr _sym_build_float_to_signed_integer(SymExpr, uint8_t))
//UNSUPPORTED(SymExpr _sym_build_float_to_unsigned_integer(SymExpr, uint8_t))

#undef UNSUPPORTED
#undef H

//
// Call-stack tracing
//

void _sym_notify_call(uintptr_t site_id) {
  g_call_stack_manager.visitCall(site_id);
}

void _sym_notify_ret(uintptr_t site_id) {
  g_call_stack_manager.visitRet(site_id);
}

void _sym_notify_basic_block(uintptr_t site_id) {
  g_call_stack_manager.visitBasicBlock(site_id);
}

//
// Debugging
//

const char *_sym_expr_to_string(SymExpr expr) {
  static char buffer[4096];

  auto expr_string = expr->toString();
  auto copied = expr_string.copy(
      buffer, std::min(expr_string.length(), sizeof(buffer) - 1));
  buffer[copied] = '\0';

  return buffer;
}

bool _sym_feasible(SymExpr expr) {
  expr->simplify();

  g_solver->push();
  g_solver->add(expr->toZ3Expr());
  bool feasible = (g_solver->check() == z3::sat);
  g_solver->pop();

  return feasible;
}

//
// Garbage collection
//

void _sym_collect_garbage() {
  if (allocatedExpressions.size() < g_config.garbageCollectionThreshold)
    return;

#ifdef DEBUG_RUNTIME
  auto start = std::chrono::high_resolution_clock::now();
#endif

  auto reachableExpressions = collectReachableExpressions();
  for (auto expr_it = allocatedExpressions.begin();
       expr_it != allocatedExpressions.end();) {
    if (reachableExpressions.count(expr_it->first) == 0) {
      expr_it = allocatedExpressions.erase(expr_it);
    } else {
      ++expr_it;
    }
  }

#ifdef DEBUG_RUNTIME
  auto end = std::chrono::high_resolution_clock::now();

  std::cerr << "After garbage collection: " << allocatedExpressions.size()
            << " expressions remain" << std::endl
            << "\t(collection took "
            << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                     start)
                   .count()
            << " milliseconds)" << std::endl;
#endif
}

//
// Test-case handling
//

void symcc_set_test_case_handler(TestCaseHandler handler) {
  g_test_case_handler = handler;
}

//
// Path Constaints Tree handling
//

template <typename E>
constexpr auto to_underlying(E e) noexcept{
  return static_cast<std::underlying_type_t<E>>(e);
}

SymbolicExpr serializeQsymExpr(SymExpr expr) {
  UINT32 hashValue = expr->hash();
  auto it = cached.find(hashValue);
  if (it != cached.end())
    return it->second;

  SymbolicExpr res;
  SymbolicExpr *child0, *child1, *child2;

  qsym::Kind k = expr->kind();
  assert(to_underlying(k) <= 79);
  res.set_type(static_cast<ExprKind>(to_underlying(k)));
  res.set_bits(expr->bits());
  res.set_hash(hashValue);

  switch (k) {
  case Kind::Bool:
    res.set_value(((BoolExpr *) (expr))->value());
    break;
  case Kind::Constant:
    res.set_value(((ConstantExpr *) (expr))->value().getSExtValue());
    break;
  case Kind::Float:
    res.set_value(
        ((ConstantFloatExpr *) (expr))->value().bitcastToAPInt().getSExtValue());
    break;
  case Kind::Read:{
    //ReadExpr has a _index of type uint32, so we are safe to assign it to a int64.
    int index = ((ReadExpr *) (expr))->index();
    res.set_value(index);
    res.set_name(("v_" + std::to_string(index)));
    break;
  }
  /* Unary Expression */
  /// logical expression
  case Kind::Neg: case Kind::Not: case Kind::LNot:
  /// floating-point function
  case Kind::FPToBV: case Kind::BVToFP: case Kind::FPToFP: case Kind::FPToSI:
  case Kind::FPToUI: case Kind::SIToFP: case Kind::UIToFP: case Kind::FAbs:
    /// extension operator: the targeted bit-width has been preserved
  case Kind::ZExt: case Kind::SExt:
    child0 = res.add_children();
    *child0 = serializeQsymExpr(expr->getChild(0).get());
    break;
  case Kind::Extract:
    child0 = res.add_children();
    *child0 = serializeQsymExpr(expr->getChild(0).get());
    res.set_value(((ExtractExpr *) (expr))->index());
    break;
    /* Binary Expression */
    /// bit-vector expression
  case Kind::Concat:
  case Kind::Equal: case Kind::Distinct: case Kind::Ult: case Kind::Ule: case Kind::Ugt:
  case Kind::Uge: case Kind::Slt: case Kind::Sle: case Kind::Sgt: case Kind::Sge:
  case Kind::Add: case Kind::Sub: case Kind::Mul: case Kind::UDiv: case Kind::SDiv:
  case Kind::URem: case Kind::SRem: case Kind::And: case Kind::Or: case Kind::Xor:
  case Kind::Shl: case Kind::LShr: case Kind::AShr: case Kind::LOr: case Kind::LAnd:
    /// floating-point expression
  case Kind::FAdd: case Kind::FSub: case Kind::FMul: case Kind::FDiv: case Kind::FRem:
  case Kind::FOgt: case Kind::FOge: case Kind::FOlt: case Kind::FOle: case Kind::FOne:
  case Kind::FOeq: case Kind::FOrd: case Kind::FUne: case Kind::FUno:
  case Kind::FUlt: case Kind::FUle: case Kind::FUgt: case Kind::FUge: case Kind::FUeq:
    child0 = res.add_children();
    child1 = res.add_children();
    *child0 = serializeQsymExpr(expr->getChild(0).get());
    *child1 = serializeQsymExpr(expr->getChild(1).get());
    break;
    /* Ternary Expression */
  case Kind::Ite:
    child0 = res.add_children();
    child1 = res.add_children();
    child2 = res.add_children();
    *child0 = serializeQsymExpr(expr->getChild(0).get());
    *child1 = serializeQsymExpr(expr->getChild(1).get());
    *child2 = serializeQsymExpr(expr->getChild(2).get());
    break;
  case Kind::Rol:
  case Kind::Ror:
  case Kind::Invalid:
    LOG_FATAL("Unsupported expression kind in serialization");
    break;
  default:
    LOG_FATAL("Unknown expression kind in serialization");
    break;
  }

  cached.insert(make_pair(hashValue, res));
  return res;
}

std::string toString6digit(INT32 val) {
  char buf[6 + 1]; // ndigit + 1
  snprintf(buf, 7, "%06d", val);
  buf[6] = '\0';
  return std::string(buf);
}

uint32_t getTestCaseID() {
  uint32_t max_number = 0;
  fs::path output_dir(g_config.outputDir);

  for (const auto& entry : fs::directory_iterator(output_dir)) {
    if (!entry.is_regular_file())
      continue;

    std::string filename = entry.path().filename().string();

    // 检查是否以 ".pct" 结尾
    if (filename.substr(filename.size() - 4) != ".pct")
      continue;

    std::string number_str = filename.substr(0, filename.size() - 4);

    try {
      if (!number_str.empty() &&
          std::all_of(number_str.begin(), number_str.end(), ::isdigit)) {
        uint32_t number = static_cast<uint32_t>(std::stoul(number_str));
        if (number > max_number)
          max_number = number;
      }
    } catch (const std::exception&) {
      continue;
    }
  }

  return max_number + 1;
}

void _sym_report_path_constraint_sequence() {
  ConstraintSequence cs;
  for(const auto &e : branchConstaints) {
    if (e.constraint) {
      /// first meet this constraint
      SymExpr constraint = e.constraint;
      std::cerr << "[zgf dbg] cons : " << constraint->toString() << "\n";

      SequenceNode *node = cs.add_node();
      node->set_taken((e.taken > 0));
      node->set_b_id(e.currBB);
      node->set_b_left(e.leftBB);
      node->set_b_right(e.rightBB);

      SymbolicExpr *expr = node->mutable_constraint();
      *expr = serializeQsymExpr(constraint);
    }
  }

  std::string fname = g_config.outputDir + "/" + toString6digit(getTestCaseID()) + ".pct";
  ofstream of(fname, std::ofstream::out | std::ofstream::binary);
  LOG_INFO("New path constraint tree: " + fname + "\n");
  if (of.fail())
    LOG_FATAL("Unable to open a file to write results\n");

  // TODO: batch write
  cs.SerializeToOstream(&of);
  of.close();
}
