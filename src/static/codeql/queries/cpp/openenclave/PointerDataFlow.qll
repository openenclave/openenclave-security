// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.dataflow.new.TaintTracking

/**
 * Pointer Expresssion
 */
class PointerExpr extends Expr {
  PointerExpr() {
    getType().getUnderlyingType().getUnspecifiedType() instanceof PointerType or
    this.isConstant()
  }
}

/**
 * Data flow configuration tracking pointer flow from expressions or parameters of pointer type
 * to their accesses.
 */
module PointerConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) {
    hasPointerType(n) and
    // restrict to non-null values, as these are safe to repeatedly free
    not n.asExpr() instanceof NullValue
  }

  predicate isSink(DataFlow::Node n) {
    hasPointerType(n) and
    n.asExpr() instanceof VariableAccess
  }
}

module PointerFlow = TaintTracking::Global<PointerConfig>;

/**
 * Holds if the data flow node `n` is an expression or parameter of pointer type.
 */
predicate hasPointerType(DataFlow::Node n) {
  n.asExpr().getFullyConverted() instanceof PointerExpr or
  n.asParameter().getType().getUnderlyingType().getUnspecifiedType() instanceof PointerType
}
