// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
/**
 * @name Missing enclave boundary check when accessing untrusted memory.
 * @description When host pointers are passed as arguments to ECall, There has to a check
 *              to validate if the memory region is outside the enclave memory boundary.
 * @kind problem
 * @id ecall-args-isoutsideenclave
 * @problem.severity error
 * @tags security
 * @precision medium
 */

import cpp
import semmle.code.cpp.Type
import semmle.code.cpp.controlflow.IRGuards
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.dataflow.new.TaintTracking
import OpenEnclave

/**
 * isOutsideEnclaveBarrierGuardChecks - A gaurd condition to check if a basic block is
 * validated for envalve memory range protection by issuing a call to IsOutsideEnclave.
 */
predicate isOutsideEnclaveBarrierGuardChecks(IRGuardCondition g, Expr checked, boolean isTrue) {
  exists(Call call |
    g.getUnconvertedResultExpression() = call and
    call instanceof IsOutsideEnclaveFunctionCall and
    checked = call.getArgument(0) and
    isTrue = true
  )
}

/**
 * IsOutsideEnclaveBarrierConfig - Data-flow configuration to check if the sink is
 * protected by IsOutsideEnclave validation.
 */
module IsOutsideEnclaveBarrierConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    not exists(IsOutsideEnclaveFunctionCall fc | fc.getArgument(0) = source.asExpr())
  }

  predicate isSink(DataFlow::Node sink) {
    exists(AssignExpr assExp |
      assExp.getRValue() = sink.asExpr() and
      assExp.getLValue().getType() instanceof PointerType
    )
  }

  // Treat a call to IsOutsideEnclaveFunction as a barrier
  // And stop tracking data flow
  predicate isBarrier(DataFlow::Node node) {
    // /3 means there 3 parameters
    node = DataFlow::BarrierGuard<isOutsideEnclaveBarrierGuardChecks/3>::getABarrierNode()
  }
}

module IsOutsideEnclaveBarrierFlow = TaintTracking::Global<IsOutsideEnclaveBarrierConfig>;

// Find any access to host parameter without calling IsOutsideEnclaveFunction
from UntrustedMemory hostMem, ECallInputParameter inParam
where
  hostMem.isOriginatedFrom(inParam) and
  IsOutsideEnclaveBarrierFlow::flow(DataFlow::exprNode(hostMem), DataFlow::exprNode(hostMem))
select hostMem, "Missing enclave boundary check when accessing untrusted memory."
