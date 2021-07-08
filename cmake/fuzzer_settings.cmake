# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

macro (enclave_enable_fuzzing NAME)
  target_compile_options(${NAME}
    PRIVATE
    -fsanitize=enclavefuzzer,enclaveaddress
    -fsanitize-address-instrument-interceptors
    -fsanitize-coverage=edge,indirect-calls,no-prune
    -fsanitize-coverage=trace-cmp,trace-div,trace-gep,trace-pc,trace-pc-guard)

  target_link_options(${NAME}
    PRIVATE
    -fsanitize=enclavefuzzer,enclaveaddress
    -fsanitize-address-instrument-interceptors
    -fsanitize-coverage=edge,indirect-calls,no-prune
    -fsanitize-coverage=trace-cmp,trace-div,trace-gep,trace-pc,trace-pc-guard)
endmacro (enclave_enable_fuzzing)

macro (host_enable_fuzzing NAME)
  target_compile_options(${NAME}
    PRIVATE
    -fsanitize=fuzzer,address
    -fsanitize-coverage=edge,indirect-calls,no-prune
    -fsanitize-coverage=trace-cmp,trace-div,trace-gep,trace-pc,trace-pc-guard)
  
  target_link_options(${NAME}
    PRIVATE
    -fsanitize=fuzzer,address
    -fsanitize-coverage=edge,indirect-calls,no-prune
    -fsanitize-coverage=trace-cmp,trace-div,trace-gep,trace-pc,trace-pc-guard)
endmacro (host_enable_fuzzing)
