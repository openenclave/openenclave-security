# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT create_u.h create_u.c create_args.h
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../create.edl
  COMMAND
    openenclave::oeedger8r --untrusted ${CMAKE_CURRENT_SOURCE_DIR}/../create.edl
    --search-path ${OE_INCLUDEDIR} 
    --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx
    --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../../common)

add_executable(create_host 
  host.cpp 
  ${CMAKE_CURRENT_BINARY_DIR}/create_u.c)
  # elf.c)

set_property(TARGET create_host PROPERTY CXX_STANDARD 14)
target_include_directories(create_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(create_host 
  PRIVATE 
  oefuzzsup_host 
  openenclave::oehost)

target_compile_options(create_host 
  PUBLIC 
  -fsanitize=fuzzer,address
  -fsanitize-coverage=edge,indirect-calls,no-prune 
  -fsanitize-coverage=trace-cmp,trace-div,trace-gep,trace-pc,trace-pc-guard)

target_link_options(create_host
  PUBLIC 
  -fsanitize=fuzzer,address
  -fsanitize-coverage=edge,indirect-calls,no-prune 
  -fsanitize-coverage=trace-cmp,trace-div,trace-gep,trace-pc,trace-pc-guard)
