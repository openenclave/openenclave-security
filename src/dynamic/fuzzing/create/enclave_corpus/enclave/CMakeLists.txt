# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE "../../create.edl")
add_custom_command(
  OUTPUT create_t.h create_t.c create_args.h
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${EDL_FILE}
  COMMAND
    openenclave::oeedger8r --trusted ${CMAKE_CURRENT_SOURCE_DIR}/${EDL_FILE}
    --search-path ${OE_INCLUDEDIR} 
    --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx
    --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../../../common)

add_executable(create_enclave enc.c ${CMAKE_CURRENT_BINARY_DIR}/create_t.c)
target_compile_definitions(create_enclave PUBLIC OE_API_VERSION=2)

target_include_directories(create_enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(create_enclave
  openenclave::oelibcxx
  openenclave::oeenclave
  openenclave::oecryptombedtls
  openenclave::oelibc)
