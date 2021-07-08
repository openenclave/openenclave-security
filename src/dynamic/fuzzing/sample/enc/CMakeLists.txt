# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ${CMAKE_CURRENT_SOURCE_DIR}/../enclavefuzz.edl)
add_custom_command(
  OUTPUT enclavefuzz_t.h enclavefuzz_t.c enclavefuzz_args.h
  DEPENDS ${EDL_FILE}
  COMMAND
    openenclave::oeedger8r --trusted ${EDL_FILE}
    --search-path ${OE_INCLUDEDIR} 
    --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx
    --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../../common)

add_executable(enclavefuzz_enc
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/enclavefuzz_t.c)

target_compile_definitions(enclavefuzz_enc PUBLIC OE_API_VERSION=2)

target_include_directories(enclavefuzz_enc
  PRIVATE 
  ${PROJECT_SOURCE_DIR}/sut
  ${PROJECT_SOURCE_DIR}/sut/openenclave/
  ${PROJECT_SOURCE_DIR}/sut/openenclave/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common
  ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(enclavefuzz_enc 
  PRIVATE 
  oefuzzsup_enc
  openenclave::oeenclave
  openenclave::oelibcxx
  openenclave::oelibc
  openenclave::oecore
  openenclave::oecryptombedtls)

enclave_enable_fuzzing(enclavefuzz_enc)
