# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ${CMAKE_CURRENT_SOURCE_DIR}/../enclavefuzz.edl)

add_custom_command(
  OUTPUT enclavefuzz_u.h enclavefuzz_u.c
  DEPENDS ${EDL_FILE}
  COMMAND
    openenclave::oeedger8r --untrusted ${EDL_FILE}
    --search-path ${OE_INCLUDEDIR} 
    --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx
    --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../../common)

add_executable(enclavefuzz_host
  host.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/enclavefuzz_u.c)

target_include_directories(enclavefuzz_host
  PRIVATE
  ${PROJECT_SOURCE_DIR}/sut
  ${PROJECT_SOURCE_DIR}/sut/openenclave/
  ${PROJECT_SOURCE_DIR}/sut/openenclave/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common
  ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(enclavefuzz_host 
  PRIVATE 
  oefuzzsup_host 
  openenclave::oehost)

host_enable_fuzzing(enclavefuzz_host)
