# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../../common/fuzzsupport.edl)

add_custom_command(
  OUTPUT fuzzsupport_u.h fuzzsupport_u.c
  DEPENDS ${EDL_FILE}
  COMMAND
    openenclave::oeedger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_library(oefuzzsup_host 
              host.cpp
              ${OPEN_ENCLAVE_SDK_SRC}/host/sgx/elf.c
              fuzzsupport_u.c)

target_include_directories(oefuzzsup_host 
  PUBLIC
  ${PROJECT_SOURCE_DIR}/sut
  ${PROJECT_SOURCE_DIR}/sut/openenclave
  ${PROJECT_SOURCE_DIR}/sut/openenclave/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_PREFIX_PATH}/../oe_instrumented_build/output/include
  ${CMAKE_PREFIX_PATH}/include)
  
target_link_libraries(oefuzzsup_host PRIVATE openenclave::oehost)
host_enable_fuzzing(oefuzzsup_host)
