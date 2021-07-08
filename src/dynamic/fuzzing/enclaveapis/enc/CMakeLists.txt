# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ${CMAKE_CURRENT_SOURCE_DIR}/../enclaveapis.edl)
add_custom_command(
  OUTPUT enclaveapis_t.h enclaveapis_t.c enclaveapis_args.h
  DEPENDS ${EDL_FILE}
  COMMAND
    openenclave::oeedger8r --trusted ${EDL_FILE}
    --search-path ${OE_INCLUDEDIR} 
    --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx
    --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../../common)

list(APPEND fuzzer_projects
  "oe_get_report_enc"
  "oe_get_target_info_enc"
  "oe_parse_report_enc"
  "oe_verify_report_enc"
  "oe_get_seal_key_by_policy_enc"
  "oe_get_public_key_by_policy_enc"
  "oe_get_public_key_enc"
  "oe_get_private_key_by_policy_enc"
  "oe_get_private_key_enc"
  "oe_get_seal_key_enc"
  "oe_generate_attestation_certificate_enc"
  "oe_verify_attestation_certificate_enc")

foreach(fuzzer_project ${fuzzer_projects})
  add_executable(${fuzzer_project}
    enc.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/enclaveapis_t.c)

  set_target_properties(${fuzzer_project} PROPERTIES COMPILE_FLAGS -D${fuzzer_project})
  target_compile_definitions(${fuzzer_project} PUBLIC OE_API_VERSION=2)

  target_include_directories(${fuzzer_project}
    PUBLIC
    ${PROJECT_SOURCE_DIR}/sut
    ${PROJECT_SOURCE_DIR}/sut/openenclave/
    ${PROJECT_SOURCE_DIR}/sut/openenclave/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../common
    ${CMAKE_CURRENT_BINARY_DIR})

  target_link_libraries(${fuzzer_project} 
    PRIVATE
    oefuzzsup_enc
    openenclave::oeenclave
    openenclave::oelibcxx
    openenclave::oelibc
    openenclave::oecore
    openenclave::oecryptombedtls)
    
  enclave_enable_fuzzing(${fuzzer_project})
endforeach()
