# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ${CMAKE_CURRENT_SOURCE_DIR}/../enclaveapis.edl)

add_custom_command(
  OUTPUT enclaveapis_u.h enclaveapis_u.c
  DEPENDS ${EDL_FILE}
  COMMAND
    openenclave::oeedger8r --untrusted ${EDL_FILE}
    --search-path ${OE_INCLUDEDIR} 
    --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx
    --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../../common)

list(APPEND fuzzer_projects
  "oe_get_report_enc_fuzz"
  "oe_get_target_info_enc_fuzz"
  "oe_parse_report_enc_fuzz"
  "oe_verify_report_enc_fuzz"
  "oe_get_seal_key_by_policy_enc_fuzz"
  "oe_get_public_key_by_policy_enc_fuzz"
  "oe_get_public_key_enc_fuzz"
  "oe_get_private_key_by_policy_enc_fuzz"
  "oe_get_private_key_enc_fuzz"
  "oe_get_seal_key_enc_fuzz"
  "oe_generate_attestation_certificate_enc_fuzz"
  "oe_verify_attestation_certificate_enc_fuzz")

foreach(fuzzer_project ${fuzzer_projects})
  add_executable(${fuzzer_project}
    host.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/enclaveapis_u.c)
  
  set_target_properties(${fuzzer_project} PROPERTIES COMPILE_FLAGS -D${fuzzer_project})

  target_include_directories(${fuzzer_project}
    PRIVATE
    ${PROJECT_SOURCE_DIR}/sut
    ${PROJECT_SOURCE_DIR}/sut/openenclave/
    ${PROJECT_SOURCE_DIR}/sut/openenclave/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../common
    ${CMAKE_CURRENT_BINARY_DIR})

  target_link_libraries(${fuzzer_project} 
    PRIVATE 
    oefuzzsup_host 
    openenclave::oehost)

    host_enable_fuzzing(${fuzzer_project})
endforeach()
