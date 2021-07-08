# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
cmake_minimum_required(VERSION 3.0.0)
project("oe_fuzzing" LANGUAGES C CXX)

find_package(OpenEnclave CONFIG REQUIRED)
set(CMAKE_CXX_STANDARD 14)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output/lib)

add_subdirectory(enclave)

# Generate key
add_custom_command(
  OUTPUT private.pem public.pem
  COMMAND openssl genrsa -out private.pem -3 3072
  COMMAND openssl rsa -in private.pem -pubout -out public.pem)

# Sign enclave
add_custom_command(
  OUTPUT enclave/create_enclave.signed
  DEPENDS create_enclave ${CMAKE_CURRENT_SOURCE_DIR}/enclave/create.conf private.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:create_enclave> -c
          ${CMAKE_CURRENT_SOURCE_DIR}/enclave/create.conf -k private.pem)

add_custom_target(sign ALL DEPENDS enclave/create_enclave.signed)
