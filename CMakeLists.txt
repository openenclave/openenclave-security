cmake_minimum_required(VERSION 3.0.0)
project(oefuzz VERSION 1.0.0)
set(CMAKE_C_COMPILER_ID "Clang")
set(CMAKE_CXX_COMPILER_ID "Clang")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(fuzzer_settings)

set(OPEN_ENCLAVE_SDK_SRC ${PROJECT_SOURCE_DIR}/sut/openenclave)
add_subdirectory(src/dynamic/fuzzing)
