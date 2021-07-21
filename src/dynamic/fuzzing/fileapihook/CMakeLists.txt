# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_library(create_fileapihook SHARED fileapihook.c)
target_compile_options(
    create_fileapihook
    PRIVATE
    -Wno-sign-conversion
    -Wno-sign-compare)
