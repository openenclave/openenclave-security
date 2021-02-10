#!/bin/bash
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Update all submodules
git submodule update --init --recursive

# Invoke CodeQL analysis
# If the SCAN_PATH env variable is not set, the argument will be ignored
python3 ./src/static/codeql/scripts/codeql.py --clean --builtin --scan_path=$SCAN_PATH
