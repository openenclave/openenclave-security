#!/bin/bash
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Update all submodules
git submodule update --init --recursive

# Invoke CodeQL analysis
python3 ./src/static/codeql/scripts/codeql.py --clean --builtin
