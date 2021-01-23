#!/bin/bash
git submodule update --init --recursive
python3 ./src/static/codeql/scripts/codeql.py --clean --builtin
