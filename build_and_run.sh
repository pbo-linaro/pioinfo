#!/usr/bin/env bash

set -euo pipefail

cl main.cpp /nologo /MD # ucrt
#https://learn.microsoft.com/en-us/cpp/c-runtime-library/crt-library-features?view=msvc-170
./main.exe 

echo "OK"
