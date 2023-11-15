#!/usr/bin/env bash

set -euo pipefail

llvm-objdump --disassemble-symbols=_isatty C:/Windows/System32/ucrtbase.dll
echo "----------------------"
# https://github.com/ajkhoury/pdbfetch
./pdbfetch C:/Windows/System32/ucrtbase.dll pdb
mv pdb/ucrtbase.pdb/*/ucrtbase.pdb .
echo "Address for pioinfo symbol (from pdb file)"
llvm-pdbutil pretty ucrtbase.pdb --all | grep pioinfo
echo "----------------------"
cl main.cpp /nologo /EHsc /MD # ucrt
#https://learn.microsoft.com/en-us/cpp/c-runtime-library/crt-library-features?view=msvc-170
echo "----------------------"
file main.exe
echo "----------------------"
./main.exe 

echo "OK"
