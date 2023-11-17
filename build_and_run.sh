#!/usr/bin/env bash

set -euo pipefail

echo "----------------------"
cl main.cpp /nologo /EHsc /MD /Fe:pioinfo.exe
cl main.cpp /nologo /EHsc /MDd /Fe:pioinfo_debug.exe
# /MD, /MDd to target ucrt
#https://learn.microsoft.com/en-us/cpp/c-runtime-library/crt-library-features?view=msvc-170
echo "----------------------"
llvm-objdump --disassemble-symbols=_isatty C:/Windows/System32/ucrtbase.dll | tee ucrtbase.disas
echo "----------------------"
llvm-objdump --disassemble-symbols=_isatty C:/Windows/System32/ucrtbased.dll | tee ucrtbased.disas
echo "----------------------"
# https://github.com/ajkhoury/pdbfetch
[ -f ucrtbase.pdb ] || ./pdbfetch C:/Windows/System32/ucrtbase.dll pdb
[ -f ucrtbased.pdb ] || ./pdbfetch C:/Windows/System32/ucrtbased.dll pdb
rsync -av pdb/*/*/*.pdb .
echo "----------------------"
llvm-pdbutil pretty ucrtbase.pdb --include-symbols=__pioinfo --externals
echo "----------------------"
llvm-pdbutil pretty ucrtbased.pdb --include-symbols=__pioinfo --externals 
echo "----------------------"
file pioinfo.exe
file pioinfo_debug.exe
echo "----------------------"
./pioinfo.exe || true
echo "----------------------"
#./pioinfo_debug.exe || true
