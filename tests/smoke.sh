#!/usr/bin/env bash
# Smoke test for the lab (~40s): builds tiny samples and checks every main pipeline end to end.
# usage: tests/smoke.sh      (run after changing setup.sh or the wrappers)
set -uo pipefail
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
pass=0; fail=0
check() { if eval "$2" >/dev/null 2>&1; then echo "PASS $1"; pass=$((pass+1)); else echo "FAIL $1"; fail=$((fail+1)); fi; }

cat > "$T/c.c" <<'C'
#include <stdio.h>
#include <string.h>
int check(const char*s){ return strcmp(s,"letmein")==0; }
int main(int c,char**v){ puts(c>1&&check(v[1])?"Access granted":"Denied"); return 0; }
C
gcc -O1 -s -o "$T/c" "$T/c.c"
cd "$T"
check "re-doctor"                 "re-doctor"
check "re-triage ELF"             "re-triage c | grep -q 'KIND *native-elf'"
check "ghidra-analyze + main"     "ghidra-analyze c | grep -q '^main:'"
check "decomp has strings"        "grep -rq 'Access granted' work/c/ghidra/decomp"
check "ghidra-query decomp"       "ghidra-query work/c/ghidra decomp main | grep -q 'Denied'"
check "r2 + r2ghidra"             "r2 -q -c 'aaa; s main; pdg' c | grep -q Denied"
cp c c_upx && upx -q c_upx >/dev/null
check "upx unpack"                "upx -d -o c_unp c_upx"
printf 'public class H { public static void main(String[] a){ System.out.println("hi-jar"); } }' > H.java
javac H.java 2>/dev/null && jar cfe h.jar H H.class 2>/dev/null
check "jadx jar"                  "jadx -q -d jx h.jar && grep -rq hi-jar jx"
printf 'x = 1\nprint("hello-pyc")\n' > m.py && python3 -m py_compile m.py && cp __pycache__/m.*.pyc m.pyc
check "py-unpack pyc"             "py-unpack m.pyc -o py && grep -rq hello-pyc py/src"
check "ilspycmd"                  "ilspycmd --version"
check "capa"                      "capa --version"
check "repy libs"                 "repy -c 'import lief,pefile,angr,androguard,capstone,unicorn,z3,dnfile,pyghidra'"
echo "passed $pass, failed $fail"; [ $fail -eq 0 ]
