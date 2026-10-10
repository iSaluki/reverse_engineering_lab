#!/usr/bin/env bash
# Smoke test for the lab (~90s): builds tiny samples and checks every main pipeline end to end.
# usage: tests/smoke.sh      (run after changing setup.sh or the wrappers)
set -uo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
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
# ---- bug bounty layer: vuln-scan (native sinks, secrets, endpoints, semgrep rules) and re-fuzz
cat > v.c <<'C'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
const char *TOKEN = "ghp_R2d9xQ7mK4vL8nT1pW6sY3zB5cF0hJ2gA9eU", *API = "https://api.acme-corp.io/v2/users";
void greet(const char *n){ char b[32]; strcpy(b, n); printf(b); }
void ping(const char *h){ char c[64]; sprintf(c, "ping -c1 %s", h); system(c); }
int main(int c, char **v){ if (c > 2) ping(v[2]); if (c > 1) greet(v[1]); return TOKEN[0] == API[0]; }
C
gcc -O0 -o v v.c 2>/dev/null
vuln-scan v > vs.log 2>&1
check "vuln-scan native sinks"    "grep -q 'command injection' work/v/vuln/native_sinks.tsv && grep -q 'format string (non-constant' work/v/vuln/native_sinks.tsv"
check "vuln-scan secrets"         "grep -q github-pat work/v/vuln/secrets.tsv"
check "vuln-scan endpoints"       "grep -q api.acme-corp.io work/v/vuln/endpoints.txt"
check "vuln-scan CANDIDATES"      "grep -q 'HIGH' work/v/vuln/CANDIDATES.md"
check "semgrep rules vs fixtures" "vuln-scan $REPO/tests/fixtures -o fx --no-secrets && repy -I $REPO/tests/check_rules.py fx/semgrep.json"
printf '#include <unistd.h>\nint main(void){char b[8];if(read(0,b,8)>=4&&b[0]==66&&b[1]==79&&b[2]==79&&b[3]==77)*(volatile int*)0=1;return 0;}\n' > fz.c
check "re-fuzz build+fuzz+triage" "re-fuzz --build fz.c -o fz.afl && re-fuzz fz.afl -t 25 -s BOOL && grep -q '^## crash 1' work/fz.afl/fuzz/triage.txt"
echo "passed $pass, failed $fail"; [ $fail -eq 0 ]
