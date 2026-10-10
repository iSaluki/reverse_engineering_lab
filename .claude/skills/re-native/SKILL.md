---
name: re-native
description: Static reverse engineering of native code (ELF, PE/DLL, Mach-O, .so JNI libs, Go/Rust/C++ binaries, WebAssembly, raw firmware) with headless Ghidra, radare2, capa and FLOSS. Use when re-triage reports KIND native-*, go, wasm, or when analysing .so files extracted from an APK.
---

# Native binaries

## Pipeline
```bash
ghidra-analyze BIN                    # -> work/<bin>/ghidra/ (≈10s small, ≈1min per 2k funcs; --no-decomp for huge bins)
cat work/<bin>/ghidra/summary.txt     # arch, compiler, entry/main, counts, memory map
```
Find the interesting code **by evidence**, then read only those functions (for security bugs, `vuln-scan BIN` ranks dangerous
call sites by input reachability: skill re-vulnhunt):
```bash
G=work/<bin>/ghidra
rg -i 'passw|key|flag|license|http|error' $G/strings.tsv | head -40   # column 3 = functions referencing the string
sort -t$'\t' -k3 -nr $G/functions.tsv | head -30                       # biggest functions (by size); col 4 = #callers
cut -f2 $G/imports.tsv | sort -u | head -100                           # crypto? network? anti-debug?
rg -l 'CryptDecrypt|EVP_|AES|socket|ptrace' $G/decomp | head          # who calls it
cat $G/decomp/<addr>_<name>.c                                          # header lists callers/callees
ghidra-query $G xrefs 0x401234        # code/data refs to an address or symbol
ghidra-query $G decomp main FUN_00401a20 0x401b00    # fresh decompile (reflects renames)
ghidra-query $G disasm 0x401b00       # when decompiler output is suspicious
ghidra-query $G rename 0x401b00 decrypt_config        # persist names as you understand code
```
Stripped ELF: `main` is auto-detected via `__libc_start_main`. PE: `main`/`WinMain` are usually found; otherwise start
from `entry` and follow the call after the CRT init. For DLLs, start from `exports.tsv` and `DllMain`.

## Quick alternatives
- r2 one-shots (colors are off via ~/.radare2rc): `r2 -q -c 'aaa; afl~main; s main; pdg' BIN` (pdg = r2ghidra
  decompiler, pdf = disassembly). `rabin2 -I/-i/-E/-z/-S BIN` gives info, imports, exports, strings, and sections.
- `objdump -d --no-show-raw-insn -M intel --start-address=0x... --stop-address=0x... BIN` gives exact bytes.
- `capa BIN` maps capabilities (ATT&CK, crypto, anti-debug) and their addresses. Use `capa -v` for match locations.
  It works on PE/ELF/shellcode (`-f sc32|sc64`).
- `floss BIN` extracts stack, tight, and decoded strings that `strings` misses (PE). Use `floss --only static -- BIN` for speed.
- `repy` scripting: lief (parse/patch), capstone (disasm), unicorn (emulate a decrypt routine), pyghidra (full API).

## Language-specific notes
- **Go**: Ghidra 12 recovers names (`main.main`, `main.*`). Focus on `main.*` and the module path from
  `goresym -t -d -p BIN | jq '.BuildInfo, [.UserFunctions[].FullName]'`. Strings are not NUL-terminated (ptr+len).
- **Rust**: user code is under `<crate>::`. The real `main` is passed to `std::rt::lang_start`. Panic strings give source paths.
- **C++**: demangled names are in functions.tsv. Vtables show up as arrays of function pointers in `.rodata`/`.rdata`.
  RTTI strings (`.?AV...@@`) name the classes.
- **Mach-O / iOS**: ObjC selectors and classes are recovered. App Store binaries are FairPlay-encrypted
  (`LC_ENCRYPTION_INFO cryptid=1`), and you cannot decrypt them statically.
- **JNI .so (from APKs)**: `Java_pkg_Class_method` exports or `JNI_OnLoad` → `RegisterNatives` table (array of
  {name, signature, fnPtr}). The first two params are `JNIEnv*` and `jobject`/`jclass`. Calls through `*(env)+OFF` are
  JNIEnv function-table slots (64-bit: index = OFF/8, in jni.h order). Common ones: 0x30 FindClass, 0x108 GetMethodID,
  0x110 CallObjectMethod, 0x388 GetStaticMethodID, 0x538 NewStringUTF, 0x548 GetStringUTFChars,
  0x550 ReleaseStringUTFChars, 0x558 GetArrayLength, 0x6b8 RegisterNatives.
- **WebAssembly**: `wasm-decompile f.wasm -o f.dcmp` (readable), `wasm2wat` (exact). Exports are the entry points.
- **Raw firmware / shellcode**: `binwalk` first. Then
  `ghidra-analyze blob -- -processor ARM:LE:32:Cortex -loader BinaryLoader -loader-baseAddr 0x08000000`.
  Find the base from the vector table or absolute pointers. Shellcode: `-processor x86:LE:64:default -loader BinaryLoader`.

## Crackme / keygen recipe
1. Find the success string in `strings.tsv`, then the referencing function, then the comparison that gates it.
2. Simple transforms: reimplement in Python and invert. With constraints: z3 in `repy`.
3. Many branches or heavy hashing-free logic: use angr (`repy`):
```python
import angr, claripy
p = angr.Project("BIN", auto_load_libs=False)
arg = claripy.BVS("arg", 8*32)
st = p.factory.full_init_state(args=["BIN", arg])
sm = p.factory.simulation_manager(st)
sm.explore(find=lambda s: b"Access granted" in s.posix.dumps(1), avoid=lambda s: b"Wrong" in s.posix.dumps(1))
print(sm.found[0].solver.eval(arg, cast_to=bytes))
```
   (stdin input: `stdin=angr.SimFileStream(...)`; PIE base is 0x400000 in angr when you use addresses.)
4. Verify by running the binary with the answer (see re-dynamic).

## Patching
- Find the jump: `ghidra-query $G disasm func`. File offset = VA − section VA + section raw offset (lief
  `binary.virtual_address_to_offset` for ELF, `pe.get_offset_from_rva` for PE).
- Patch with `repy` (lief / plain bytes), then `chmod +x` and test. `r2 -w -q -c 's 0x...; wx 9090' BIN` also works.
