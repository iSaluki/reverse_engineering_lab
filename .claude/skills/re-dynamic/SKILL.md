---
name: re-dynamic
description: Run and observe a target safely - gdb in batch mode, strace/ltrace, qemu-user for foreign architectures (ARM/MIPS/...), wine for Windows PEs, unicorn/angr emulation of single routines, frida when a device is available. Use to confirm static findings, solve crackmes, dump unpacked/decrypted data, or trace behaviour.
---

# Dynamic analysis

**Safety first**: this container is disposable, but the target is untrusted. Always wrap runs in `timeout`. Run it from a
scratch directory (`mkdir -p work/run && cd work/run`), never with real credentials, and don't let it reach real
services. Prefer emulating one routine over running the whole program when that answers the question.

## Linux x86-64
```bash
timeout 10 strace -f -s 200 -o work/run/strace.txt ./BIN args      # syscalls: files, network, exec, ptrace
rg 'open|connect|execve|ptrace' work/run/strace.txt | head
timeout 10 ltrace -f -s 200 ./BIN args 2>&1 | head -100             # libc calls (strcmp/memcmp leak passwords!)
```
gdb non-interactively (agents can't drive a TTY, so always use `-batch`):
```bash
gdb -q -batch -ex 'starti' -ex 'info proc mappings' ./BIN                   # PIE base
gdb -q -batch -ex 'break *0x555555555230' -ex 'run AAAA' -ex 'info registers' \
    -ex 'x/8gx $rsp' -ex 'x/s $rdi' ./BIN
gdb -q -batch -x script.gdb --args ./BIN arg                                # longer scripts; `python` blocks allowed
```
PIE: runtime address = base (usually 0x555555554000 under gdb, ASLR off) + (Ghidra addr − Ghidra imagebase 0x100000).
Use `set disable-randomization on` (the default). GEF is available if you want it: `gdb -q -batch -x /opt/re/gef.py ...`.
Anti-debug (`ptrace(PTRACE_TRACEME)` check): `catch syscall ptrace` and then `set $rax=0`, or patch the check.

Memory dump after unpacking/decryption: break after the routine, then `dump memory out.bin 0xSTART 0xEND`.

## Other architectures (ARM, AArch64, MIPS, PPC, RISC-V...)
```bash
qemu-aarch64 -L /usr/aarch64-linux-gnu ./bin_arm64      # dynamic arm64 (cross libc installed)
qemu-arm -L /usr/arm-linux-gnueabihf ./bin_armhf
qemu-mips -L <sysroot> ./bin                            # other sysroots: extract from the firmware's own rootfs
qemu-aarch64 -g 1234 -L /usr/aarch64-linux-gnu ./bin &  # then: gdb-multiarch -q -batch -ex 'target remote :1234' ...
qemu-aarch64 -strace -L /usr/aarch64-linux-gnu ./bin    # syscall trace
```
Android `.so` files need bionic, so they won't run under qemu-user. Emulate the function with unicorn instead (below).

## Windows PE
Install wine on demand: `./setup.sh --with-wine` (~1 min, ~1 GB; 32- and 64-bit console PEs). Then
`timeout 30 rewine app.exe args` (headless wrapper, `WINEDEBUG=-all` by default). Use
`WINEDEBUG=+relay rewine app.exe 2> relay.txt` to trace API calls (very verbose; grep it), and `+file`/`+reg` for files and the registry.
GUI apps need a display: `apt-get install -y xvfb` and then `xvfb-run -a rewine app.exe`. Many malware samples detect
wine, so prefer static analysis plus emulation for those.

## Emulating one routine (best for decryptors, keygens, string decoders)
```python
# repy - unicorn: run a function extracted from the binary
from unicorn import *; from unicorn.x86_const import *
import lief
b = lief.parse("BIN"); code_va = 0x1011a9                 # Ghidra addr - imagebase + load base
mu = Uc(UC_ARCH_X86, UC_MODE_64)
for seg in b.segments:                                      # map loadable segments at their vaddr
    if seg.type == lief.ELF.Segment.TYPE.LOAD:
        start = seg.virtual_address & ~0xfff; size = ((seg.virtual_address + seg.virtual_size + 0xfff) & ~0xfff) - start
        mu.mem_map(start, size); mu.mem_write(seg.virtual_address, bytes(seg.content))
mu.mem_map(0x7f0000000000, 0x100000); mu.reg_write(UC_X86_REG_RSP, 0x7f00000ff000)
# set args (rdi, rsi...), write input buffers, push a fake return address and stop there
```
angr (symbolic): see the re-native crackme recipe. Use `angr.Project(..., auto_load_libs=False)` and hook libc
functions it doesn't model. For pure-math checks, z3 is faster and simpler.

## frida
`frida`, `frida-trace`, and `frida-ps` are installed. Without a device or remote server they can only attach to local
Linux processes: `frida-trace -f ./BIN -i 'strcmp' -i 'memcmp'` (needs ptrace permission, which root in the container has).
