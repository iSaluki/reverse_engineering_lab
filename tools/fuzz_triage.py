"""Deduplicate AFL++ crashes into unique bugs with a repro command. usage: fuzz_triage.py <afl-out-dir> <binary> -- [args]
Signature = ASan/UBSan SUMMARY + top frames when the binary is sanitized, else signal + top-3 gdb frames
(native x86-64) or signal + faulting PC (qemu-user for foreign arches). Writes <afl-out-dir>/../triage.txt.
"""
import collections
import glob
import os
import re
import shlex
import subprocess
import sys


def short(p):
    r = os.path.relpath(p)
    return r if not r.startswith("../..") else p

LIBC_FRAME = re.compile(r"^(__\w+|_IO_\w+|raise|abort|__GI_\w+|__libc_\w+|__pthread\w*|__fortify_fail|__chk_fail|"
                        r"__stack_chk_fail|_dl_\w+|\?\?)$")
ARCH_QEMU = {"aarch64": "qemu-aarch64", "arm": "qemu-arm", "mipsel": "qemu-mipsel", "mips": "qemu-mips",
             "i386": "qemu-i386", "ppc": "qemu-ppc"}


def run(cmd, inp, stdin_mode, env, timeout=10):
    try:
        if stdin_mode:
            with open(inp, "rb") as f:
                r = subprocess.run(cmd, stdin=f, capture_output=True, timeout=timeout, env=env)
        else:
            r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, env=env)
        return r.returncode, (r.stdout + r.stderr).decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return "timeout", ""


def main():
    out, binary = sys.argv[1], sys.argv[2]
    args = sys.argv[4:] if len(sys.argv) > 3 and sys.argv[3] == "--" else sys.argv[3:]
    crashes = sorted(p for p in glob.glob(os.path.join(out, "*", "crashes", "id:*")))
    hangs = glob.glob(os.path.join(out, "*", "hangs", "id:*"))
    data = open(binary, "rb").read()
    asan = b"__asan_init" in data or b"__ubsan_handle" in data
    ftype = subprocess.run(["file", "-bL", binary], capture_output=True, text=True).stdout
    arch = next((a for k, a in (("x86-64", "x86_64"), ("aarch64", "aarch64"), ("ARM", "arm"), ("80386", "i386"),
                                 ("PowerPC", "ppc")) if k in ftype), None)
    if "MIPS" in ftype:
        arch = "mipsel" if "LSB" in ftype else "mips"
    env = dict(os.environ, ASAN_OPTIONS="abort_on_error=0:symbolize=1:detect_leaks=0", UBSAN_OPTIONS="print_stacktrace=1")
    sym = next((p for p in glob.glob("/usr/lib/llvm-*/bin/llvm-symbolizer") + glob.glob("/usr/bin/llvm-symbolizer*")), None)
    if sym:
        env["ASAN_SYMBOLIZER_PATH"] = sym
    stdin_mode = "@@" not in args
    groups = collections.OrderedDict()
    for c in crashes[:500]:
        a = [c if x == "@@" else x for x in args]
        sig, detail = "", ""
        if asan or arch == "x86_64":
            if asan:
                rc, o = run([binary] + a, c, stdin_mode, env)
                m = re.search(r"SUMMARY: (\w+Sanitizer: .*)", o)
                frames = [f or os.path.basename(m) for f, m in
                          re.findall(r"#\d+ 0x[0-9a-f]+ (?:in (\S+)|\((\S+?\+0x[0-9a-f]+)\))", o)[:3]]
                summ = re.sub(r"\s*\([^)]*\)", "", m.group(1)) if m else f"rc={rc}"
                sig = summ + " | " + " < ".join(frames)
                keep = [ln for ln in o.splitlines() if re.match(r"\s*(==\d+==ERROR|#[0-4] |SUMMARY|READ|WRITE|Address 0x|\S+ is located)", ln)]
                detail = "\n".join(keep[:14])[:1800]
            if not sig or sig.startswith("rc="):
                g = ["gdb", "-q", "-batch", "-ex", "set pagination off", "-ex",
                     "run" + (f" < {shlex.quote(c)}" if stdin_mode else ""), "-ex", "bt 14", "-ex", "x/i $pc",
                     "--args", binary] + a
                _, o = run(g, c, False, env, timeout=30)
                m = re.search(r"received signal (\w+)", o)
                allf = re.findall(r"#\d+\s+(?:0x[0-9a-f]+ in )?(\S+) \(", o)
                frames = [f for f in allf if not LIBC_FRAME.match(f)][:3] or allf[:3]
                pc = re.search(r"=> (0x[0-9a-f]+)", o)
                sig = f"{m.group(1) if m else 'no-crash-on-replay'} | " + " < ".join(frames or [pc.group(1) if pc else "?"])
                detail = "\n".join(ln for ln in o.splitlines() if re.match(r"(#\d|=>|Program received)", ln))[:1200]
                if "__stack_chk_fail" in o or "__fortify_fail" in o:
                    sig += " (stack canary/FORTIFY tripped = stack buffer overflow)"
        elif arch in ARCH_QEMU:
            rc, o = run([ARCH_QEMU[arch], binary] + a, c, stdin_mode, env)
            sig = f"rc={rc} (qemu-user; for a backtrace: {ARCH_QEMU[arch]} -g 1234 ... + gdb-multiarch)"
            detail = o[-600:]
        else:
            sig = "unknown-arch"
        groups.setdefault(sig, []).append((c, detail))
    lines = [f"# {len(crashes)} saved crashes -> {len(groups)} unique signatures; {len(hangs)} hangs",
             f"# binary: {binary}  args: {' '.join(args) or '(stdin)'}", ""]
    for i, (sig, items) in enumerate(groups.items(), 1):
        c, detail = min(items, key=lambda x: os.path.getsize(x[0]))
        a = [short(c) if x == "@@" else x for x in args]
        repro = " ".join(shlex.quote(x) for x in [short(binary)] + a) + (f" < {shlex.quote(short(c))}" if stdin_mode else "")
        lines += [f"## crash {i}: {sig}", f"count: {len(items)}   smallest input: {short(c)} ({os.path.getsize(c)} bytes)",
                  f"repro: {repro}", f"input (hex, first 64B): {open(c, 'rb').read(64).hex()}"]
        if detail:
            lines += ["```", detail, "```"]
        lines += [""]
    if crashes:
        lines += ["Next: minimize (afl-tmin -i <input> -o min.bin [-Q] -- BIN [args]), map the crashing frame in Ghidra "
                  "(ghidra-query decomp <func>), decide exploitability (write? controlled size/addr? heap vs stack)."]
    txt = "\n".join(lines)
    open(os.path.join(os.path.dirname(os.path.abspath(out)), "triage.txt"), "w").write(txt + "\n")
    print(txt)


if __name__ == "__main__":
    main()
