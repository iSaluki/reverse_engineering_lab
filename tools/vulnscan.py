"""First-pass vulnerability discovery over a re-auto work dir (or any directory). Static only: never runs the target
and never contacts the network.

usage: vulnscan.py <workdir|dir> [--target FILE] [--out DIR] [--rules DIR] [--no-semgrep] [--no-secrets]
                   [--all-code] [--top N]

Writes OUT (default <workdir>/vuln):
  CANDIDATES.md      ranked leads (score 0-10) with evidence and what to verify -- start here
  candidates.tsv     every lead, machine-readable
  hardening.tsv      NX/PIE/RELRO/canary/FORTIFY (ELF), ASLR/DEP/CFG/GS/SafeSEH/signed (PE), PIE/encrypted (Mach-O)
  native_sinks.tsv   dangerous call sites in Ghidra decompilation (+ input-reachability heuristics)
  semgrep.tsv        rule hits on decompiled Java/C#/JS/Python (rules/semgrep/*.yml)  (raw: semgrep.json)
  secrets.tsv        gitleaks hits, masked (raw, unmasked: gitleaks.json)
  endpoints.txt      hosts -> sample URLs/paths; cloud storage; GraphQL     (all urls: urls.txt)
  attack_surface.txt entry points: exported components, deep links, URL schemes, listeners, IPC, CGI...
  components.txt     bundled library/daemon versions from binary strings (OpenSSL, curl, BusyBox...) -> n-day CVEs
"""
import argparse
import collections
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

try:
    import lief
    lief.logging.disable()
except Exception:  # noqa: BLE001
    lief = None

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SKIP_DIRS = {".git", "node_modules.asar.unpacked", "proj.rep"}


def skip_dir(parent, d, siblings):
    """Ghidra project dirs (OUT/project next to OUT/decomp) and VCS metadata."""
    return d in SKIP_DIRS or (d == "project" and ("decomp" in siblings or os.path.exists(os.path.join(parent, "summary.txt"))))
TEXT_EXT = {".java", ".kt", ".smali", ".cs", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".py", ".c", ".h", ".cpp",
            ".xml", ".json", ".txt", ".tsv", ".plist", ".properties", ".yml", ".yaml", ".cfg", ".conf", ".ini",
            ".html", ".htm", ".sh", ".lua", ".php", ".asp", ".dcmp", ".wat", ".config", ".env", ".toml", ".dart"}


class Scan:
    def __init__(self, root, out, target, args):
        self.root, self.out, self.target, self.args = root, out, target, args
        self.cands = []          # dict(score, cat, where, evidence, verify, module)
        self.notes = []          # lines for CANDIDATES.md header
        self.surface = []        # attack surface lines
        self.first_party = []    # app's own package dirs (a/b/c)
        self.deep_dir = os.path.join(os.path.dirname(out), "ghidra-deep")
        sd = os.path.join(out, "strings")
        self.scan_roots = [root] + ([sd] if not sd.startswith(root + os.sep) else [])  # + binaries' strings

    def add(self, score, cat, where, evidence, verify="", module=""):
        self.cands.append(dict(score=max(0, min(10, int(score))), cat=cat, where=where, evidence=evidence.strip(),
                               verify=verify, module=module))

    def rel(self, p):
        try:
            r = os.path.relpath(p, self.root)
        except ValueError:
            return p
        return p if r.startswith("..") else r

    def w(self, name):
        return open(os.path.join(self.out, name), "w", encoding="utf-8")


def walk(root, exts=None, max_files=None):
    n = 0
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if not skip_dir(dp, d, dns) and not (d == "vuln" and dp == root)]
        for f in fns:
            if exts is None or os.path.splitext(f)[1].lower() in exts:
                yield os.path.join(dp, f)
                n += 1
                if max_files and n >= max_files:
                    return


def sh(cmd, timeout=None, **kw):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return subprocess.CompletedProcess(cmd, 124, "", str(e))


# ------------------------------------------------------------------------------------------------- hardening
MAGICS = (b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")


def is_native(p):
    try:
        with open(p, "rb") as f:
            h = f.read(4)
        return h.startswith(MAGICS) and os.path.getsize(p) > 512
    except OSError:
        return False


def harden_elf(b):
    imps = {s.name.split("@")[0] for s in b.imported_symbols}
    T = lief.ELF.DynamicEntry.TAG
    relro = "none"
    if any(s.type == lief.ELF.Segment.TYPE.GNU_RELRO for s in b.segments):
        relro = "partial"
        for e in b.dynamic_entries:
            if (e.tag == T.FLAGS and e.value & 0x8) or (e.tag == T.FLAGS_1 and e.value & 0x1) or e.tag == T.BIND_NOW:
                relro = "full"
    rpath = []
    for e in b.dynamic_entries:
        if e.tag in (T.RPATH, T.RUNPATH):
            v = getattr(e, "runpath", None) or getattr(e, "rpath", None) or getattr(e, "name", None)
            rpath.append(v if isinstance(v, str) else ":".join(getattr(e, "paths", []) or []))
    is_so = b.header.file_type == lief.ELF.Header.FILE_TYPE.DYN and not b.has_interpreter
    return {
        "fmt": "ELF-so" if is_so else "ELF", "arch": str(b.header.machine_type).split(".")[-1],
        "NX": b.has_nx, "PIE": b.is_pie or is_so, "RELRO": relro,
        "canary": "__stack_chk_fail" in imps or "__stack_chk_guard" in imps,
        "fortify": any(i.endswith("_chk") and i.startswith("__") for i in imps),
        "rpath": ":".join(rpath) or "-", "stripped": not any(True for _ in b.symtab_symbols),
        "imports": imps,
    }


def harden_pe(b):
    oh = b.optional_header
    DC = lief.PE.OptionalHeader.DLL_CHARACTERISTICS

    def has(f):
        try:
            return oh.has(f)
        except Exception:  # noqa: BLE001
            return False
    lc = b.load_configuration if b.has_configuration else None
    is64 = b.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64 or "64" in str(b.header.machine)
    imps = {e.name for lib in b.imports for e in lib.entries if e.name}
    gs = bool(lc and getattr(lc, "security_cookie", 0))
    safeseh = "n/a" if is64 else ("NO_SEH" if has(DC.NO_SEH) else bool(lc and getattr(lc, "se_handler_count", 0)))
    return {
        "fmt": "PE-dll" if b.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL) else "PE",
        "arch": str(b.header.machine).split(".")[-1],
        "ASLR": has(DC.DYNAMIC_BASE), "HEVA": has(DC.HIGH_ENTROPY_VA) if is64 else "n/a", "DEP": has(DC.NX_COMPAT),
        "CFG": has(DC.GUARD_CF), "GS": gs, "SafeSEH": safeseh, "signed": b.has_signatures,
        "dotnet": b.data_directory(lief.PE.DataDirectory.TYPES.CLR_RUNTIME_HEADER).size > 0, "imports": imps,
    }


def harden_macho(b):
    imps = {s.name for s in b.imported_symbols}
    enc = b.has_encryption_info and b.encryption_info.crypt_id != 0
    return {"fmt": "Mach-O", "arch": str(b.header.cpu_type).split(".")[-1], "PIE": b.is_pie, "NX-heap": b.has_nx_heap,
            "canary": "___stack_chk_fail" in imps, "ARC": "_objc_release" in imps, "signed": b.has_code_signature,
            "encrypted": enc, "imports": imps}


def hardening(s, bins):
    if lief is None:
        s.notes.append("hardening: lief not importable, skipped")
        return {}
    res = {}
    with s.w("hardening.tsv") as f:
        f.write("file\tformat\tarch\tprotections\tweak\n")
        for p in bins:
            try:
                b = lief.parse(p)
            except Exception:  # noqa: BLE001
                b = None
            if b is None:
                continue
            if isinstance(b, lief.ELF.Binary):
                h = harden_elf(b)
                weak = [k for k in ("NX", "PIE", "canary") if not h[k]] + (["RELRO=" + h["RELRO"]] if h["RELRO"] != "full" else [])
                if h["rpath"] != "-" and re.search(r"(^|:)(\.|[^/$]|/tmp|/var/tmp|/home|/mnt|/media)", h["rpath"]):
                    s.add(5, "insecure RPATH/RUNPATH", s.rel(p), f"rpath={h['rpath']}",
                          "Library search path is relative or user-writable: plant a .so there (local privesc if the binary runs privileged/setuid).", "hardening")
            elif isinstance(b, lief.PE.Binary):
                h = harden_pe(b)
                keys = ("ASLR", "DEP", "signed") if h["dotnet"] else ("ASLR", "DEP", "CFG", "GS", "signed")  # managed: no CFG/GS
                weak = [k for k in keys if h[k] is False] + (["SafeSEH"] if h["SafeSEH"] is False and not h["dotnet"] else [])
            elif isinstance(b, lief.MachO.Binary):
                h = harden_macho(b)
                weak = [k for k in ("PIE", "canary") if not h[k]] + (["ENCRYPTED(FairPlay)"] if h["encrypted"] else [])
            else:
                continue
            try:
                mode = os.stat(p).st_mode
                if mode & 0o4000:
                    weak.append("SETUID")
                    s.add(5, "setuid binary", s.rel(p), "setuid bit set",
                          "Local privilege escalation surface: audit argv/env/file handling (vuln-scan it with --deep).", "hardening")
            except OSError:
                pass
            prot = " ".join(f"{k}={v}" for k, v in h.items() if k not in ("fmt", "arch", "imports"))
            f.write(f"{s.rel(p)}\t{h['fmt']}\t{h['arch']}\t{prot}\t{','.join(weak) or '-'}\n")
            res[p] = (h, weak)
    if res:
        weakest = sorted(res.items(), key=lambda kv: -len(kv[1][1]))[:3]
        s.notes.append("hardening: " + "; ".join(f"{os.path.basename(p)} weak[{','.join(w) or 'none'}]" for p, (h, w) in weakest))
    return res


# ------------------------------------------------------------------------------------------- native sinks
# name -> (category, base score). Argument checks below adjust the score.
SINKS = {}
for n in ("gets", "_getws"):
    SINKS[n] = ("stack/heap overflow (unbounded read)", 9)
for n in ("strcpy", "strcat", "wcscpy", "wcscat", "stpcpy", "lstrcpyA", "lstrcpyW", "lstrcpy", "lstrcatA", "lstrcatW",
          "lstrcat", "StrCpyA", "StrCpyW", "StrCatA", "StrCatW", "_mbscpy", "_mbscat", "strcpyA", "__strcpy_chk", "__strcat_chk"):
    SINKS[n] = ("buffer overflow (unbounded copy)", 6)
for n in ("sprintf", "vsprintf", "swprintf", "wsprintfA", "wsprintfW", "vswprintf", "__sprintf_chk", "__vsprintf_chk"):
    SINKS[n] = ("buffer overflow / format string (sprintf)", 3)
for n in ("snprintf", "vsnprintf", "_snprintf", "_snwprintf", "__snprintf_chk", "__vsnprintf_chk"):
    SINKS[n] = ("format string (snprintf)", 0)
for n in ("printf", "fprintf", "dprintf", "vprintf", "vfprintf", "syslog", "vsyslog", "wprintf", "fwprintf", "err",
          "errx", "warn", "warnx", "__printf_chk", "__fprintf_chk", "__syslog_chk", "printk", "_printf"):
    SINKS[n] = ("format string", 0)
for n in ("scanf", "fscanf", "sscanf", "__isoc99_scanf", "__isoc99_fscanf", "__isoc99_sscanf", "vscanf", "vsscanf"):
    SINKS[n] = ("buffer overflow (scanf %s)", 0)
for n in ("memcpy", "memmove", "bcopy", "strncpy", "strncat", "wmemcpy", "wcsncpy", "RtlCopyMemory", "CopyMemory",
          "__memcpy_chk", "__memmove_chk", "__strncpy_chk", "memcpy_s", "qmemcpy"):
    SINKS[n] = ("memory copy with variable length", 3)
for n in ("system", "popen", "_popen", "_wsystem", "_wpopen", "execl", "execlp", "execle", "execv", "execvp", "execve",
          "execvpe", "WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW", "CreateProcessA",
          "CreateProcessW", "doSystemCmd", "doSystem", "twsystem", "CsteSystem", "bstartcmd", "eval_cmd", "run_cmd",
          "_eval", "do_system", "exec_cmd"):
    SINKS[n] = ("command injection", 4)
for n in ("alloca", "_alloca"):
    SINKS[n] = ("stack exhaustion (variable alloca)", 3)
for n in ("malloc", "calloc", "realloc", "operator_new", "operator.new", "HeapAlloc", "LocalAlloc", "GlobalAlloc",
          "VirtualAlloc"):
    SINKS[n] = ("integer overflow in allocation size", 0)
for n in ("LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "dlopen"):
    SINKS[n] = ("library hijack / load from variable path", 0)
for n in ("fopen", "open", "open64", "fopen64", "CreateFileA", "CreateFileW", "unlink", "remove", "rename"):
    SINKS[n] = ("path traversal (file op on variable path)", 0)

FMT_IDX = {"printf": 0, "vprintf": 0, "wprintf": 0, "_printf": 0, "printk": 0, "fprintf": 1, "dprintf": 1, "vfprintf": 1,
           "fwprintf": 1, "syslog": 1, "vsyslog": 1, "err": 1, "errx": 1, "warn": 0, "warnx": 0, "sprintf": 1,
           "vsprintf": 1, "swprintf": 2, "vswprintf": 2, "wsprintfA": 1, "wsprintfW": 1, "snprintf": 2, "vsnprintf": 2,
           "_snprintf": 2, "_snwprintf": 2, "__printf_chk": 1, "__fprintf_chk": 2, "__syslog_chk": 2,
           "__sprintf_chk": 3, "__vsprintf_chk": 3, "__snprintf_chk": 4, "__vsnprintf_chk": 4, "scanf": 0, "vscanf": 0,
           "__isoc99_scanf": 0, "fscanf": 1, "sscanf": 1, "vsscanf": 1, "__isoc99_fscanf": 1, "__isoc99_sscanf": 1}
LEN_IDX = {"memcpy": 2, "memmove": 2, "bcopy": 2, "strncpy": 2, "strncat": 2, "wmemcpy": 2, "wcsncpy": 2,
           "RtlCopyMemory": 2, "CopyMemory": 2, "__memcpy_chk": 2, "__memmove_chk": 2, "__strncpy_chk": 2,
           "memcpy_s": 3, "qmemcpy": 2}
SOURCES = {"recv", "recvfrom", "recvmsg", "read", "fread", "fgets", "gets", "getline", "getdelim", "scanf", "fscanf",
           "__isoc99_scanf", "__isoc99_fscanf", "getenv", "secure_getenv", "SSL_read", "BIO_read", "mbedtls_ssl_read",
           "wolfSSL_read", "websGetVar", "websGetVarString", "nvram_get", "nvram_safe_get", "nvram_bufget",
           "acosNvramConfig_get", "cgiFormString", "cgiGetValue", "get_cgi", "httpGetEnv", "cJSON_Parse",
           "cJSON_GetObjectItem", "json_object_get_string", "json_tokener_parse", "ReadFile", "InternetReadFile",
           "WinHttpReadData", "WSARecv", "WSARecvFrom", "recv_line", "GetCommandLineA", "GetCommandLineW",
           "CommandLineToArgvW", "RegQueryValueExA", "RegQueryValueExW", "GetStringUTFChars", "uv_read_start",
           "find_val", "get_param", "getParameter", "httpd_get_param", "webcgi_get", "FCGX_GetParam", "FCGI_fgets",
           "mg_get_var", "json_get_value"}
NAME_SOURCE_HINT = re.compile(r"(?i)(^Java_|^main$|handler|handle_|parse|request|cgi|http|recv|packet|msg|cmd_|ioctl|rpc)")
CALL_RE = re.compile(r"(?<![\w.>])(\(\*)?([A-Za-z_][\w:.]*)\s*\(")
CONST_LABEL = re.compile(r"^&?(s_|u_|PTR_s_|PTR_u_|PTR_PTR_s_|\w+::s_)")
LOCAL_BUF = re.compile(r"^&?(local_|auStack_|acStack_|abStack_|uStack_|aStack_|stack0x)")


def split_args(line, i):
    """line[i] == '(' ; returns list of top-level args or None if unbalanced."""
    depth, cur, args, q = 0, [], [], None
    while i < len(line):
        ch = line[i]
        if q:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(line):
                cur.append(line[i + 1])
                i += 1
            elif ch == q:
                q = None
        elif ch in "\"'":
            q = ch
            cur.append(ch)
        elif ch == "(":
            depth += 1
            if depth > 1:
                cur.append(ch)
        elif ch == ")":
            depth -= 1
            if depth == 0:
                a = "".join(cur).strip()
                if a or args:
                    args.append(a)
                return args
            cur.append(ch)
        elif ch == "," and depth == 1:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    return None


def strip_cast(a):
    prev = None
    while prev != a:
        prev = a
        a = re.sub(r"^\(\s*(const\s+|unsigned\s+|signed\s+|struct\s+)*[A-Za-z_][\w:]*(\s*\*)*\s*\)\s*", "", a).strip()
    return a


def is_str_const(a):
    a = strip_cast(a)
    return bool(re.match(r'^(L|u|U|u8)?"', a) or CONST_LABEL.match(a))


def is_num_const(a):
    a = strip_cast(a)
    return bool(re.fullmatch(r"-?(0x[0-9a-fA-F]+|\d+)[uUlL]*", a)) or a.startswith("sizeof")


def parse_decomp(ddir):
    funcs = {}
    for fn in sorted(os.listdir(ddir)):
        if not fn.endswith(".c"):
            continue
        p = os.path.join(ddir, fn)
        try:
            lines = open(p, encoding="utf-8", errors="replace").read().split("\n")
        except OSError:
            continue
        name, addr, callers, callees = fn[:-2], fn.split("_")[0], [], []
        for ln in lines[:4]:
            m = re.match(r"// (.+) @ ([0-9a-fA-Fx:]+)", ln)
            if m:
                name, addr = m.group(1), m.group(2)
            elif ln.startswith("// called by:"):
                callers = [c.strip() for c in ln.split(":", 1)[1].split(",") if c.strip()]
            elif ln.startswith("// calls:"):
                callees = [c.strip() for c in ln.split(":", 1)[1].split(",") if c.strip()]
        funcs[name] = dict(addr=addr, file=p, lines=lines, callers=callers, callees=callees)
    return funcs


def base_name(n):
    n = n.split("::")[-1]
    return n[2:] if n.startswith("__") and n[2:] in SINKS and not n.endswith("_chk") else n


def native_sinks(s, ghidra_dirs):
    rows = []
    for gd in ghidra_dirs:
        ddir = os.path.join(gd, "decomp")
        funcs = parse_decomp(ddir)
        exports = set()
        try:
            for ln in open(os.path.join(gd, "exports.tsv"), encoding="utf-8", errors="replace").read().split("\n")[1:]:
                if ln:
                    exports.add(ln.split("\t")[0])
        except OSError:
            pass
        label = s.rel(gd)
        if gd.startswith(s.deep_dir + os.sep):
            label = "ghidra-deep/" + os.path.relpath(gd, s.deep_dir)
        elif os.path.dirname(gd) == s.root and os.path.basename(gd) == "ghidra":
            label = os.path.basename(s.target or s.root)
        reads_input = {n for n, f in funcs.items() if any(base_name(c) in SOURCES for c in f["callees"])}
        entryish = {n for n in funcs if NAME_SOURCE_HINT.search(n) or n in exports}

        def reach(n, depth=3):
            seen, frontier = {n}, [n]
            for _ in range(depth):
                nxt = []
                for x in frontier:
                    for c in funcs.get(x, {}).get("callers", []):
                        if c not in seen:
                            seen.add(c)
                            nxt.append(c)
                frontier = nxt
            return seen

        for fname, f in funcs.items():
            if base_name(fname) in SINKS:
                continue
            body = "\n".join(f["lines"])
            anc = reach(fname)
            src_here = fname in reads_input
            src_up = bool((anc - {fname}) & reads_input) or bool(anc & entryish)
            for ln_no, line in enumerate(f["lines"], 1):
                if line.startswith("//"):
                    continue
                for m in CALL_RE.finditer(line):
                    callee = base_name(m.group(2))
                    if callee not in SINKS:
                        continue
                    args = split_args(line, m.end() - 1)
                    if args is None:
                        continue
                    cat, score = SINKS[callee]
                    why = []
                    fi = FMT_IDX.get(callee)
                    if callee in FMT_IDX and fi < len(args):
                        fmt = args[fi]
                        if not is_str_const(fmt) and "scanf" not in callee:
                            cat, score = "format string (non-constant format)", 7
                            why.append("format arg is not a literal")
                        elif "scanf" in callee:
                            if re.search(r"%(s|\[)", fmt):
                                score = 6
                                why.append("%s/%[ without width")
                            else:
                                continue
                        elif callee in ("sprintf", "vsprintf", "swprintf", "wsprintfA", "wsprintfW", "__sprintf_chk"):
                            if re.search(r"%(-?\d*)s", fmt):
                                score = 5 + (1 if LOCAL_BUF.match(strip_cast(args[0])) else 0)
                                why.append("%s into fixed buffer" if LOCAL_BUF.match(strip_cast(args[0])) else "%s into buffer")
                            else:
                                continue
                        else:
                            continue
                    elif cat.startswith("buffer overflow (unbounded"):
                        if len(args) >= 2 and is_str_const(args[1]):
                            continue
                        if len(args) >= 1 and LOCAL_BUF.match(strip_cast(args[0])):
                            score += 1
                            why.append("dest is a stack buffer")
                    elif callee in LEN_IDX:
                        li = LEN_IDX[callee]
                        if li >= len(args) or is_num_const(args[li]):
                            continue
                        why.append(f"length={args[li][:40]}")
                        if LOCAL_BUF.match(strip_cast(args[0] if callee != "bcopy" else args[1])):
                            score += 1
                            why.append("dest is a stack buffer")
                    elif cat == "command injection":
                        if args and is_str_const(args[0]) and callee not in ("execl", "execlp", "execle", "execv",
                                                                            "execvp", "execve", "CreateProcessA",
                                                                            "CreateProcessW", "ShellExecuteA",
                                                                            "ShellExecuteW"):
                            continue
                        if callee.startswith("exec") and len(args) >= 2 and all(is_str_const(a) or a in ("0", "NULL") for a in args):
                            continue
                        score = 6
                        tgt = strip_cast(args[0]).lstrip("&") if args else ""
                        if tgt and re.search(r"(sn?printf|strcat|strcpy)\s*\(\s*(\([^)]*\)\s*)?&?" + re.escape(tgt) + r"\b[^;]*%s|strn?cat\s*\(\s*&?" + re.escape(tgt), body):
                            score += 2
                            why.append("command string built with %s/strcat in same function")
                    elif cat.startswith("integer overflow"):
                        if not args or not re.search(r"[*+]|<<", args[0]) or is_num_const(args[0]):
                            continue
                        score = 3
                        why.append(f"size={args[0][:40]}")
                    elif cat.startswith("library hijack"):
                        if args and is_str_const(args[0]):
                            lit = args[0]
                            if re.search(r'[/\\]|^&?s_[A-Za-z]:', lit) or callee == "dlopen":
                                continue
                            score = 3
                            why.append("bare DLL name - search-order hijack if the app dir/CWD is writable")
                        else:
                            score = 3
                            why.append("path not constant")
                    elif cat.startswith("path traversal"):
                        if not args or is_str_const(args[0]) or not (src_here or src_up):
                            continue
                        score = 2
                    elif cat.startswith("stack exhaustion"):
                        if not args or is_num_const(args[0]):
                            continue
                    if src_here:
                        score += 2
                        why.append("function reads input")
                    elif src_up:
                        score += 1
                        why.append("input/entry within 3 callers")
                    rows.append((min(score, 10), cat, callee, fname, f["addr"], label, s.rel(f["file"]), ln_no,
                                 line.strip()[:160], "; ".join(why)))
    rows.sort(key=lambda r: -r[0])
    with s.w("native_sinks.tsv") as fo:
        fo.write("score\tcategory\tsink\tfunction\taddr\tbinary\tfile\tline\tcode\twhy\n")
        for r in rows:
            fo.write("\t".join(str(x) for x in r) + "\n")
    verify = {
        "format string (non-constant format)": "Trace the format arg back to input (ghidra-query xrefs). PoC: %p.%p.%p / %n.",
        "command injection": "Find where the argument comes from (HTTP param/nvram/IPC). PoC payload: ;id> /tmp/x or $(sleep 5).",
        "buffer overflow (unbounded copy)": "Compare dest size (decomp locals) with max source length; is the source attacker-sized?",
        "buffer overflow / format string (sprintf)": "Is the %s argument attacker-controlled and longer than the buffer?",
        "memory copy with variable length": "Is the length attacker-controlled and unchecked vs dest size (or signed/truncated)?",
    }
    for r in rows:
        if r[0] >= 4:
            s.add(r[0], r[1], f"{r[5]}:{r[3]}@{r[4]}", f"{r[8]}  ({r[9]})" if r[9] else r[8],
                  verify.get(r[1], "Read the function; confirm attacker data reaches the call and what it controls."),
                  "native")
    c = collections.Counter(r[1] for r in rows)
    s.notes.append(f"native sinks: {len(rows)} call sites in {len(ghidra_dirs)} decompiled binar{'y' if len(ghidra_dirs) == 1 else 'ies'}"
                   + (" (" + ", ".join(f"{k}: {v}" for k, v in c.most_common(5)) + ")" if rows else ""))
    # network servers: import-level attack surface
    for gd in ghidra_dirs:
        try:
            imps = {ln.split("\t")[1] for ln in open(os.path.join(gd, "imports.tsv"), encoding="utf-8").read().split("\n")[1:] if "\t" in ln}
        except OSError:
            continue
        srv = imps & {"bind", "listen", "accept", "accept4", "WSAAccept", "CreateNamedPipeA", "CreateNamedPipeW",
                      "HttpReceiveHttpRequest", "RpcServerListen", "RpcServerRegisterIf", "ConnectNamedPipe"}
        if srv:
            s.surface.append(f"native  {s.rel(gd)}: server-side imports {', '.join(sorted(srv))} (network/IPC listener)")


# --------------------------------------------------------------------------------------------------- semgrep
LIB1 = {"android", "androidx", "kotlin", "kotlinx", "okhttp3", "okio", "retrofit2", "dagger", "javax", "java", "j$",
        "_COROUTINE", "bolts", "butterknife", "rx", "timber", "coil", "leakcanary", "hilt_aggregated_deps"}
LIB2 = {"com/google", "com/android", "com/facebook", "com/squareup", "com/bumptech", "com/fasterxml", "com/crashlytics",
        "com/airbnb", "com/amplitude", "com/appsflyer", "com/adjust", "com/onesignal", "com/braze", "com/mixpanel",
        "com/segment", "com/microsoft", "com/github", "com/jakewharton", "com/journeyapps", "com/yalantis",
        "com/getkeepsafe", "com/unity3d", "com/applovin", "com/ironsource", "com/mopub", "com/bytedance",
        "com/tencent", "com/huawei", "com/swmansion", "com/th3rdwave", "com/reactnativecommunity", "com/horcrux",
        "com/learnium", "com/oblador", "com/BV", "com/dylanvann", "com/lwansbrough", "com/brentvatne", "com/zoontek",
        "org/apache", "org/json", "org/intellij", "org/jetbrains", "org/greenrobot", "org/bouncycastle", "org/slf4j",
        "org/chromium", "org/webrtc", "org/reactivestreams", "org/joda", "org/xmlpull", "org/conscrypt",
        "org/spongycastle", "io/reactivex", "io/flutter", "io/sentry", "io/grpc", "io/realm", "io/branch",
        "io/invertase", "io/fabric", "io/netty", "io/jsonwebtoken", "net/sqlcipher", "ch/qos", "de/greenrobot",
        "me/leolin", "com/datadog", "com/newrelic", "com/instabug", "com/stripe", "com/paypal", "com/twitter",
        "com/linecorp", "com/kakao", "com/naver", "com/iterable", "com/clevertap", "com/zendesk", "com/intercom",
        "com/salesforce", "com/optimizely", "com/launchdarkly", "com/auth0", "com/okta", "com/scottyab",
        "io/card", "com/airship", "com/urbanairship", "com/localytics", "com/batch", "com/leanplum"}
LANG_DIRS = {"java": [("apk/jadx/sources", "java"), ("jadx/sources", "java")], "cs": [("dotnet", "cs")],
             "js": [("asar", "js"), ("js", "js"), ("hermes", "js"), ("extracted", "js")], "py": [("py/src", "py")]}


def find_manifest(s):
    for cand in ("apk/jadx/resources/AndroidManifest.xml", "jadx/resources/AndroidManifest.xml", "apk/apktool/AndroidManifest.xml"):
        p = os.path.join(s.root, cand)
        if os.path.exists(p):
            return p
    found = [p for p in walk(s.root, {".xml"}, 200000) if os.path.basename(p) == "AndroidManifest.xml"
             and "/build/" not in p and "/apktool/" not in p]
    found.sort(key=lambda p: (not p.endswith("src/main/AndroidManifest.xml"), len(p)))
    return found[0] if found else None


def first_party(s):
    """Package dirs (a/b/c) of the app's own code: manifest package + component classes (Android)."""
    fp = set()
    for man in filter(None, [find_manifest(s)]):
        try:
            root = ET.parse(man).getroot()
        except ET.ParseError:
            continue
        pkg = root.get("package", "")
        if pkg:
            fp.add(pkg.replace(".", "/"))
        app = root.find("application")
        for c in (app.iter() if app is not None else []):
            n = c.get(ANS + "name", "")
            if c.tag in ("application", "activity", "activity-alias", "service", "receiver", "provider") and n.count(".") >= 2:
                n = pkg + n if n.startswith(".") else n
                fp.add("/".join(n.split(".")[:-1]))
    # keep the shortest distinctive prefixes (>= 2 segments)
    fp = {p for p in fp if p.count("/") >= 1}
    return sorted(p for p in fp if not any(p != q and p.startswith(q + "/") for q in fp))


def is_lib_path(s, p):
    if any("/" + f + "/" in p for f in s.first_party):
        return False
    if "/node_modules/" in p or "/vendor/" in p:
        return True
    m = re.search(r"/sources/([^/]+)/([^/]+)/", p)
    return bool(m and (m.group(1) in LIB1 or f"{m.group(1)}/{m.group(2)}" in LIB2))


def java_app_dirs(src, all_code, fp=()):
    if all_code:
        return [src]
    out = []
    for d1 in sorted(os.listdir(src)):
        p1 = os.path.join(src, d1)
        if not os.path.isdir(p1) or d1 in LIB1:
            continue
        subs = [d for d in os.listdir(p1) if os.path.isdir(os.path.join(p1, d))]
        if d1 in ("com", "org", "io", "net", "de", "me", "ch", "co", "uk", "fr", "nl", "ru", "cn", "jp", "br", "in",
                  "us", "tv", "app", "dev", "ai", "ly", "it", "es", "se", "kr", "au", "ca", "pl", "eu"):
            out += [os.path.join(p1, d) for d in sorted(subs) if f"{d1}/{d}" not in LIB2]
        else:
            out.append(p1)
    for f in fp:  # first-party packages always scanned, even under a library-looking prefix (com/android/...)
        p = os.path.join(src, f)
        if os.path.isdir(p) and not any(p == o or p.startswith(o + "/") for o in out):
            out.append(p)
    return out


def semgrep(s, rules):
    sg = shutil.which("semgrep")
    if not sg:
        s.notes.append("semgrep: not installed (./setup.sh --only vuln_tools) - skipped")
        return []
    targets = []
    is_workdir = os.path.exists(os.path.join(s.root, "triage.txt"))
    if is_workdir:
        for sub in ("apk/jadx/sources", "jadx/sources"):
            p = os.path.join(s.root, sub)
            if os.path.isdir(p):
                targets += java_app_dirs(p, s.args.all_code, s.first_party)
        for sub in ("dotnet", "asar", "js", "hermes", "py/src", "extracted", "webcrack"):
            p = os.path.join(s.root, sub)
            if os.path.isdir(p):
                targets.append(p)
    else:
        targets = [s.root]
    if not targets:
        s.notes.append("semgrep: no decompiled source in this work dir - skipped")
        return []
    out_json = os.path.join(s.out, "semgrep.json")
    excl = [] if s.args.all_code else ["--exclude=node_modules", "--exclude=*.min.js", "--exclude=vendor",
                                       "--exclude=bower_components", "--exclude=jquery*.js"]
    cmd = [sg, "scan", "--metrics=off", "--disable-version-check", "--quiet", "--no-git-ignore", "--project-root",
           s.root, "--config", rules, "--json", "--output", out_json, "--timeout", "30", "--max-target-bytes",
           "8000000", "--jobs", str(max(1, (os.cpu_count() or 2) - 1))] + excl + [os.path.relpath(t, s.root) for t in targets]
    r = sh(cmd, timeout=s.args.semgrep_timeout, cwd=s.root)
    try:
        d = json.load(open(out_json))
    except (OSError, ValueError):
        s.notes.append(f"semgrep: failed (rc={r.returncode}) {r.stderr.strip()[-300:]}")
        return []
    res = d.get("results", [])
    sev_score = {"ERROR": 7, "WARNING": 5, "INFO": 2}
    cache = {}

    def src_line(x):  # semgrep OSS prints "requires login" instead of the matched code, so read it ourselves
        p = os.path.join(s.root, x["path"])
        if p not in cache:
            try:
                cache[p] = open(p, encoding="utf-8", errors="replace").read().split("\n")
            except OSError:
                cache[p] = []
        a, b = x["start"]["line"], x["end"]["line"]
        return " ".join(ln.strip() for ln in cache[p][a - 1:min(b, a + 2)])[:200]
    with s.w("semgrep.tsv") as f:
        f.write("severity\trule\tfile\tline\tcode\n")
        for x in sorted(res, key=lambda x: -sev_score.get(x["extra"].get("severity"), 0)):
            rule = x["check_id"].split(".")[-1]
            code = src_line(x)
            f.write(f"{x['extra'].get('severity')}\t{rule}\t{x['path']}\t{x['start']['line']}\t{code}\n")
    for x in res:
        rule = x["check_id"].split(".")[-1]
        md = x["extra"].get("metadata", {})
        code = src_line(x)[:160]
        s.add(sev_score.get(x["extra"].get("severity"), 2), f"{rule} ({md.get('cwe', '').split(':')[0]})",
              f"{x['path']}:{x['start']['line']}", f"{x['extra'].get('message', '')} | {code}", md.get("verify", ""), "semgrep")
    nerr = len(d.get("errors", []))
    s.notes.append(f"semgrep: {len(res)} hits in {len(d.get('paths', {}).get('scanned', []))} files"
                   f"{f' ({nerr} parse errors/timeouts - normal for decompiled code)' if nerr else ''}"
                   f"{'' if s.args.all_code else '; third-party library packages skipped (--all-code to include)'}")
    return res


# --------------------------------------------------------------------------------------------------- secrets
SECRET_SCORE = [(r"private-key", 8), (r"aws-access|aws-secret", 8), (r"stripe-access|stripe", 7), (r"github", 8),
                (r"gitlab", 8), (r"slack-(bot|user|app|legacy|config)", 7), (r"slack-webhook", 5), (r"twilio", 6),
                (r"sendgrid|mailgun|mailchimp", 6), (r"azure|ms-teams", 6), (r"gcp-service-account", 8),
                (r"gcp-api-key", 3), (r"jwt", 4), (r"facebook|twitter", 4), (r"heroku|digitalocean|doppler|okta", 7),
                (r"openai|anthropic|huggingface", 7), (r"generic-api-key", 3), (r"", 4)]
SECRET_VERIFY = {
    "gcp-api-key": "Google API keys ship in most apps; only reportable if unrestricted for a paid/sensitive API (check with the program's rules before calling any API).",
    "private-key": "What is the key for (TLS client cert, JWT signing, SSH, code signing)? Identify the counterpart from nearby code.",
    "jwt": "Decode it (base64) - is it a long-lived token for a real user/service account?",
    "generic-api-key": "Often false positive; check the variable name and where it's sent (endpoints.txt).",
}


def mask(v):
    v = v.strip()
    return v[:6] + "..." + v[-2:] if len(v) > 12 else v[:3] + "..."


def dump_strings(s, bins):
    """Native binaries are not text: save their strings so gitleaks / endpoints / components can read them."""
    sdir = os.path.join(s.out, "strings")
    os.makedirs(sdir, exist_ok=True)
    for p in bins[:300]:
        r = s.rel(p)
        with open(os.path.join(sdir, re.sub(r"[^\w.-]", "_", os.path.basename(r) if os.path.isabs(r) else r) + ".txt"), "w") as f:
            subprocess.run(["strings", "-a", "-n", "6", p], stdout=f, stderr=subprocess.DEVNULL)


COMPONENTS = [
    (r"OpenSSL (\d+\.\d+\.\d+[a-z]?)", "OpenSSL"), (r"libcurl/(\d+\.\d+\.\d+)", "curl"), (r"curl/(\d+\.\d+\.\d+)", "curl"),
    (r"BusyBox v(\d+\.\d+(?:\.\d+)?)", "BusyBox"), (r"dropbear_(\d{4}\.\d+)", "Dropbear"), (r"OpenSSH_(\d+\.\d+p?\d*)", "OpenSSH"),
    (r"lighttpd/(\d+\.\d+\.\d+)", "lighttpd"), (r"nginx/(\d+\.\d+\.\d+)", "nginx"), (r"dnsmasq-(\d+\.\d+)", "dnsmasq"),
    (r"miniupnpd[/ ](\d+\.\d+(?:\.\d+)?)", "miniupnpd"), (r"Linux version (\d+\.\d+\.\d+)", "Linux kernel"),
    (r"uClibc[- ](\d+\.\d+\.\d+)", "uClibc"), (r"GoAhead[- /]?(?:Webs/)?(\d+\.\d+\.\d+)", "GoAhead"),
    (r"Boa/(\d+\.\d+\.\d+)", "Boa"), (r"libpng version (\d+\.\d+\.\d+)", "libpng"),
    (r"(?:deflate|inflate) (\d+\.\d+\.\d+(?:\.\d+)?) Copyright", "zlib"), (r"SQLite version (\d+\.\d+\.\d+)", "SQLite"),
    (r"mbed TLS (\d+\.\d+\.\d+)", "mbedTLS"), (r"wolfSSL (\d+\.\d+\.\d+)", "wolfSSL"), (r"libxml2[- ](\d+\.\d+\.\d+)", "libxml2"),
    (r"Expat_(\d+\.\d+\.\d+)|expat_(\d+\.\d+\.\d+)", "expat"), (r"libjpeg-turbo version (\d+\.\d+\.\d+)", "libjpeg-turbo"),
    (r"FFmpeg version (\S+)|Lavc(\d+\.\d+\.\d+)", "FFmpeg"), (r"WebKit/(\d+\.\d+(?:\.\d+)*)", "WebKit"),
    (r"Chrome/(\d+\.\d+\.\d+\.\d+) .*Electron/(\d+\.\d+\.\d+)", "Chromium/Electron"), (r"Electron/(\d+\.\d+\.\d+)", "Electron"),
    (r"Mongoose/(\d+\.\d+)|mongoose (\d+\.\d+)", "Mongoose"), (r"PHP/(\d+\.\d+\.\d+)", "PHP"), (r"Samba (\d+\.\d+\.\d+)", "Samba"),
]


def components(s):
    rg = shutil.which("rg")
    sdir = os.path.join(s.out, "strings")
    if not rg or not os.path.isdir(sdir):
        return
    found = collections.defaultdict(set)
    pat = "|".join(f"(?:{p})" for p, _ in COMPONENTS)
    r = sh([rg, "-o", "-N", "--no-heading", "-a", "-e", pat, sdir], timeout=300)
    for ln in r.stdout.splitlines():
        f, _, txt = ln.partition(":")
        for p, name in COMPONENTS:
            m = re.search(p, txt)
            if m:
                ver = next(g for g in m.groups() if g) if any(m.groups()) else txt
                found[(name, ver)].add(os.path.basename(f)[:-4])
                break
    if not found:
        return
    with s.w("components.txt") as fo:
        fo.write("# bundled components with version banners -> check each against CVE databases (n-days in embedded copies\n"
                 "# are often unpatched). Search: '<component> <version> CVE'. Confirm the vulnerable code path is reachable.\n")
        for (name, ver), files in sorted(found.items()):
            fo.write(f"{name:<18} {ver:<14} {', '.join(sorted(files)[:4])}\n")
    s.notes.append("components: " + ", ".join(f"{n} {v}" for n, v in sorted(found)[:12]) + " (components.txt: check for n-day CVEs)")


def secrets(s, bins):
    gl = shutil.which("gitleaks")
    if not gl:
        s.notes.append("secrets: gitleaks not installed (./setup.sh --only vuln_tools) - skipped")
        return
    rep = os.path.join(s.out, "gitleaks.json")
    cfg = os.path.join(REPO, "rules", "gitleaks.toml")
    cmd = [gl, "dir", s.root, "--no-banner", "--exit-code", "0", "--report-format", "json", "--report-path", rep,
           "--max-target-megabytes", "50", "--log-level", "error"] + (["--config", cfg] if os.path.exists(cfg) else [])
    hits = []
    for i, root in enumerate(p for p in s.scan_roots if os.path.isdir(p)):
        rp = rep if i == 0 else rep.replace(".json", f".{i}.json")
        c = list(cmd)
        c[2], c[c.index(rep)] = root, rp
        r = sh(c, timeout=s.args.secrets_timeout)
        try:
            hits += json.load(open(rp))
        except (OSError, ValueError):
            s.notes.append(f"secrets: gitleaks failed on {root} rc={r.returncode} {r.stderr.strip()[-200:]}")
    seen = set()
    rows = []
    for h in hits:
        key = (h.get("RuleID"), h.get("Secret"))
        if key in seen:
            continue
        seen.add(key)
        rid = h.get("RuleID", "")
        score = next(sc for pat, sc in SECRET_SCORE if re.search(pat, rid))
        f = h.get("File", "")
        if re.search(r"/(androidx|kotlin|com/google|okhttp3|org/apache|node_modules)/", f):
            score -= 2
        rows.append((score, rid, mask(h.get("Secret", "")), s.rel(f), h.get("StartLine", 0)))
    rows.sort(key=lambda r: -r[0])
    with s.w("secrets.tsv") as fo:
        fo.write("score\trule\tsecret(masked)\tfile\tline\n")
        for r in rows:
            fo.write("\t".join(map(str, r)) + "\n")
    for r in rows:
        s.add(r[0], f"hardcoded secret: {r[1]}", f"{r[3]}:{r[4]}", f"{r[2]} (full value in vuln/gitleaks.json)",
              SECRET_VERIFY.get(r[1], "Identify the service and the privilege. Never use a live credential without the program's explicit permission - report it with the location instead."),
              "secrets")
    s.notes.append(f"secrets: {len(rows)} unique ({', '.join(f'{k}: {v}' for k, v in collections.Counter(r[1] for r in rows).most_common(6))})")


# ------------------------------------------------------------------------------------------------- endpoints
URL_RE = r"(?:https?|wss?|ftp)://[A-Za-z0-9._~:@!$&'*+,;=%/?#\[\]-]{3,300}"
NOISE_HOST = re.compile(r"(^|\.)(schemas\.android\.com|w3\.org|apache\.org|xml\.org|xmlpull\.org|example\.(com|org|net)|"
                        r"ns\.adobe\.com|purl\.org|openxmlformats\.org|microsoft\.com/winfx|schemas\.microsoft\.com|"
                        r"json-schema\.org|www\.apple\.com/DTDs|developer\.android\.com|developer\.apple\.com|"
                        r"github\.com/(square|google|facebook|ReactiveX)|goo\.gl|unicode\.org|ietf\.org|"
                        r"mozilla\.org|gnu\.org|opensource\.org|creativecommons\.org|reactjs\.org|nodejs\.org|"
                        r"localhost$|schema\.org|ogp\.me|iana\.org|oasis-open\.org|jquery\.com|momentjs\.com|"
                        r"googlesource\.com|chromium\.org|fb\.me|bugs\.webkit\.org|stackoverflow\.com|"
                        r"digicert\.com|verisign\.com|symantec\.com|globalsign\.(com|net)|letsencrypt\.org|"
                        r"usertrust\.com|sectigo\.com|comodoca\.com|entrust\.net|godaddy\.com|thawte\.com|"
                        r"apple\.com/(appleca|certificateauthority)|pki\.goog|crl\.|ocsp\.)")
CLOUD = [(r"[\w.-]*\.s3[\w.-]*\.amazonaws\.com|s3://[\w.-]+", "AWS S3 bucket"),
         (r"[\w-]+\.firebaseio\.com|[\w-]+\.firebasedatabase\.app", "Firebase Realtime DB"),
         (r"[\w-]+\.appspot\.com|storage\.googleapis\.com/[\w.-]+|gs://[\w.-]+", "GCP storage/App Engine"),
         (r"[\w-]+\.blob\.core\.windows\.net|[\w-]+\.(file|queue|table)\.core\.windows\.net", "Azure storage"),
         (r"[\w-]+\.supabase\.co", "Supabase"), (r"[\w-]+\.execute-api\.[\w-]+\.amazonaws\.com", "AWS API Gateway"),
         (r"[\w-]+\.cloudfunctions\.net|[\w-]+\.run\.app", "GCP functions/run"),
         (r"[\w.-]+\.digitaloceanspaces\.com", "DO Spaces"), (r"[\w-]+\.azurewebsites\.net", "Azure web app")]
INTERESTING_HOST = re.compile(r"(?i)(^|[.-])(dev|stag(e|ing)?|test|qa|uat|internal|corp|admin|debug|sandbox|preprod|beta|int)\d*[.-]")


def endpoints(s):
    rg = shutil.which("rg")
    globs = ["!**/proj.rep/**", "!**/apktool/smali*/**", "!*.png", "!*.jpg", "!*.so", "!*.dex", "!*.gz", "!*.zip"]
    hits = []
    if rg:
        cmd = [rg, "-o", "--no-heading", "-N", "-I", "--with-filename", "-a", "--max-columns", "2000", "-e", URL_RE]
        for g in globs:
            cmd += ["-g", g]
        r = sh(cmd + [p for p in s.scan_roots if os.path.isdir(p)], timeout=600)
        for ln in r.stdout.splitlines():
            if "/vuln/" in ln and "/vuln/strings/" not in ln:
                continue
            m = re.match(r"^(.*?):((?:https?|wss?|ftp)://.*)$", ln)
            if m:
                hits.append((m.group(2), m.group(1)))
    urls = collections.OrderedDict()
    for u, f in hits:
        u = u.rstrip(".,;:'\")]}\\")
        u = re.split(r"\\[nrt\"']|\\x", u)[0]
        if len(u) < 10:
            continue
        urls.setdefault(u, f)
    by_host = collections.defaultdict(list)
    for u, f in urls.items():
        host = re.sub(r"^[a-z]+://", "", u).split("/")[0].split("?")[0].split(":")[0].lower()
        if not host or NOISE_HOST.search(host + "/" + "/".join(u.split("/")[3:5])) or "%" in host or "{" in host:
            continue
        by_host[host].append((u, f, is_lib_path(s, f)))
    with s.w("urls.txt") as fo:
        for u, f in urls.items():
            fo.write(f"{u}\t{s.rel(f)}\n")
    # api-ish relative paths and GraphQL operations from code
    paths, gql = collections.Counter(), collections.Counter()
    if rg:
        r = sh([rg, "-o", "-N", "-I", "--no-filename", "-a", "-g", "!**/proj.rep/**", "-g", "!**/vuln/**", "-e",
                r"[\"'`](/(?:api|v[0-9]|rest|graphql|gql|rpc|internal|admin|auth|oauth2?|user|users|account|accounts)(?:/[A-Za-z0-9_.{}:$-]*)*)[\"'`?]",
                "-r", "$1", *[p for p in s.scan_roots if os.path.isdir(p)]], timeout=600)
        paths.update(r.stdout.splitlines())
        r = sh([rg, "-o", "-N", "-I", "--no-filename", "-a", "-g", "!**/proj.rep/**", "-g", "!**/vuln/**", "-e",
                r"\b(query|mutation|subscription)\s+([A-Z]\w+)\s*[({]", "-r", "$1 $2", *[p for p in s.scan_roots if os.path.isdir(p)]], timeout=600)
        gql.update(r.stdout.splitlines())
    cloud = collections.defaultdict(set)
    for u in list(urls) + [h for h in by_host]:
        for pat, kind in CLOUD:
            for m in re.finditer(pat, u):
                cloud[kind].add(m.group(0))
    if rg:  # bare bucket names in resources (e.g. google_storage_bucket, firebase_database_url)
        r = sh([rg, "-o", "-N", "-I", "--no-filename", "-a", "-g", "!**/proj.rep/**", "-g", "!**/vuln/**", "-e",
                "|".join(p for p, _ in CLOUD[:4]), *[p for p in s.scan_roots if os.path.isdir(p)]], timeout=300)
        for m in set(r.stdout.splitlines()):
            for pat, kind in CLOUD:
                if re.fullmatch(pat, m):
                    cloud[kind].add(m)
    own = {h: lst for h, lst in by_host.items() if not all(lib for _, _, lib in lst)}
    lib_only = {h: lst for h, lst in by_host.items() if h not in own}
    with s.w("endpoints.txt") as fo:
        fo.write(f"# {len(by_host)} hosts ({len(own)} referenced by app code, {len(lib_only)} only by third-party SDKs), "
                 f"{len(urls)} unique URLs (all: urls.txt). Noise hosts (schemas, CAs, docs) removed.\n")
        for title, group in (("app code", own), ("third-party SDK code only", lib_only)):
            fo.write(f"\n## hosts referenced by {title}\n")
            for host, lst in sorted(group.items(), key=lambda kv: -len(kv[1])):
                fo.write(f"\n{host}  ({len(lst)})\n")
                for u, f, _ in sorted(lst, key=lambda x: x[2])[:8]:
                    fo.write(f"    {u[:200]}    <- {s.rel(f)}\n")
        if cloud:
            fo.write("\n# cloud storage / serverless\n")
            for kind, vals in cloud.items():
                fo.write(f"{kind}: {', '.join(sorted(vals)[:20])}\n")
        if paths:
            fo.write("\n# API-looking path literals (combine with the hosts above)\n")
            for p, n in paths.most_common(150):
                fo.write(f"    {p}  x{n}\n")
        if gql:
            fo.write("\n# GraphQL operations\n")
            for p, n in gql.most_common(100):
                fo.write(f"    {p}  x{n}\n")
    for kind, vals in cloud.items():
        for v in sorted(vals)[:10]:
            s.add(4, f"cloud asset: {kind}", v, "referenced by the app",
                  "In scope? Then check for unauthenticated read/list/write (e.g. Firebase <url>/.json, S3 ListBucket) - only with the program's permission.",
                  "endpoints")
    for host, lst in own.items():
        lst = [(u, f) for u, f, lib in lst if not lib]
        if INTERESTING_HOST.search(host):
            s.add(3, "non-production host", host, lst[0][0][:150],
                  "Staging/dev/internal hosts are often weaker (debug endpoints, default creds). Check program scope first.", "endpoints")
        if any(u.startswith("http://") for u, _ in lst) and not re.match(r"^(\d+\.){3}\d+$|^10\.|^192\.168\.", host):
            u = next(u for u, _ in lst if u.startswith("http://"))
            s.add(2, "cleartext HTTP endpoint", host, u[:150],
                  "Is sensitive data or an update/download fetched over it? Check network security config / ATS.", "endpoints")
    s.notes.append(f"endpoints: {len(by_host)} hosts, {len(urls)} URLs, {len(paths)} API paths, {len(gql)} GraphQL ops, "
                   f"cloud: {', '.join(f'{k}({len(v)})' for k, v in cloud.items()) or '-'}")


# ------------------------------------------------------------------------------------------ platform checks
ANS = "{http://schemas.android.com/apk/res/android}"


def android(s):
    man = find_manifest(s)
    if not man:
        return
    try:
        root = ET.parse(man).getroot()
    except ET.ParseError as e:
        s.notes.append(f"android: manifest parse error {e}")
        return
    res_dir = os.path.join(os.path.dirname(man), "res")
    pkg = root.get("package", "")
    sdk = root.find("uses-sdk")
    target = int(sdk.get(ANS + "targetSdkVersion", "0") or 0) if sdk is not None else 0
    app = root.find("application")
    if app is None:
        return
    srcs = [os.path.join(os.path.dirname(os.path.dirname(man)), "sources"),   # jadx layout
            os.path.join(os.path.dirname(man), "java"), os.path.join(os.path.dirname(man), "kotlin")]  # gradle layout
    if not pkg:  # AGP 7+: namespace lives in build.gradle
        for g in ("build.gradle", "build.gradle.kts"):
            gp = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(man))), g)
            if os.path.exists(gp):
                m = re.search(r"""namespace\s*=?\s*["']([\w.]+)""", open(gp, encoding="utf-8", errors="replace").read())
                pkg = m.group(1) if m else pkg
    if not target:  # gradle source tree
        for g in ("build.gradle", "build.gradle.kts"):
            gp = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(man))), g)
            if os.path.exists(gp):
                m = re.search(r"targetSdk(?:Version)?\s*=?\s*\(?(\d+)", open(gp, encoding="utf-8", errors="replace").read())
                target = int(m.group(1)) if m else target

    def cls_file(name):
        if name.startswith("."):
            name = pkg + name
        elif "." not in name:
            name = pkg + "." + name
        for sd in srcs:
            for ext in (".java", ".kt"):
                p = os.path.join(sd, name.replace(".", "/") + ext)
                if os.path.exists(p):
                    return p
        return None

    def flag(k, v, score, what, verify):
        if app.get(ANS + k) == v:
            s.add(score, what, "AndroidManifest.xml <application>", f'android:{k}="{v}"', verify, "android")
    flag("debuggable", "true", 7, "debuggable release build",
         "run-as / jdwp attach gives code exec in the app sandbox from adb; usually accepted for production builds.")
    flag("usesCleartextTraffic", "true", 2, "cleartext traffic allowed", "Find an http:// endpoint carrying sensitive data (endpoints.txt).")
    if app.get(ANS + "allowBackup") != "false" and target < 31:
        s.add(2, "allowBackup", "AndroidManifest.xml", f"allowBackup={app.get(ANS + 'allowBackup')} targetSdk={target}",
              "adb backup extracts app data (tokens in shared_prefs?). Many programs rate this informational.", "android")
    perms = {p.get(ANS + "name"): p.get(ANS + "protectionLevel", "normal") for p in root.findall("permission")}
    # network security config
    nsc = app.get(ANS + "networkSecurityConfig")
    if nsc:
        p = os.path.join(res_dir, "xml", nsc.split("/")[-1] + ".xml")
        try:
            t = open(p, encoding="utf-8").read()
            if re.search(r'cleartextTrafficPermitted="true"', t):
                doms = re.findall(r"<domain[^>]*>([^<]+)</domain>", t)
                s.add(3, "NSC allows cleartext", s.rel(p), "cleartextTrafficPermitted=true " + ",".join(doms[:6]),
                      "Which data goes to these domains over HTTP?", "android")
            if re.search(r'<certificates\s+src="user"', t):
                s.add(2, "NSC trusts user CAs", s.rel(p), 'certificates src="user"',
                      "Makes MITM easy (helps your testing); rarely reportable alone.", "android")
            if "<pin-set" in t:
                s.notes.append("android: certificate pinning configured in NSC (bypass needed for traffic testing)")
        except OSError:
            pass
    lines = []
    for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
        for c in app.findall(tag):
            name = c.get(ANS + "name", "")
            exp = c.get(ANS + "exported")
            filters = c.findall("intent-filter")
            implicit = exp is None and filters and (target < 31) and tag != "provider"
            if tag == "provider" and exp is None and target < 17:
                implicit = True
            if not (exp == "true" or implicit):
                if tag == "provider" and c.get(ANS + "grantUriPermissions") == "true":
                    lines.append(f"provider(grantable) {name} authorities={c.get(ANS + 'authorities')}")
                    fp = c.find("meta-data")
                    if fp is not None and "FileProvider" in name + str(c.get(ANS + "name")):
                        res = (fp.get(ANS + "resource") or "").split("/")[-1]
                        try:
                            t = open(os.path.join(res_dir, "xml", res + ".xml"), encoding="utf-8").read()
                            if re.search(r"<root-path|<external-path[^>]*path=\"(\.|/)?\"", t):
                                s.add(4, "FileProvider exposes broad paths", f"res/xml/{res}.xml", re.sub(r"\s+", " ", t)[:200],
                                      "Combine with intent redirection / grant flags to read arbitrary app or external files.", "android")
                        except OSError:
                            pass
                continue
            perm = c.get(ANS + "permission") or c.get(ANS + "readPermission") or ""
            plevel = perms.get(perm, "system/other" if perm else "")
            acts, links, browsable = [], [], False
            for f in filters:
                acts += [x.get(ANS + "name", "").replace("android.intent.action.", "") for x in f.findall("action")]
                browsable |= any(x.get(ANS + "name", "").endswith("BROWSABLE") for x in f.findall("category"))
                auto = f.get(ANS + "autoVerify") == "true"
                for d in f.findall("data"):
                    sch, host = d.get(ANS + "scheme"), d.get(ANS + "host")
                    pth = d.get(ANS + "path") or d.get(ANS + "pathPrefix") or d.get(ANS + "pathPattern") or ""
                    if sch or host:
                        links.append(f"{sch or '*'}://{host or '*'}{pth}{' [autoVerify]' if auto else ''}")
            f = cls_file(name)
            unprotected = not perm or plevel in ("normal", "dangerous")
            desc = (f"{tag:<9} {name}{' perm=' + perm + '(' + plevel + ')' if perm else ''}"
                    f"{' actions=' + ','.join(sorted(set(acts))[:5]) if acts else ''}"
                    f"{' deeplinks=' + ','.join(sorted(set(links))[:6]) if links else ''}"
                    f"{' authorities=' + str(c.get(ANS + 'authorities')) if tag == 'provider' else ''}"
                    f"  -> {s.rel(f) if f else '(class not found)'}")
            lines.append(desc)
            if tag == "provider" and unprotected:
                s.add(5, "exported ContentProvider", name, desc,
                      "query()/openFile()/call() reachable by any app: test SQLi in selection/projection, path traversal in openFile, data leaks.",
                      "android")
            elif unprotected and tag in ("activity", "activity-alias") and not browsable and "MAIN" not in acts:
                own = f is not None and not is_lib_path(s, "/sources/" + s.rel(f).split("/sources/")[-1])
                s.add(3 if own else 1, "exported activity", name, desc,
                      "Any app can start it directly: does it show post-login screens or act on extras without re-checking auth?",
                      "android")
            elif unprotected and (browsable or tag in ("service", "receiver")):
                s.add(3, f"exported {tag}{' (BROWSABLE deep link)' if browsable else ''}", name, desc,
                      "Map the extras/URI params it reads (getIntent().get*) and follow them to WebView, file, intent, auth or payment logic.",
                      "android")
    s.surface += ["android " + x for x in lines]
    # correlate code findings with exported entry classes
    exported_files = {re.sub(r".*-> ", "", ln) for ln in lines}
    for c in s.cands:
        if c["module"] == "semgrep" and c["where"].split(":")[0] in exported_files:
            c["score"] = min(10, c["score"] + 2)
            c["evidence"] += "  [in an EXPORTED component]"
    # strings.xml cloud config
    sx = os.path.join(res_dir, "values", "strings.xml")
    if os.path.exists(sx):
        t = open(sx, encoding="utf-8", errors="replace").read()
        for k in ("firebase_database_url", "google_storage_bucket", "google_api_key", "google_app_id", "gcm_defaultSenderId",
                  "default_web_client_id", "project_id"):
            m = re.search(rf'name="{k}">([^<]+)<', t)
            if m:
                s.surface.append(f"android config {k}={m.group(1)}")
    s.notes.append(f"android: package={pkg} targetSdk={target}; {len(lines)} exported/grantable components (attack_surface.txt)")


def ios(s):
    apps = []
    for dp, dns, fns in os.walk(s.root):
        dns[:] = [d for d in dns if not skip_dir(dp, d, dns)]
        if dp.endswith(".app") and "Info.plist" in fns and os.sep + "Payload" + os.sep in dp + os.sep:
            apps.append(dp)
    for a in apps[:3]:
        try:
            pl = plistlib.load(open(os.path.join(a, "Info.plist"), "rb"))
        except Exception:  # noqa: BLE001
            continue
        rel = s.rel(a)
        for ut in pl.get("CFBundleURLTypes", []):
            for sch in ut.get("CFBundleURLSchemes", []):
                s.surface.append(f"ios {rel}: URL scheme {sch}://  (any app/web page can open it; find handler: application:openURL:)")
                s.add(3, "iOS custom URL scheme", rel, f"{sch}://",
                      "Grep the binary/strings for the scheme's paths; check what parameters are trusted (tokens, URLs loaded in WebView).", "ios")
        ats = pl.get("NSAppTransportSecurity", {})
        if ats.get("NSAllowsArbitraryLoads"):
            s.add(3, "ATS disabled (NSAllowsArbitraryLoads)", rel, "NSAllowsArbitraryLoads=true", "Find an http:// endpoint with sensitive data.", "ios")
        for dom, cfg in (ats.get("NSExceptionDomains") or {}).items():
            if cfg.get("NSExceptionAllowsInsecureHTTPLoads") or cfg.get("NSTemporaryExceptionAllowsInsecureHTTPLoads"):
                s.surface.append(f"ios {rel}: ATS exception allows HTTP for {dom}")
        exe = os.path.join(a, pl.get("CFBundleExecutable", ""))
        if os.path.isfile(exe):
            data = open(exe, "rb").read()
            for m in re.finditer(rb"<\?xml[^>]*>\s*<!DOCTYPE plist.{0,20000}?</plist>", data, re.S):
                blob = m.group(0)
                if b"application-identifier" in blob or b"associated-domains" in blob:
                    try:
                        ent = plistlib.loads(blob)
                    except Exception:  # noqa: BLE001
                        continue
                    for d in ent.get("com.apple.developer.associated-domains", []):
                        s.surface.append(f"ios {rel}: associated domain {d} (universal links -> check /.well-known/apple-app-site-association paths)")
                    for k in ("get-task-allow",):
                        if ent.get(k):
                            s.add(4, "debuggable iOS build (get-task-allow)", rel, k, "Development-signed build.", "ios")
                    break
            s.notes.append(f"ios: {os.path.basename(a)} executable {s.rel(exe)} -> ghidra-analyze it, then vuln-scan again")
        s.surface.append(f"ios {rel}: bundle id {pl.get('CFBundleIdentifier')} version {pl.get('CFBundleShortVersionString')}")


def electron(s):
    for pj in list(walk(s.root, {".json"}, 20000)):
        if os.path.basename(pj) != "package.json" or "node_modules" in pj:
            continue
        try:
            d = json.load(open(pj, encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(d, dict) or "main" not in d:
            continue
        deps = {**d.get("dependencies", {}), **d.get("devDependencies", {})}
        ver = deps.get("electron")
        s.surface.append(f"js {s.rel(pj)}: name={d.get('name')} version={d.get('version')} main={d.get('main')}"
                         + (f" electron={ver}" if ver else ""))
        if ver:
            m = re.match(r"\D*(\d+)", ver)
            if m and int(m.group(1)) < 28:
                s.add(4, "outdated Electron/Chromium", s.rel(pj), f"electron {ver}",
                      "Old Chromium n-days (renderer RCE) become reachable if remote content is loaded - check sandbox/contextIsolation.", "electron")
    rg = shutil.which("rg")
    if rg:
        r = sh([rg, "-n", "--no-heading", "-g", "!**/node_modules/**", "-g", "!**/vuln/**", "-e",
                r"setAsDefaultProtocolClient\(|registerFileProtocol\(|protocol\.handle\(|registerSchemesAsPrivileged|createServer\(|\.listen\(\d+|new WebSocketServer|ipcMain\.(handle|on)\(",
                s.root], timeout=300)
        for ln in r.stdout.splitlines()[:60]:
            p, _, rest = ln.partition(":")
            s.surface.append(f"js {s.rel(p)}:{rest[:180]}")


def generic_surface(s):
    rg = shutil.which("rg")
    if not rg:
        return
    pats = {
        "dotnet": r"new (HttpListener|TcpListener|NamedPipeServerStream|ServiceHost|IpcServerChannel|TcpServerChannel)\b|\"URL Protocol\"|UseUrls\(",
        "java": r"new (ServerSocket|LocalServerSocket|NanoHTTPD)\b|extends NanoHTTPD|@JavascriptInterface",
        "py": r"socketserver\.|HTTPServer\(|@app\.route\(|\.bind\(\(|websockets\.serve\(",
    }
    for lang, pat in pats.items():
        r = sh([rg, "-n", "--no-heading", "-g", "!**/proj.rep/**", "-g", "!**/vuln/**", "-g", "!**/androidx/**",
                "-g", "!**/com/google/**", "-e", pat, s.root], timeout=300)
        for ln in r.stdout.splitlines()[:40]:
            p, _, rest = ln.partition(":")
            s.surface.append(f"{lang} {s.rel(p)}:{rest[:180].strip()}")


def firmware(s, bins):
    roots = set()
    for dp, dns, fns in os.walk(s.root):
        dns[:] = [d for d in dns if not skip_dir(dp, d, dns)]
        if os.path.basename(dp) == "etc" and ("passwd" in fns or "shadow" in fns or "inittab" in fns):
            roots.add(os.path.dirname(dp))
    for r in sorted(roots)[:4]:
        rel = s.rel(r)
        for fn in ("etc/shadow", "etc/passwd", "etc/shadow-", "etc_ro/shadow", "etc_ro/passwd"):
            p = os.path.join(r, fn)
            if os.path.isfile(p):
                for ln in open(p, encoding="utf-8", errors="replace"):
                    parts = ln.strip().split(":")
                    if len(parts) > 1 and parts[1] not in ("", "x", "*", "!", "!!", "*LK*") and not parts[1].startswith("!"):
                        s.add(6, "hardcoded password hash", f"{rel}/{fn}", f"{parts[0]}:{parts[1][:20]}...",
                              "Crack it offline (hashcat/john). Shared hash across devices = default credential for telnet/ssh/web.", "firmware")
                    elif len(parts) > 1 and parts[1] == "" and parts[0] == "root":
                        s.add(6, "empty root password", f"{rel}/{fn}", ln.strip()[:60], "Login without password on any exposed console/service?", "firmware")
        init_hits = sh(["rg", "-n", "--no-heading", "-e", r"\b(telnetd|utelnetd|dropbear|sshd|tftpd|httpd|uhttpd|lighttpd|boa|goahead|mini_httpd|miniupnpd|dnsmasq|smbd|adbd)\b",
                        os.path.join(r, "etc")], timeout=60).stdout.splitlines()
        for ln in init_hits[:20]:
            s.surface.append(f"firmware {s.rel(ln.split(':')[0])}: {ln.split(':', 2)[-1].strip()[:150]}")
            if re.search(r"telnetd|adbd|tftpd", ln):
                s.add(4, "debug/legacy service started at boot", s.rel(ln.split(":")[0]), ln.split(":", 2)[-1].strip()[:150],
                      "Is it reachable on LAN/WAN by default? Combine with the hardcoded hash above.", "firmware")
        web = [p for p in walk(r) if re.search(r"\.(cgi|asp|php|lua)$|/(cgi-bin|www|htdocs|web)/", p)]
        if web:
            s.surface.append(f"firmware {rel}: {len(web)} web files (e.g. {', '.join(s.rel(p) for p in web[:5])})")
        s.notes.append(f"firmware: rootfs at {rel}")
    if not roots or lief is None:
        return
    for p in bins:
        if not any(p.startswith(r) for r in roots):
            continue
        try:
            b = lief.parse(p)
            imps = {x.name for x in b.imported_symbols}
        except Exception:  # noqa: BLE001
            continue
        sinks = imps & {"system", "popen", "doSystemCmd", "twsystem", "CsteSystem", "_eval", "execve", "execv"}
        srcs = imps & {"websGetVar", "nvram_get", "nvram_safe_get", "acosNvramConfig_get", "getenv", "recv", "recvfrom",
                       "cgiFormString", "httpGetEnv", "find_val", "get_cgi", "FCGX_GetParam", "json_object_get_string", "cJSON_Parse"}
        if sinks and srcs:
            name = os.path.basename(p)
            sc = 5 + (1 if re.search(r"httpd|cgi|web|upnp|boa|goahead|lighttpd|hnap|ssi|soap", name, re.I) else 0)
            s.add(sc, "IoT command-injection pattern (imports)", s.rel(p), f"sinks={','.join(sorted(sinks))} sources={','.join(sorted(srcs))}",
                  f"Decompile and scan it: vuln-scan {s.rel(p)} (Ghidra; then follow input -> sprintf -> system).", "firmware")


# ------------------------------------------------------------------------------------------------------ deep
THIRD_PARTY_SO = re.compile(r"^lib(c\+\+_shared|flutter|reactnativejni|hermes|jsc|fbjni|yoga|folly_json|glog|"
                            r"double-conversion|sqlcipher|sqlite\w*|realm\w*|crashlytics\w*|sentry\w*|"
                            r"firebase\w*|gms\w*|tensorflow\w*|opencv\w*|ffmpeg|avcodec|avformat|avutil|swscale|"
                            r"swresample|unity|il2cpp|mono\w*|monosgen\w*|xamarin\w*|main|bugsnag\w*|"
                            r"conscrypt\w*|barhopper\w*|imagepipeline|native-imagetranscoder|static-webp|gifimage|"
                            r"turbomodulejsijni|react_\w+|jsi\w*|fabricjni|mapbufferjni|rrc_\w+|reanimated|"
                            r"rnscreens|c\+\+|ssl|crypto|z|curl|png|jpeg|webp\w*|tool-checker|pl_droidsonroids_gif)\.so$")


def deep(s, bins, n):
    """Run ghidra-analyze on the most promising embedded binaries so native_sinks can see their code."""
    have = {os.path.basename(os.path.dirname(os.path.dirname(p))) for p in walk(s.deep_dir, {".c"})}
    pri = []
    flagged = {c["where"] for c in s.cands if c["module"] == "firmware"}
    for p in bins:
        rel, name = s.rel(p), os.path.basename(p)
        if s.target and os.path.realpath(p) == os.path.realpath(s.target) and os.path.isdir(os.path.join(s.root, "ghidra")):
            continue
        sc = 0
        if "/native/" in p and name.endswith(".so"):
            if THIRD_PARTY_SO.match(name):
                continue
            abi = p.split("/native/")[1].split("/")[0]
            sc = 5 + {"arm64-v8a": 2, "armeabi-v7a": 1, "x86_64": 0}.get(abi, -1)
        elif rel in flagged:
            sc = 8
        elif ".app/" in p and "/Payload/" in p and "/Frameworks/" not in p:
            sc = 6
        elif re.search(r"(httpd|cgi|upnp|hnap|boa|goahead|lighttpd|webs|mini_httpd)", name, re.I):
            sc = 5
        if sc:
            pri.append((sc, os.path.getsize(p), p))
    pri.sort(key=lambda x: (-x[0], x[1]))
    picked, abis_seen = [], set()
    for sc, size, p in pri:
        name = os.path.basename(p)
        if "/native/" in p and name in abis_seen:
            continue  # same lib for another ABI
        abis_seen.add(name)
        picked.append(p)
        if len(picked) >= n:
            break
    for p in picked:
        od = os.path.join(s.deep_dir, re.sub(r"[^\w.-]", "_", s.rel(p)))
        if os.path.basename(od) in have or os.path.isdir(os.path.join(od, "decomp")):
            continue
        print(f"[vuln-scan] deep: ghidra-analyze {s.rel(p)}", file=sys.stderr)
        r = sh(["ghidra-analyze", p, "-o", od], timeout=s.args.deep_timeout)
        if r.returncode != 0:
            s.notes.append(f"deep: ghidra-analyze failed for {s.rel(p)} (see {s.rel(od)}/analyze.log)")
    if picked:
        s.notes.append(f"deep: decompiled {len(picked)} embedded binar{'y' if len(picked) == 1 else 'ies'} into {s.deep_dir} "
                       f"({', '.join(os.path.basename(p) for p in picked)})")
    elif n:
        s.notes.append("deep: no promising embedded binaries found")


# ---------------------------------------------------------------------------------------------------- report
def report(s, kind):
    s.cands.sort(key=lambda c: (-c["score"], c["module"], c["where"]))
    with s.w("candidates.tsv") as f:
        f.write("score\tmodule\tcategory\twhere\tevidence\tverify\n")
        for c in s.cands:
            f.write(f"{c['score']}\t{c['module']}\t{c['cat']}\t{c['where']}\t{c['evidence'][:300]}\t{c['verify']}\n")
    with s.w("attack_surface.txt") as f:
        f.write("\n".join(s.surface) + ("\n" if s.surface else "(nothing detected)\n"))
    top = [c for c in s.cands if c["score"] >= s.args.min_score][: s.args.top]
    sev = lambda n: "HIGH" if n >= 8 else "MED" if n >= 6 else "LOW" if n >= 4 else "INFO"  # noqa: E731
    with s.w("CANDIDATES.md") as f:
        f.write(f"# Vulnerability candidates: {os.path.basename(s.target or s.root)}\n\n")
        f.write(f"kind: {kind or 'directory'}   root: {s.root}\n\n")
        f.write("These are LEADS from static heuristics, not findings. Verify each one (reachability from an attacker-controlled\n"
                "input, real impact, in program scope) before reporting. Record confirmed issues in FINDINGS.md.\n\n")
        f.write("## Scan summary\n" + "".join(f"- {n}\n" for n in s.notes) + "\n")
        f.write(f"## Top {len(top)} of {len(s.cands)} candidates (score >= {s.args.min_score}; all in candidates.tsv)\n\n")
        for i, c in enumerate(top, 1):
            f.write(f"{i}. **[{sev(c['score'])} {c['score']}] {c['cat']}** - `{c['where']}`\n")
            f.write(f"   - evidence: `{c['evidence'][:260].replace('`', chr(39))}`\n")
            if c["verify"]:
                f.write(f"   - verify: {c['verify']}\n")
        f.write("\n## Files\nattack_surface.txt  native_sinks.tsv  semgrep.tsv  secrets.tsv  endpoints.txt  components.txt  hardening.tsv  candidates.tsv\n")
    print(open(os.path.join(s.out, "CANDIDATES.md"), encoding="utf-8").read())


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root")
    ap.add_argument("--target")
    ap.add_argument("--out")
    ap.add_argument("--rules", default=os.path.join(REPO, "rules", "semgrep"))
    ap.add_argument("--no-semgrep", action="store_true")
    ap.add_argument("--no-secrets", action="store_true")
    ap.add_argument("--all-code", action="store_true", help="include third-party library packages in semgrep")
    ap.add_argument("--deep", type=int, default=0, metavar="N",
                    help="ghidra-analyze up to N promising embedded binaries (JNI libs, firmware daemons, iOS main exe)")
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--min-score", type=int, default=3)
    ap.add_argument("--semgrep-timeout", type=int, default=1800)
    ap.add_argument("--secrets-timeout", type=int, default=900)
    ap.add_argument("--deep-timeout", type=int, default=1800)
    a = ap.parse_args()
    root = os.path.realpath(a.root)
    out = os.path.realpath(a.out or os.path.join(root, "vuln"))
    os.makedirs(out, exist_ok=True)
    s = Scan(root, out, a.target, a)
    kind = ""
    tri = os.path.join(root, "triage.txt")
    if os.path.exists(tri):
        m = re.search(r"^KIND\s+(\S+)", open(tri, encoding="utf-8", errors="replace").read(), re.M)
        kind = m.group(1) if m else ""
    bins, seen_bins = [], set()
    if a.target and os.path.isfile(a.target) and is_native(a.target):
        bins.append(os.path.realpath(a.target))
    for p in walk(root):
        if p.startswith(out + os.sep):
            continue
        if is_native(p) and p not in bins:
            try:
                with open(p, "rb") as fh:
                    key = (os.path.getsize(p), hash(fh.read(65536)))
            except OSError:
                continue
            if key in seen_bins:
                continue
            seen_bins.add(key)
            bins.append(p)
        if len(bins) >= 2000:
            break
    s.first_party = first_party(s)
    hardening(s, bins)
    firmware(s, bins)
    if a.deep:
        deep(s, bins, a.deep)
    gdirs = sorted({os.path.dirname(os.path.dirname(p)) for d in {root, s.deep_dir} if os.path.isdir(d)
                    for p in walk(d, {".c"}) if os.path.basename(os.path.dirname(p)) == "decomp"})
    if gdirs:
        native_sinks(s, gdirs)
    if not a.no_semgrep:
        semgrep(s, a.rules)
    android(s)
    ios(s)
    electron(s)
    generic_surface(s)
    dump_strings(s, bins)
    components(s)
    if not a.no_secrets:
        secrets(s, bins)
    endpoints(s)
    report(s, kind)


if __name__ == "__main__":
    sys.exit(main())
