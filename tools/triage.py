"""Fast, compact first look at any file. Run via `re-triage <file>` (uses the lab venv).

Prints: identity, hashes, detected compiler/packer/framework, format-specific facts,
a sample of interesting strings, and a one-line recommended next step (KIND=...).
Never executes the target.
"""
import hashlib
import math
import os
import re
import shutil
import subprocess
import sys
import zipfile
from collections import Counter

MAX_READ = 256 * 1024 * 1024


def sh(cmd, timeout=60):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace").stdout.strip()
    except Exception as e:  # noqa: BLE001
        return f"<{cmd[0]} failed: {e}>"


def entropy(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def human(n):
    for u in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.0f}{u}"
        n /= 1024
    return f"{n:.1f}TB"


class Out:
    def __init__(self):
        self.kind = None
        self.notes = []
        self.next = []

    def kv(self, k, v):
        print(f"{k:<12} {v}")

    def note(self, s):
        self.notes.append(s)


def strings_of(data, n=6):
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % n)
    wide_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % n)
    for m in ascii_re.finditer(data):
        yield m.group().decode()
    for m in wide_re.finditer(data):
        yield m.group().decode("utf-16le")


INTERESTING = [
    ("url", re.compile(r"[a-z][a-z0-9+.-]{1,10}://[^\s\"'<>]{4,}", re.I)),
    ("ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b")),
    ("path", re.compile(r"(?:\b[A-Za-z]:\\(?:[\w .()-]+\\)+[\w .()-]*|/(?:etc|tmp|var|usr|home|proc|data|sdcard|system)/[^\s\"']+)")),
    ("secretish", re.compile(r"(?i)(?:passw|secret|token|api[_-]?key|private|BEGIN [A-Z ]*KEY|AKIA[0-9A-Z]{16}|flag\{|ctf\{)")),
    ("crypto", re.compile(r"(?i)\b(?:aes|rsa|chacha|salsa|rc4|blowfish|sha256|sha1|md5|hmac|pbkdf2|base64|xor)\b")),
    ("cmd", re.compile(r"(?i)(?:cmd\.exe|powershell|/bin/sh|/bin/bash|wget |curl |chmod |schtasks|reg add|CreateRemoteThread|VirtualAlloc|LoadLibrary|GetProcAddress|ptrace|dlopen)")),
]


def interesting_strings(data, limit=12):
    hits = {k: [] for k, _ in INTERESTING}
    seen = set()
    for s in strings_of(data[:64 * 1024 * 1024]):
        if s in seen:
            continue
        seen.add(s)
        for k, rx in INTERESTING:
            if len(hits[k]) < limit and rx.search(s):
                hits[k].append(s[:160])
    return {k: v for k, v in hits.items() if v}


def markers(data, o):
    m = []
    if b"UPX!" in data[:4096] or b"UPX0" in data[:4096]:
        m.append("UPX-packed (try: upx -d -o unpacked FILE)")
    if b"MEI\x0c\x0b\x0a\x0b\x0e" in data[-4096:] or b"pyi-windows-manifest" in data or b"PYZ-00.pyz" in data or b"_MEIPASS" in data:
        m.append("PyInstaller bundle (py-unpack)")
    if b"__nuitka" in data or b"NUITKA_ONEFILE" in data or b"nuitka" in data[-8 * 1024 * 1024:]:
        m.append("Nuitka-compiled Python (native code; strings + Ghidra)")
    if b"Go build ID:" in data or b"\xff Go buildinf:" in data or b"runtime.gopanic" in data:
        m.append("Go binary (goresym FILE first, then ghidra-analyze)")
    if b"/rustc/" in data or b"rust_panic" in data or b"core::panicking" in data:
        m.append("Rust binary (symbols demangle in Ghidra; look for main via std::rt::lang_start)")
    if b"electron.asar" in data or b"ELECTRON_RUN_AS_NODE" in data:
        m.append("Electron app (find resources/app.asar -> asar extract)")
    if b"AutoIt" in data and b"AU3!" in data:
        m.append("AutoIt compiled script")
    if b"Inno Setup" in data[:2 * 1024 * 1024]:
        m.append("Inno Setup installer (innoextract FILE)")
    if b"Nullsoft" in data[:2 * 1024 * 1024] or b"NSIS" in data[:2 * 1024 * 1024]:
        m.append("NSIS installer (7z x FILE)")
    if b"pkg/prelude/bootstrap.js" in data or b"PAYLOAD_POSITION" in data:
        m.append("vercel/pkg Node.js bundle (JS snapshot embedded)")
    if b"global-metadata.dat" in data and b"il2cpp" in data:
        m.append("Unity IL2CPP")
    if b"Qt_5" in data or b"Qt_6" in data or b"Qt5Core" in data or b"Qt6Core" in data:
        m.append("Qt application")
    if b"Embarcadero" in data or (b"Borland" in data and b"TObject" in data):
        m.append("Delphi/C++Builder")
    if b"_CorExeMain" in data or b"_CorDllMain" in data:
        m.append(".NET assembly (dotnet-decompile)")
    if b"\x00VMProtect" in data or b".vmp0" in data[:4096]:
        m.append("VMProtect section names present (heavily protected)")
    if b".themida" in data[:4096] or b"Themida" in data[:4096]:
        m.append("Themida/WinLicense")
    return m


def diec(path):
    if not shutil.which("diec"):
        return None
    out = sh(["diec", path], timeout=90)
    out = re.sub(r"\x1b\[[0-9;]*m", "", out)
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    return lines


def tri_pe(path, data, o):
    import pefile
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
        ])
    except Exception as e:  # noqa: BLE001
        o.kv("pe", f"parse error: {e}")
        return
    import datetime
    mach = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
    sub = pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, "?")
    dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    ts = pe.FILE_HEADER.TimeDateStamp
    o.kv("pe", f"{mach} {'DLL' if dll else 'EXE'} {sub} imagebase={hex(pe.OPTIONAL_HEADER.ImageBase)} "
               f"entry=+{hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)} timestamp={datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).date() if ts else 0}")
    secs = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode(errors="replace")
        secs.append(f"{name}({human(s.SizeOfRawData)},H={s.get_entropy():.1f})")
    o.kv("sections", " ".join(secs))
    clr = getattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR", None) or pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress
    if clr:
        o.kind = "dotnet"
        try:
            import dnfile
            dn = dnfile.dnPE(data=data)
            asm = dn.net.mdtables.Assembly.rows[0] if dn.net and dn.net.mdtables.Assembly else None
            name = asm.Name if asm else "?"
            ver = f"{asm.MajorVersion}.{asm.MinorVersion}.{asm.BuildNumber}" if asm else ""
            flags = dn.net.Flags
            o.kv(".net", f"assembly={name} {ver} runtime={dn.net.metadata.struct.Version.decode(errors='replace').strip(chr(0)) if dn.net.metadata else '?'} "
                         f"ILonly={bool(flags.CLR_ILONLY)} types={dn.net.mdtables.TypeDef.num_rows if dn.net.mdtables.TypeDef else 0}")
        except Exception as e:  # noqa: BLE001
            o.kv(".net", f"CLR header present ({e.__class__.__name__} reading metadata)")
    imps = getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
    if imps:
        dlls = [i.dll.decode(errors="replace") for i in imps]
        nfun = sum(len(i.imports) for i in imps)
        o.kv("imports", f"{nfun} funcs from {len(dlls)} DLLs: {', '.join(dlls[:15])}{' ...' if len(dlls) > 15 else ''}")
        sus = {"VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread", "IsDebuggerPresent",
               "CheckRemoteDebuggerPresent", "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "CryptDecrypt",
               "InternetOpenA", "InternetOpenW", "WinHttpOpen", "URLDownloadToFileW", "ShellExecuteW", "CreateProcessW",
               "RegSetValueExW", "BCryptDecrypt", "NtQueryInformationProcess", "SetWindowsHookExW", "socket", "connect"}
        found = sorted({i.name.decode() for d in imps for i in d.imports if i.name and i.name.decode() in sus})
        if found:
            o.kv("notable", ", ".join(found))
        if nfun < 10 and not clr:
            o.note("very few imports -> likely packed / resolves APIs dynamically")
    exps = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exps:
        names = [e.name.decode(errors="replace") for e in exps.symbols if e.name][:15]
        o.kv("exports", f"{len(exps.symbols)}: {', '.join(names)}")
    for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        e = getattr(d, "entry", None)
        if e is not None and hasattr(e, "PdbFileName"):
            o.kv("pdb", e.PdbFileName.rstrip(b"\x00").decode(errors="replace"))
    if pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size:
        o.kv("signed", f"Authenticode blob {pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size} bytes (osslsigncode verify FILE)")
    ov = pe.get_overlay_data_start_offset()
    if ov:
        o.kv("overlay", f"{human(len(data) - ov)} at {hex(ov)} H={entropy(data[ov:ov + 1 << 20]):.2f} (installer/bundle payload?)")
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        for fi in getattr(pe, "FileInfo", []) or []:
            for x in fi:
                for st in getattr(x, "StringTable", []):
                    vi = {k.decode(errors="replace"): v.decode(errors="replace") for k, v in st.entries.items()}
                    keep = {k: vi[k] for k in ("CompanyName", "ProductName", "FileDescription", "OriginalFilename", "FileVersion") if vi.get(k)}
                    if keep and not getattr(o, "_vi", False):
                        o._vi = True
                        o.kv("versioninfo", "; ".join(f"{k}={v}" for k, v in keep.items()))
    except Exception:  # noqa: BLE001
        pass
    if o.kind is None:
        o.kind = "native-pe"


def tri_lief(path, o, fmt):
    try:
        import lief
        lief.logging.disable()
        b = lief.parse(path)
    except Exception as e:  # noqa: BLE001
        o.kv(fmt.lower(), f"lief error {e}")
        return
    if b is None:
        return
    if fmt == "ELF":
        h = b.header
        interp = b.interpreter if b.has_interpreter else "static/none"
        o.kv("elf", f"{h.machine_type.name} {h.file_type.name} {'PIE' if b.is_pie else 'non-PIE'} interp={interp} "
                    f"entry={hex(b.entrypoint)} stripped={'yes' if not any(True for _ in b.symtab_symbols) else 'no'}")
        libs = list(b.libraries)
        if libs:
            o.kv("needed", ", ".join(libs[:20]))
        boring = (".note", ".gnu.", ".rela", ".dynsym", ".dynstr", ".interp", ".comment", ".shstrtab", ".init_array", ".fini_array", ".eh_frame_hdr")
        secs = [f"{s.name}({human(s.size)})" for s in b.sections if s.name and not s.name.startswith(boring)][:25]
        o.kv("sections", " ".join(secs))
        exps = [s.name for s in b.exported_functions][:20]
        if exps and h.file_type.name == "DYN" and not b.has_interpreter:
            o.kv("exports", f"{len(list(b.exported_functions))}: {', '.join(exps)}")
            if any(e.startswith("Java_") or e == "JNI_OnLoad" for e in exps):
                o.note("JNI library: Java_* exports map to native methods; JNI_OnLoad may RegisterNatives")
        arch = h.machine_type.name
        if arch not in ("X86_64", "I386", "x86_64", "i386"):
            o.note(f"foreign arch {arch}: run with qemu-{{aarch64,arm,mips...}} -L /usr/<triple> (see re-dynamic skill)")
    elif fmt == "MachO":
        o.kv("macho", f"{b.header.cpu_type.name} {b.header.file_type.name} entry={hex(b.entrypoint) if b.entrypoint else '?'}")
        o.kv("libs", ", ".join(l.name for l in b.libraries)[:400])
        if b.has_code_signature:
            o.kv("signed", "yes")
        if any("objc" in s.name.lower() for s in b.sections):
            o.note("Objective-C metadata present: Ghidra recovers class/selector names")
        if any("swift" in s.name.lower() for s in b.sections):
            o.note("Swift binary")


def tri_zip(path, o):
    try:
        z = zipfile.ZipFile(path)
    except Exception as e:  # noqa: BLE001
        o.kv("zip", f"bad zip: {e}")
        return
    names = z.namelist()
    o.kv("zip", f"{len(names)} entries")
    lower = [n.lower() for n in names]
    if "androidmanifest.xml" in lower and any(n.endswith(".dex") for n in lower):
        o.kind = "apk"
        dex = [n for n in names if n.endswith(".dex")]
        abis = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and n.count("/") >= 2})
        o.kv("apk", f"{len(dex)} dex, native ABIs: {', '.join(abis) or 'none'}")
        if shutil.which("aapt"):
            bad = sh(["aapt", "dump", "badging", path])
            for l in bad.splitlines():
                if l.startswith(("package:", "sdkVersion", "targetSdkVersion", "launchable-activity", "application-label:")):
                    o.kv("", l[:200])
        fw = apk_frameworks(names)
        if fw:
            o.kv("framework", "; ".join(fw))
    elif any(n.endswith(".apk") for n in lower) and ("manifest.json" in lower or "toc.pb" in lower or any(n.startswith("splits/") for n in lower)):
        o.kind = "apk"
        o.kv("bundle", "XAPK/APKS split bundle: " + ", ".join(n for n in names if n.endswith(".apk"))[:300])
    elif "meta-inf/manifest.mf" in lower and any(n.endswith(".class") for n in lower):
        o.kind = "jar"
        mf = z.read([n for n in names if n.lower() == "meta-inf/manifest.mf"][0]).decode(errors="replace")
        main = re.search(r"Main-Class:\s*(\S+)", mf)
        o.kv("jar", f"{sum(n.endswith('.class') for n in lower)} classes; Main-Class={main.group(1) if main else '-'}")
        if "BOOT-INF/" in "".join(names[:200]):
            o.note("Spring Boot fat jar: app classes in BOOT-INF/classes, deps in BOOT-INF/lib")
    elif any(n.startswith("payload/") and n.endswith(".app/") or (n.startswith("payload/") and ".app/" in n) for n in lower):
        o.kind = "ipa"
        o.kv("ipa", "iOS app: unzip, main Mach-O is Payload/<X>.app/<X> (likely FairPlay-encrypted if from App Store)")
    else:
        o.kind = "archive"
        o.kv("entries", ", ".join(names[:20]) + (" ..." if len(names) > 20 else ""))


def apk_frameworks(names):
    s = set(names)
    j = "\n".join(names)
    fw = []
    if any(n.endswith("libflutter.so") for n in names):
        fw.append("Flutter (Dart AOT in libapp.so; Java side is a thin shell)")
    if "assets/index.android.bundle" in s:
        fw.append("React Native (assets/index.android.bundle; Hermes bytecode if magic c61fbc03 -> hbc-decompiler)")
    if "libil2cpp.so" in j and "global-metadata.dat" in j:
        fw.append("Unity IL2CPP (libil2cpp.so + global-metadata.dat)")
    elif "assets/bin/Data/Managed/" in j:
        fw.append("Unity Mono (C# DLLs in assets/bin/Data/Managed -> dotnet-decompile Assembly-CSharp.dll)")
    if "libmonodroid.so" in j or "assemblies/" in j or "libassemblies" in j:
        fw.append("Xamarin/.NET MAUI (C# assemblies; may be in assemblies.blob / libassemblies.*.blob.so)")
    if "assets/www/index.html" in s or "assets/public/index.html" in s:
        fw.append("Cordova/Capacitor (web app in assets/www or assets/public)")
    if "kotlin/" in j or "META-INF/kotlin" in j:
        fw.append("Kotlin")
    for packer, sig in [("Jiagu(360)", "libjiagu"), ("Bangcle/SecNeo", "libsecexe"), ("Ijiami", "libexec.so"),
                        ("Tencent Legu", "libshell"), ("Baidu", "libbaiduprotect"), ("DexGuard/Arxan?", "libdxbase")]:
        if sig in j:
            fw.append(f"PACKER: {packer} (real dex decrypted at runtime)")
    return fw


def main():
    if len(sys.argv) < 2:
        print("usage: re-triage <file>")
        sys.exit(2)
    path = sys.argv[1]
    o = Out()
    st = os.stat(path)
    with open(path, "rb") as f:
        data = f.read(MAX_READ)
    o.kv("file", path)
    o.kv("type", sh(["file", "-b", path])[:300])
    o.kv("size", f"{human(st.st_size)} ({st.st_size}) entropy={entropy(data[:32 << 20]):.2f}")
    o.kv("sha256", hashlib.sha256(data).hexdigest())
    d = diec(path)
    if d:
        o.kv("die", " | ".join(d[:10]))

    magic = data[:8]
    if magic[:2] == b"MZ":
        tri_pe(path, data, o)
    elif magic[:4] == b"\x7fELF":
        o.kind = "native-elf"
        tri_lief(path, o, "ELF")
    elif magic[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe") and not path.endswith(".class"):
        o.kind = "native-macho"
        tri_lief(path, o, "MachO")
    elif magic[:4] == b"\xca\xfe\xba\xbe":
        o.kind = "jar"
    elif magic[:4] == b"PK\x03\x04":
        tri_zip(path, o)
    elif magic[:4] == b"dex\n":
        o.kind = "dex"
    elif magic[:4] == b"\x00asm":
        o.kind = "wasm"
    elif len(magic) >= 4 and magic[2:4] == b"\r\n" and path.endswith((".pyc", ".pyo")):
        o.kind = "pyc"
    elif magic[:8] == bytes.fromhex("c61fbc03c103191f"):
        o.kind = "hermes"
    elif data[:2] == b"\x1f\x8b" or data[:3] == b"BZh" or data[:6] == b"\xfd7zXZ\x00" or data[:6] == b"7z\xbc\xaf\x27\x1c" or data[:4] == b"Rar!":
        o.kind = "archive"
    elif path.endswith(".asar"):
        o.kind = "asar"
    else:
        text = sum(32 <= c < 127 or c in (9, 10, 13) for c in data[:4096]) / max(1, len(data[:4096]))
        o.kind = "text/script" if text > 0.95 else "unknown-blob"

    mk = markers(data, o)
    for m in mk:
        o.note(m)
        if m.startswith("PyInstaller"):
            o.kind = "pyinstaller"
        elif m.startswith("UPX") and o.kind and o.kind.startswith("native"):
            o.kind = "upx"
        elif m.startswith("Go binary") and o.kind and o.kind.startswith("native"):
            o.kind = "go"
        elif m.startswith("Electron") and o.kind and o.kind.startswith("native"):
            o.kind = "electron"

    for n in o.notes:
        o.kv("note", n)
    hits = {} if o.kind in ("apk", "jar", "ipa", "archive") else interesting_strings(data)
    for k, v in hits.items():
        o.kv(f"str.{k}", " | ".join(v)[:600])

    nxt = {
        "native-elf": "ghidra-analyze FILE   (skill: re-native; dynamic: re-dynamic)",
        "native-pe": "ghidra-analyze FILE ; capa FILE   (skill: re-native)",
        "native-macho": "ghidra-analyze FILE   (skill: re-native)",
        "upx": "upx -d -o FILE.unpacked FILE && re-triage FILE.unpacked   (skill: re-unpack)",
        "go": "goresym -t -p FILE > goresym.json ; ghidra-analyze FILE   (skill: re-native, Go section)",
        "dotnet": "dotnet-decompile FILE   (skill: re-dotnet)",
        "apk": "apk-analyze FILE   (skill: re-android)",
        "dex": "jadx -d OUT FILE   (skill: re-android)",
        "jar": "jadx -d OUT FILE  or  vineflower FILE OUT/   (skill: re-android, JVM section)",
        "pyinstaller": "py-unpack FILE   (skill: re-python)",
        "pyc": "py-unpack FILE   (skill: re-python)",
        "hermes": "hbc-decompiler FILE out.js   (skill: re-android, React Native)",
        "electron": "locate resources/app.asar; asar extract app.asar OUT   (skill: re-unpack)",
        "asar": "asar extract FILE OUT   (skill: re-unpack)",
        "wasm": "wasm-decompile FILE -o out.dcmp ; wasm2wat FILE   (skill: re-native, wasm)",
        "archive": "7z x -oOUT FILE then re-triage the contents   (skill: re-unpack)",
        "ipa": "unzip, then ghidra-analyze Payload/X.app/X   (skill: re-native, Mach-O)",
        "text/script": "read it; deobfuscate JS with webcrack, beautify with js-beautify",
        "unknown-blob": "binwalk FILE ; re-triage carved parts; raw firmware -> ghidra-analyze FILE -- -processor ... (skill: re-unpack)",
    }
    print(f"{'KIND':<12} {o.kind}")
    print(f"{'NEXT':<12} {nxt.get(o.kind, 're-auto FILE')}")


if __name__ == "__main__":
    main()
