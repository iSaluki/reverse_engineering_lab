# reverse_engineering_lab

A ready-to-use, headless reverse-engineering workbench for AI agents (and humans) running in Claude Code cloud
containers (Ubuntu 24.04, x86-64, root, outbound HTTPS through a proxy). You give it any binary, such as an APK, a
Windows EXE/DLL, a Linux ELF, Mach-O, .NET, JAR, PyInstaller, Electron, WebAssembly or firmware, and you get
decompiled, greppable text in about a minute.

Agents should read [`CLAUDE.md`](CLAUDE.md), which loads automatically. Domain playbooks live in `.claude/skills/`.

## Setup
```bash
./setup.sh                # ~80 s on a fresh container, ~1 s when already done (idempotent, per-step markers)
./setup.sh --with-wine    # + wine (32/64-bit) to run Windows PEs, ~1 min extra
re-doctor                 # what's installed
```
In Claude Code cloud sessions, `.claude/hooks/session-start.sh` runs this automatically (synchronously, so tools are
guaranteed present when the agent starts). Logs go to `/opt/re/logs/`, and all tools install under `/opt/re` and get
symlinked into `/usr/local/bin`.

## Quick start
```bash
re-auto path/to/target           # triage + right pipeline -> work/<target>/
re-triage path/to/target         # just identify: format, compiler/packer (DIE), frameworks, strings, KIND/NEXT
```

## What's inside
| Area | Tools |
|---|---|
| Native decompilation | Ghidra 12.1.4 headless (custom export/query scripts), radare2 6.2.4 + r2ghidra, objdump/llvm |
| Identification | Detect It Easy (diec), file, lief, pefile, readpe (pev), exiftool, ssdeep, yara |
| Capabilities / strings | Mandiant capa 9.4, FLOSS 3.1, GoReSym 3.4 |
| Android / JVM | jadx 1.5.6, apktool 3.0.3, dex2jar 2.4, Vineflower 1.12, androguard, aapt, apksigner, zipalign, hermes-dec |
| .NET | .NET SDK 10 + ilspycmd 11.1, dnfile |
| Python | pyinstxtractor-ng, pycdc/pycdas, decompyle3, uncompyle6, xdis, CPython 3.8–3.14 via uv (exact-version `dis`) |
| JS / Electron / wasm | @electron/asar, webcrack, js-beautify, wabt (wasm-decompile, wasm2wat) |
| Unpacking | UPX 5.2.1, 7zip, binwalk, innoextract, msitools, unshield, unar, squashfs-tools, cabextract |
| Dynamic | gdb (+GEF opt-in), gdb-multiarch, strace, ltrace, qemu-user(-static) + arm64/armhf sysroots, frida-tools, wine (opt) |
| Scripting (`repy`) | angr, z3, unicorn, capstone, lief, pyghidra, r2pipe, pwntools, ROPgadget, binary-refinery, oletools |

## Repo layout
```
setup.sh                  installer (pinned versions at top)
bin/                      wrappers: re-auto re-triage re-doctor ghidra-analyze ghidra-query apk-analyze dotnet-decompile py-unpack
tools/triage.py           identification logic         tools/apk_summary.py   manifest / attack surface
tools/ghidra_scripts/     ExportAll.java (bulk text export), Query.java (decomp/disasm/xrefs/rename), MakeFunctions.java
.claude/skills/           re-native re-android re-dotnet re-python re-unpack re-dynamic
.claude/hooks/            SessionStart auto-setup
tests/smoke.sh            ~30s end-to-end check of the main pipelines (run after bumping versions)
```

## Updating tool versions
Bump the variables at the top of `setup.sh`. The GitHub API isn't reachable through the sandbox proxy, but `git ls-remote`
and release downloads are:
`git ls-remote --tags --refs https://github.com/<owner>/<repo> | awk -F/ '{print $3}' | sort -V | tail -3`.
For Ghidra, the zip name includes a build date. Find it on the release page
(`https://github.com/NationalSecurityAgency/ghidra/releases/expanded_assets/Ghidra_<ver>_build`).
Then run `./setup.sh --only <step>`.
