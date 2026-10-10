# reverse_engineering_lab

A ready-to-use, headless reverse-engineering workbench for AI agents (and humans) running in Claude Code cloud
containers (Ubuntu 24.04, x86-64, root, outbound HTTPS through a proxy). You give it any binary, such as an APK, a
Windows EXE/DLL, a Linux ELF, Mach-O, .NET, JAR, PyInstaller, Electron, WebAssembly or firmware, and you get
decompiled, greppable text in about a minute.

Agents should read [`CLAUDE.md`](CLAUDE.md), which loads automatically. Domain playbooks live in `.claude/skills/`.

It is tuned for **bug bounty and vulnerability discovery**. `vuln-scan` ranks evidence-backed leads in any target,
`re-fuzz` runs time-boxed AFL++ with crash triage, and the `re-vulnhunt` skill covers verification, severity and reporting.

## Setup
```bash
./setup.sh                # ~80 s on a fresh container, ~1 s when already done (idempotent, per-step markers)
./setup.sh --with-wine    # + wine (32/64-bit) to run Windows PEs, ~1 min extra
./setup.sh --with-afl-qemu   # + AFL++ QEMU mode to fuzz closed-source binaries (~2 min; AFL_QEMU_ARCHES="x86_64 arm ...")
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

## Bug bounty / vulnerability discovery
```bash
vuln-scan path/to/target [--deep N]   # re-auto if needed, then ranked leads -> work/<target>/vuln/CANDIDATES.md
vuln-scan path/to/dir                 # source tree or extracted firmware rootfs (outputs -> work/<dir>/vuln)
re-fuzz --build harness.c             # afl-cc + ASan/UBSan
re-fuzz ./bin -t 600 -- @@            # AFL++ (instrumented or QEMU mode), dedup crash triage -> work/<bin>/fuzz/triage.txt
```
`vuln-scan` is static only: it never runs the target or contacts the network. It writes:

| File | What |
|---|---|
| `CANDIDATES.md` | top leads, scored 0-10, each with evidence and what to verify (start here) |
| `native_sinks.tsv` | command injection, unbounded copies, non-constant formats, variable memcpy in Ghidra output, with input-reachability scoring |
| `semgrep.tsv` | `rules/semgrep/*.yml`: Android (WebView, intent redirection, provider traversal, TLS, crypto...), .NET (deserialization...), Electron/JS, Python |
| `attack_surface.txt` | exported components and deep links, URL schemes and universal links, IPC handlers, listeners, firmware services and CGI |
| `secrets.tsv` | gitleaks (default rules + `rules/gitleaks.toml`), masked; first-party vs SDK code ranked |
| `endpoints.txt` | hosts referenced by app code vs SDKs, API paths, GraphQL ops, cloud buckets, staging hosts |
| `components.txt` | bundled OpenSSL/curl/BusyBox/dropbear/kernel... versions for n-day matching |
| `hardening.tsv` | ELF NX/PIE/RELRO/canary/FORTIFY/RPATH, PE ASLR/DEP/CFG/GS/SafeSEH/signing, Mach-O PIE/encryption, setuid |

Confirmed bugs go into `work/<target>/FINDINGS.md` using [`templates/FINDING.md`](templates/FINDING.md).

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
| Vuln discovery | semgrep 1.180 + lab rules, gitleaks 8.30, AFL++ 4.09c (afl-cc + ASan/UBSan, opt-in QEMU mode) |

## Repo layout
```
setup.sh                  installer (pinned versions at top)
bin/                      wrappers: re-auto re-triage re-doctor ghidra-analyze ghidra-query apk-analyze dotnet-decompile py-unpack
                          vuln-scan re-fuzz
tools/triage.py           identification logic         tools/apk_summary.py   manifest / attack surface
tools/ghidra_scripts/     ExportAll.java (bulk text export), Query.java (decomp/disasm/xrefs/rename), MakeFunctions.java
tools/vulnscan.py         vuln-scan engine              tools/fuzz_triage.py   AFL++ crash dedup/triage
rules/                    semgrep rules (java-android, csharp-dotnet, js-electron, python) + gitleaks.toml
templates/FINDING.md      bug bounty report template
.claude/skills/           re-native re-android re-dotnet re-python re-unpack re-dynamic re-vulnhunt
.claude/hooks/            SessionStart auto-setup
tests/smoke.sh            ~90s end-to-end check of the main pipelines (run after bumping versions)
tests/fixtures/           deliberately vulnerable snippets that the semgrep rules must flag (one per rule)
```

## Updating tool versions
Bump the variables at the top of `setup.sh`. The GitHub API isn't reachable through the sandbox proxy, but `git ls-remote`
and release downloads are:
`git ls-remote --tags --refs https://github.com/<owner>/<repo> | awk -F/ '{print $3}' | sort -V | tail -3`.
For Ghidra, the zip name includes a build date. Find it on the release page
(`https://github.com/NationalSecurityAgency/ghidra/releases/expanded_assets/Ghidra_<ver>_build`).
Then run `./setup.sh --only <step>`.
