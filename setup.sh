#!/usr/bin/env bash
# Reverse-engineering lab installer. Idempotent: finished steps are skipped
# (markers in $RE_HOME/.done), so re-running is cheap (~2s).
#
#   ./setup.sh               install everything (default set)
#   ./setup.sh --with-wine   also install wine (run Windows PEs dynamically, ~1 GB)
#   ./setup.sh --force       redo every step
#   ./setup.sh --only STEP   (re)run one step: apt ghidra jvm_tools native_tools dotnet python node wine links
#
# Logs: $RE_HOME/logs/<step>.log   Status: re-doctor
# Bump versions below; discover new tags with:
#   git ls-remote --tags --refs https://github.com/<owner>/<repo> | sort -V -k2 | tail
set -uo pipefail

RE_HOME=${RE_HOME:-/opt/re}
REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# ---- pinned versions -------------------------------------------------------
GHIDRA_VER=12.1.4;  GHIDRA_DATE=20260921
JADX_VER=1.5.6
APKTOOL_VER=3.0.3
VINEFLOWER_VER=1.12.0
DEX2JAR_VER=2.4
UPX_VER=5.2.1
R2_VER=6.2.4                # radare2 + r2ghidra
DIE_VER=3.21
CAPA_VER=9.4.0
FLOSS_VER=3.1.1
GORESYM_VER=3.4.1
GEF_VER=2026.01
ILSPY_VER=11.1.0.9782       # ilspycmd (NuGet)
# ---------------------------------------------------------------------------

GH=https://github.com
FORCE=0; WITH_WINE=0; ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --force) FORCE=1 ;;
    --with-wine) WITH_WINE=1 ;;
    --only) ONLY=$2; FORCE=1; shift ;;   # implies --force for that step
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown arg $1"; exit 2 ;;
  esac
  shift
done

SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
$SUDO mkdir -p "$RE_HOME"/{.done,logs,dl,bin} && $SUDO chown -R "$(id -u):$(id -g)" "$RE_HOME"
export DEBIAN_FRONTEND=noninteractive PATH="$RE_HOME/bin:$PATH"

log()  { printf '[setup %(%H:%M:%S)T] %s\n' -1 "$*"; }
dl()   { # dl URL DEST  (skips if present)
  [ -s "$2" ] && return 0
  curl -fsSL --retry 4 --retry-delay 2 -o "$2.part" "$1" && mv "$2.part" "$2"
}
link() { ln -sf "$1" "$RE_HOME/bin/$2"; $SUDO ln -sf "$1" "/usr/local/bin/$2"; }

# run_step NAME FUNC : runs FUNC once (marker), logging to file. Returns its status.
run_step() {
  local name=$1 fn=$2
  if [ -n "$ONLY" ] && [ "$ONLY" != "$name" ]; then return 0; fi
  if [ $FORCE -eq 0 ] && [ -e "$RE_HOME/.done/$name" ]; then return 0; fi
  log "start $name"
  local t0=$SECONDS
  if ( set -e; $fn ) >"$RE_HOME/logs/$name.log" 2>&1; then
    touch "$RE_HOME/.done/$name"; log "ok    $name ($((SECONDS-t0))s)"
  else
    log "FAIL  $name ($((SECONDS-t0))s) -> see $RE_HOME/logs/$name.log"; tail -5 "$RE_HOME/logs/$name.log" | sed 's/^/        /'
    return 1
  fi
}

# ---------------------------------------------------------------- steps ----
step_apt() {
  local pkgs=(
    # identification / generic
    file binutils binutils-multiarch elfutils patchelf xxd bsdextrautils hexyl
    libimage-exiftool-perl ssdeep yara jq ripgrep sqlite3
    # archives / installers / firmware
    p7zip-full 7zip unzip zip unar cabextract innoextract msitools unshield
    cpio rpm2cpio lzip zstd xz-utils squashfs-tools binwalk
    # PE tooling
    pev osslsigncode
    # Android
    aapt apksigner zipalign
    # wasm
    wabt
    # debugging / dynamic
    gdb gdb-multiarch strace ltrace qemu-user qemu-user-static
    libc6-arm64-cross libc6-armhf-cross
    # build deps (pycdc etc.)
    build-essential cmake git pkg-config libmagic1
    # JVM + .NET
    openjdk-21-jdk-headless dotnet-sdk-10.0
  )
  # apt update only if lists are older than a day
  if [ -z "$(find /var/lib/apt/lists -maxdepth 1 -name '*Packages*' -mmin -1440 2>/dev/null | head -1)" ]; then
    $SUDO apt-get update -q
  fi
  $SUDO apt-get install -y -q --no-install-recommends "${pkgs[@]}"
}

step_wine() {
  # i386 multiarch so 32-bit PEs (very common) run too
  dpkg --print-foreign-architectures | grep -qx i386 || { $SUDO dpkg --add-architecture i386; $SUDO apt-get update -q; }
  $SUDO apt-get install -y -q --no-install-recommends wine64 wine wine32:i386
  printf '#!/bin/sh\n# headless wine: no X needed for console apps\nexport WINEDEBUG=${WINEDEBUG:--all} WINEPREFIX=${WINEPREFIX:-$HOME/.wine}\nexec wine "$@"\n' > "$RE_HOME/bin/.rewine"
  chmod +x "$RE_HOME/bin/.rewine"; link "$RE_HOME/bin/.rewine" rewine
  # (re)create the prefix with 32-bit support (a 64-bit-only prefix fails on 32-bit PEs: "could not load kernel32.dll")
  [ -d "$HOME/.wine/drive_c/windows/syswow64" ] && [ -e "$HOME/.wine/drive_c/windows/syswow64/kernel32.dll" ] || rm -rf "$HOME/.wine"
  timeout 300 "$RE_HOME/bin/.rewine" wineboot -i || true
}

step_ghidra() {
  local z="$RE_HOME/dl/ghidra_${GHIDRA_VER}.zip"
  dl "$GH/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VER}_build/ghidra_${GHIDRA_VER}_PUBLIC_${GHIDRA_DATE}.zip" "$z"
  rm -rf "$RE_HOME/ghidra_${GHIDRA_VER}_PUBLIC"
  unzip -q "$z" -d "$RE_HOME"
  ln -sfn "$RE_HOME/ghidra_${GHIDRA_VER}_PUBLIC" "$RE_HOME/ghidra"
  # more heap for big binaries (machine has plenty of RAM)
  sed -i 's/^MAXMEM=.*/MAXMEM=${MAXMEM:-8G}/' "$RE_HOME/ghidra/support/analyzeHeadless" || true
  link "$RE_HOME/ghidra/support/analyzeHeadless" analyzeHeadless
  rm -f "$z"
}

step_jvm_tools() {
  dl "$GH/skylot/jadx/releases/download/v$JADX_VER/jadx-$JADX_VER.zip" "$RE_HOME/dl/jadx.zip"
  rm -rf "$RE_HOME/jadx"; unzip -q "$RE_HOME/dl/jadx.zip" -d "$RE_HOME/jadx"
  link "$RE_HOME/jadx/bin/jadx" jadx

  mkdir -p "$RE_HOME/jars"
  dl "$GH/iBotPeaches/Apktool/releases/download/v$APKTOOL_VER/apktool_$APKTOOL_VER.jar" "$RE_HOME/jars/apktool.jar"
  dl "$GH/Vineflower/vineflower/releases/download/$VINEFLOWER_VER/vineflower-$VINEFLOWER_VER.jar" "$RE_HOME/jars/vineflower.jar"
  printf '#!/bin/sh\nexec java -Xmx4g -jar %s "$@"\n' "$RE_HOME/jars/apktool.jar" > "$RE_HOME/jars/apktool"
  printf '#!/bin/sh\nexec java -Xmx4g -jar %s "$@"\n' "$RE_HOME/jars/vineflower.jar" > "$RE_HOME/jars/vineflower"
  chmod +x "$RE_HOME/jars/apktool" "$RE_HOME/jars/vineflower"
  link "$RE_HOME/jars/apktool" apktool
  link "$RE_HOME/jars/vineflower" vineflower

  dl "$GH/pxb1988/dex2jar/releases/download/v$DEX2JAR_VER/dex-tools-v$DEX2JAR_VER.zip" "$RE_HOME/dl/dex2jar.zip"
  rm -rf "$RE_HOME/dex2jar"; mkdir -p "$RE_HOME/dex2jar"; unzip -q "$RE_HOME/dl/dex2jar.zip" -d "$RE_HOME/dex2jar"
  local d; d=$(dirname "$(find "$RE_HOME/dex2jar" -name 'd2j-dex2jar.sh' | head -1)")
  chmod +x "$d"/*.sh; link "$d/d2j-dex2jar.sh" d2j-dex2jar
}

step_native_tools() {
  # radare2 + r2ghidra (decompiler plugin: `pdg`)
  dl "$GH/radareorg/radare2/releases/download/$R2_VER/radare2_${R2_VER}_amd64.deb" "$RE_HOME/dl/radare2.deb"
  dl "$GH/radareorg/r2ghidra/releases/download/$R2_VER/r2ghidra_${R2_VER}_amd64.deb" "$RE_HOME/dl/r2ghidra.deb"
  # Detect It Easy (diec)
  dl "$GH/horsicq/DIE-engine/releases/download/$DIE_VER/die_${DIE_VER}_Ubuntu_24.04_amd64.deb" "$RE_HOME/dl/die.deb"
  $SUDO apt-get install -y -q --no-install-recommends "$RE_HOME/dl/radare2.deb" "$RE_HOME/dl/die.deb"
  $SUDO apt-get install -y -q --no-install-recommends "$RE_HOME/dl/r2ghidra.deb" || echo "WARN: r2ghidra failed (r2 still works, use pdc/Ghidra instead)"

  # UPX (newer than apt's)
  dl "$GH/upx/upx/releases/download/v$UPX_VER/upx-$UPX_VER-amd64_linux.tar.xz" "$RE_HOME/dl/upx.tar.xz"
  tar -xJf "$RE_HOME/dl/upx.tar.xz" -C "$RE_HOME"; link "$RE_HOME/upx-$UPX_VER-amd64_linux/upx" upx

  # Mandiant FLARE: capa (capabilities, rules embedded), floss (deobfuscated strings), GoReSym (Go symbols)
  mkdir -p "$RE_HOME/flare"
  dl "$GH/mandiant/capa/releases/download/v$CAPA_VER/capa-v$CAPA_VER-linux.zip" "$RE_HOME/dl/capa.zip"
  dl "$GH/mandiant/flare-floss/releases/download/v$FLOSS_VER/floss-v$FLOSS_VER-linux.zip" "$RE_HOME/dl/floss.zip"
  dl "$GH/mandiant/GoReSym/releases/download/v$GORESYM_VER/GoReSym-linux.zip" "$RE_HOME/dl/goresym.zip"
  for z in capa floss goresym; do unzip -qo "$RE_HOME/dl/$z.zip" -d "$RE_HOME/flare/$z"; done
  chmod +x "$RE_HOME"/flare/*/*
  link "$(find "$RE_HOME/flare/capa" -type f -name 'capa*' | head -1)" capa
  link "$(find "$RE_HOME/flare/floss" -type f -name 'floss*' | head -1)" floss
  link "$(find "$RE_HOME/flare/goresym" -type f -iname 'goresym*' | head -1)" goresym

  # agent-friendly radare2 defaults (no ANSI colors, ASCII only, apply relocs)
  [ -f "$HOME/.radare2rc" ] || printf 'e scr.color=0\ne scr.utf8=false\ne scr.interactive=false\ne bin.relocs.apply=true\n' > "$HOME/.radare2rc"

  # GEF for gdb (opt-in: gdb -x $RE_HOME/gef.py)
  dl "https://raw.githubusercontent.com/hugsy/gef/$GEF_VER/gef.py" "$RE_HOME/gef.py"

  # pycdc / pycdas: Python bytecode decompiler (handles 3.x incl. recent versions best-effort)
  rm -rf "$RE_HOME/src/pycdc"; mkdir -p "$RE_HOME/src"
  git clone -q --depth 1 https://github.com/zrax/pycdc "$RE_HOME/src/pycdc"
  cmake -S "$RE_HOME/src/pycdc" -B "$RE_HOME/src/pycdc/build" -DCMAKE_BUILD_TYPE=Release >/dev/null
  make -s -C "$RE_HOME/src/pycdc/build" -j"$(nproc)"
  link "$RE_HOME/src/pycdc/build/pycdc" pycdc
  link "$RE_HOME/src/pycdc/build/pycdas" pycdas
}

step_dotnet() {
  export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_ROOT=${DOTNET_ROOT:-/usr/lib/dotnet}
  dotnet tool update --tool-path "$RE_HOME/dotnet-tools" ilspycmd --version "$ILSPY_VER" \
    || dotnet tool install --tool-path "$RE_HOME/dotnet-tools" ilspycmd --version "$ILSPY_VER"
  printf '#!/bin/sh\nexport DOTNET_ROOT=${DOTNET_ROOT:-/usr/lib/dotnet} DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1\nexec %s "$@"\n' \
    "$RE_HOME/dotnet-tools/ilspycmd" > "$RE_HOME/bin/.ilspycmd"
  chmod +x "$RE_HOME/bin/.ilspycmd"; link "$RE_HOME/bin/.ilspycmd" ilspycmd
}

step_python() {
  command -v uv >/dev/null || pip3 install -q uv
  [ -x "$RE_HOME/venv/bin/python" ] || uv venv -q "$RE_HOME/venv"
  local py="$RE_HOME/venv/bin/python"
  uv pip install -q --python "$py" \
    lief pefile pyelftools capstone unicorn r2pipe dnfile yara-python python-magic \
    androguard frida-tools hermes-dec \
    pyinstxtractor-ng xdis decompyle3 uncompyle6 \
    pwntools ropgadget oletools binary-refinery angr z3-solver
  # pyghidra (drive Ghidra from Python) - shipped inside the Ghidra dist; fall back to PyPI
  local whl; whl=$(ls "$RE_HOME"/ghidra/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-*.whl 2>/dev/null | head -1)
  uv pip install -q --python "$py" "${whl:-pyghidra}"
  printf '#!/bin/sh\nexec %s "$@"\n' "$py" > "$RE_HOME/bin/.repy"; chmod +x "$RE_HOME/bin/.repy"
  # CPython builds so py-unpack can `dis` bytecode with the exact version that compiled it
  uv python install 3.8 3.9 3.10 3.11 3.12 3.13 3.14 || echo "WARN: some uv pythons failed (fetched on demand later)"
  link "$RE_HOME/bin/.repy" repy   # python with all RE libs (a bare symlink would not activate the venv)
  for b in frida frida-ps frida-trace pyinstxtractor-ng decompyle3 uncompyle6 ROPgadget androguard \
           hbc-decompiler hbc-disassembler hbc-file-parser olevba oleid emit; do
    [ -x "$RE_HOME/venv/bin/$b" ] && link "$RE_HOME/venv/bin/$b" "$b"
  done
  true
}

step_node() {
  npm install -g --silent @electron/asar webcrack js-beautify
}

step_links() {   # always cheap; points helper scripts at this checkout
  for f in "$REPO_DIR"/bin/*; do [ -f "$f" ] && chmod +x "$f" && link "$f" "$(basename "$f")"; done
  echo "$REPO_DIR" > "$RE_HOME/repo_path"
}

# ---------------------------------------------------------------- main -----
T0=$SECONDS
FAIL=0
rm -f "$RE_HOME/.done/links"; [ -z "$ONLY" ] && rm -f "$RE_HOME/.setup-complete"

# ghidra/jvm downloads don't need apt -> run them in parallel with apt
run_step ghidra step_ghidra       & P1=$!
run_step jvm_tools step_jvm_tools & P2=$!
run_step node step_node           & P3=$!
run_step apt step_apt || FAIL=1
run_step native_tools step_native_tools & P4=$!
run_step dotnet step_dotnet             & P5=$!
wait $P1 || FAIL=1            # python step wants the pyghidra wheel from Ghidra
run_step python step_python || FAIL=1
for p in $P2 $P3 $P4 $P5; do wait "$p" || FAIL=1; done
if [ $WITH_WINE -eq 1 ] || [ "$ONLY" = wine ]; then run_step wine step_wine || FAIL=1; fi
run_step links step_links || FAIL=1

if [ -z "$ONLY" ]; then
  if [ $FAIL -eq 0 ]; then date -Is > "$RE_HOME/.setup-complete"; log "all done in $((SECONDS-T0))s"
  else echo failed > "$RE_HOME/.setup-complete"; log "finished with failures in $((SECONDS-T0))s (re-run ./setup.sh to retry failed steps)"; fi
fi
exit $FAIL
