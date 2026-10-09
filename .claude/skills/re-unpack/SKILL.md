---
name: re-unpack
description: Get to the real code inside packed, bundled or wrapped files - UPX and other packers, installers (NSIS, Inno, MSI, InstallShield), archives, Electron/asar and Node pkg apps, firmware images and unknown blobs. Use when re-triage reports KIND upx, archive, electron, asar, unknown-blob, or entropy/sections suggest packing.
---

# Unpacking & carving

Signs of packing: section entropy H>7.2, few imports (LoadLibrary/GetProcAddress only), odd section names
(UPX0, .vmp0, .themida, .aspack, .petite), tiny code + big data, or DIE says `Packer:`/`Protector:`.

## Packers
- **UPX**: `upx -d -o out BIN`. If that fails with "not packed by UPX" even though DIE says UPX, the `UPX!` magic or
  section names were tampered with. Restore the `UPX!` strings and the `UPX0`/`UPX1` names (hex-patch in `repy`) and retry.
- **Generic (MPRESS, ASPack, custom)**: do it dynamically. Run under gdb to the original entry point and dump
  (`gdb -batch -ex 'catch syscall mprotect' ...`, or break after the unpacking loop and `dump memory out.bin START END`),
  then `ghidra-analyze out.bin -- -processor ... -loader BinaryLoader -loader-baseAddr START`.
  Windows PE packers need wine (`./setup.sh --with-wine`) and the same idea with winedbg. Alternatively, emulate the stub
  with unicorn in `repy`.
- **VMProtect/Themida/Enigma**: full devirtualisation is out of scope. Report it, take strings/imports from a runtime dump
  if possible, and analyse the non-virtualised parts.

## Installers & archives
| Format | Command |
|---|---|
| zip/7z/rar/tar/gz/xz/zst/cab/iso/cpio/rpm/deb/dmg(partly) | `7z x -oOUT FILE` |
| NSIS (DIE "Nullsoft") | `7z x -oOUT FILE` (also extracts `$PLUGINSDIR`, and `[NSIS].nsi` script with some versions) |
| Inno Setup | `innoextract -e -d OUT FILE` (`-l` to list) |
| MSI | `msiextract -C OUT FILE` / `msiinfo export FILE File` |
| InstallShield cab | `unshield -d OUT x data1.cab` |
| Squashfs / firmware | `binwalk -e FILE` (`-Me` recursive), `unsquashfs` |
| Android backup/OTA, misc | `binwalk FILE` to locate, `dd`/`repy` to carve |
After extracting, run `re-triage` on the biggest or most interesting members (`find OUT -type f -size +100k | xargs file`).

## Electron / Node
- Find `resources/app.asar` (in the install directory or inside the installer, e.g. NSIS `$PLUGINSDIR/app-64.7z`).
  `asar extract app.asar OUT`. Then `OUT/package.json` → `main` gives the entry point.
- Minified or bundled JS: `webcrack bundle.js -o OUT/` (deobfuscates obfuscator.io code and unpacks webpack and browserify),
  `js-beautify -r file.js`. Native addons (`*.node`) are native libs, so use re-native.
- vercel/pkg executables: the JS source or V8 bytecode is appended to the binary (the triage marker is `pkg/prelude`).
  Look for the payload offset in strings (`PAYLOAD_POSITION`) and carve it. Bytecode-only builds have to be read as V8
  bytecode (hard), so report it.

## Firmware / unknown blobs
```bash
binwalk FILE                 # signatures (filesystems, compressed streams, headers)
binwalk -E FILE              # entropy plot data: flat ~1.0 = encrypted/compressed
binwalk -Me FILE -C OUT      # recursive extraction
strings -n8 FILE | head -100 ; xxd FILE | head -40
```
Bare-metal code: work out the arch from strings, the vendor, or byte patterns (ARM Thumb `push {r4-r7,lr}` = `f0 b5`). Work
out the base address from the vector table (Cortex-M: word 1 = reset handler, so base = that address rounded down) and run
`ghidra-analyze FILE --entry RESET -- -processor ARM:LE:32:Cortex -loader BinaryLoader -loader-baseAddr BASE`.
