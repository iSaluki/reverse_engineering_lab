---
name: re-python
description: Recover Python source from PyInstaller/py2exe/cx_Freeze executables and .pyc bytecode (any CPython version), and handle Nuitka/Cython/PyArmor-protected apps. Use when re-triage reports KIND pyinstaller or pyc, or strings mention python3x.dll / _MEIPASS / PYZ.
---

# Python executables & bytecode

## Pipeline
```bash
py-unpack app.exe          # -> work/app.exe/py/{extracted/, src/}
ls work/app.exe/py/src     # <entry>.py (pycdc), <entry>.dis.txt (exact `dis` listing), <entry>.pycdas.txt
```
- **Entry script**: the top-level `.pyc` in `extracted/<x>_extracted/` that is not `pyi*`/`pyimod*`. The app's own
  packages often sit in `extracted/<x>_extracted/PYZ*.pyz_extracted/<pkgname>/`. List that directory and skip stdlib
  and site-packages names.
- Decompilation quality by version: ≤3.8 is excellent (decompyle3/uncompyle6). 3.9–3.14 is partial in pycdc, and the
  output is marked `# WARNING: Decompyle incomplete`. For those, **read `<x>.dis.txt`**. It is disassembled by the exact
  same CPython minor version (uv-managed interpreters for 3.8–3.14), so it is complete and reliable. Reconstruct
  the logic from it yourself; it's mechanical.
- Decompile a library module from the PYZ: `pycdc path/mod.pyc`, then
  `uv run --no-project --python 3.X python -c "import dis,marshal,sys;f=open(sys.argv[1],'rb');f.read(16);dis.dis(marshal.load(f))" mod.pyc`.
- Constants and strings fast: `pycdas mod.pyc | rg -i "'.*(key|http|pass)"`.
- Bytecode version: `pycdas x.pyc | head -1`, or the magic number (first 2 bytes, little-endian) via xdis:
  `repy -c "import xdis.magics as m,sys;print(m.magic_int2tuple(int.from_bytes(open(sys.argv[1],'rb').read(2),'little')))" x.pyc`.

## Edge cases
- **Encrypted PYZ** (PyInstaller <6 with `--key`): pyinstxtractor-ng decrypts automatically when it can find `pyimod00_crypto_key`.
- **PyArmor** (`pyarmor_runtime`, `__pyarmor__`): the bytecode is encrypted and decrypted at runtime by a native
  extension. Statically you can only do the native analysis. Dynamically: run it under the same Python version and dump
  code objects (hook `marshal.loads`/`exec`). Report the limitation if you can't execute it.
- **Nuitka** (`__nuitka`, `onefile` temp dir): this is compiled C, not bytecode, so use re-native. Module constants are
  stored in a blob, and the strings are still greppable. Onefile builds extract to `%TEMP%/onefile_*` at runtime; the
  payload is zstd-compressed after the bootstrap.
- **Cython `.so/.pyd`**: native code. Function names keep the `__pyx_pw_<module>_<func>` pattern, and the Python-level
  strings are in `__pyx_k_*`.
- **py2exe**: the code object is in the `PYTHONSCRIPT` resource. **cx_Freeze**: `lib/library.zip` holds the pyc files. Use 7z on both.
- **Plain `.py` obfuscation** (base64/zlib/marshal exec chains): replace `exec` with `print` and peel the layers in `repy`.
  Never `exec` untrusted layers.
