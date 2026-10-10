---
name: re-android
description: Reverse engineering Android apps and JVM bytecode (APK, XAPK/APKS bundles, AAB, DEX, JAR/class, Kotlin), including Flutter, React Native/Hermes, Xamarin, Unity and packed apps; patching and re-signing APKs. Use when re-triage reports KIND apk, dex, jar or hermes.
---

# Android / JVM

## Pipeline
```bash
apk-analyze app.apk            # -> work/app.apk/apk/  (≈15-60s)
cat work/app.apk/apk/summary.txt
```
summary.txt covers the package, SDKs, risky flags (debuggable, allowBackup, cleartext), notable permissions, **exported
components and deep links** (attack surface), signer, native libs, the detected framework, and where the app's own
code lives (`app code` line).

Layout: `jadx/sources/` (Java), `jadx/resources/` (AndroidManifest.xml, res/values/strings.xml),
`apktool/` (smali + raw resources), `native/<abi>/*.so`, `hermes/`, `js/`.

## Finding things fast
Bug hunting? `vuln-scan app.apk` ranks exported-component, WebView, intent, provider, crypto and secret leads
(skill re-vulnhunt). The greps below are for manual digging.
```bash
A=work/app.apk/apk; SRC=$A/jadx/sources/<pkg/path from summary>
rg -l 'SecretKeySpec|Cipher.getInstance|MessageDigest' $A/jadx/sources | rg -v '^.*/(androidx|kotlin|com/google)/' | head
rg -n 'https?://' $SRC | head -50                     # endpoints
rg -n '"(api|secret|token|key)[^"]*"\s*[:=,]' -i $SRC  # hardcoded secrets
rg -n 'native ' $SRC                                   # JNI entry points -> native/*.so (skill re-native)
rg -n 'loadLibrary|DexClassLoader|InMemoryDexClassLoader' $A/jadx/sources   # dynamic code loading
cat $A/jadx/resources/res/values/strings.xml | rg -i 'key|secret|url|firebase'
```
- Obfuscated (ProGuard/R8 `a.b.c`): rerun with `apk-analyze app.apk --deobf`, follow strings and Android API calls
  (they can't be renamed), and use `jadx/resources` for real names in the manifest.
- Kotlin: `Intrinsics.checkNotNullParameter(x, "name")` leaks the original parameter names. Coroutines become state machines
  (`invokeSuspend`, `label` switch).
- jadx failed on a method? Check `/* JADX WARNING */` in the file, or read the smali in `apktool/smali*/`.
  Alternative decompiler: `d2j-dex2jar classes.dex -o out.jar && vineflower out.jar outdir/`.

## Frameworks (see the `framework` line)
- **Flutter**: the logic is Dart AOT in `native/<abi>/libapp.so`, and Java is only a shell. Get strings and endpoints from
  `strings -n6 libapp.so`. Full recovery needs blutter (not installed; it needs the matching Dart SDK build). Ghidra on
  libapp.so works but has no symbols.
- **React Native**: `assets/index.android.bundle`. Hermes bytecode goes through `hermes/decompiled.js` (hbc-decompiler).
  Unsupported versions: `hbc-disassembler`. Plain JS goes to `js/webcrack/`. Grep for `fetch(`, `axios`, and API keys.
- **Xamarin / .NET MAUI**: C# DLLs in `assemblies/` or `assemblies.blob` (XALZ-compressed; decompress with lz4 in
  `repy`: header `XALZ`, idx(4), size(4), then lz4 block). Then use skill re-dotnet.
- **Unity**: Mono uses `assets/bin/Data/Managed/Assembly-CSharp.dll` (re-dotnet). IL2CPP uses `libil2cpp.so` +
  `global-metadata.dat`. Il2CppDumper isn't installed, so use Ghidra on libil2cpp.so with metadata strings.
- **Cordova/Capacitor/Ionic**: the app is web code in `assets/www` or `assets/public`.
- **Packers** (Jiagu, Bangcle, SecNeo...): the dex in the APK is a stub. You need runtime dumping (frida on a device,
  not available here). Say so and analyse what you can statically.

## Patching & rebuilding
```bash
apktool d -f app.apk -o app_src        # edit smali/res (e.g. make a check return true: const/4 v0, 0x1 / return v0)
apktool b app_src -o patched-unsigned.apk
zipalign -p -f 4 patched-unsigned.apk patched-aligned.apk
keytool -genkeypair -keystore re.jks -alias re -keyalg RSA -keysize 2048 -validity 10000 -storepass android -keypass android -dname CN=re
apksigner sign --ks re.jks --ks-pass pass:android --out patched.apk patched-aligned.apk && apksigner verify patched.apk
```

## Plain JAR / class files
`jadx -d out app.jar` (or `vineflower app.jar out/`). Spring Boot: app classes in `BOOT-INF/classes`.
`unzip -p app.jar META-INF/MANIFEST.MF` gives Main-Class.

## Dynamic
No Android emulator or device is available in this container. Frida tools are installed (`frida-ps`, `frida-trace`) in case
a device or `frida-server` endpoint is provided (`-H host:port`). Otherwise stay static, or run the extracted JVM logic in
Java/Kotlin by hand-copying the decompiled routine (e.g. to decrypt strings).
