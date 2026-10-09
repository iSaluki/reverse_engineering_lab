---
name: re-dotnet
description: Decompile and analyse .NET assemblies (C#/VB/F# exe and dll, .NET Framework/Core/5+, Unity Mono Assembly-CSharp.dll, Xamarin DLLs) with ILSpy (ilspycmd) and dnfile, including obfuscated and single-file-bundled apps. Use when re-triage reports KIND dotnet.
---

# .NET

## Pipeline
```bash
dotnet-decompile App.exe            # -> work/App.exe/dotnet/src (C# project, one file per type) + types.txt
rg -n 'static void Main|WinMain' work/App.exe/dotnet/src | head
rg -ln 'HttpClient|WebClient|Aes|Rijndael|RSA|DES|Process.Start|Registry|DllImport' work/App.exe/dotnet/src
```
- Decompiled C# is usually close to the original source. Read it like normal code.
- `ilspycmd -il ...` (or `dotnet-decompile X --il`) gives the IL, for when the C# output is wrong or obfuscated control flow
  confuses it.
- Single type: `ilspycmd -t Namespace.Type App.exe`. List types: `ilspycmd -l cisde App.exe`.
- Embedded resources (often encrypted payloads or configs): the project export writes them next to the .cs files
  (`*.resources`, raw blobs). Search for `GetManifestResourceStream` to find who reads them.
- P/Invoke: `[DllImport("x.dll")]` points to native code, so analyse that DLL with re-native.

## Edge cases
- **Mixed-mode / C++/CLI** (ILonly=False in triage): managed parts via ILSpy, native parts via `ghidra-analyze`.
- **Single-file bundle** (`dotnet publish -p:PublishSingleFile`): a native apphost with the DLLs appended. Triage shows a
  native PE/ELF with a big overlay and the strings `.NET`/`DOTNET_`. Extract with `repy`: search for the bundle signature
  (sha256 of ".net core bundle") in the file. The bundle header that follows has a manifest of (offset, size, type, path) entries,
  and entries may be deflate-compressed (.NET 6+). Easier route: `7z l` sometimes lists them; otherwise carve the `MZ`
  headers that sit after the apphost and check each with `dnfile`.
- **ReadyToRun / NativeAOT**: R2R still contains IL (ILSpy works). NativeAOT has no IL, so it's native: use re-native
  (look for `S_P_CoreLib_` symbols).
- **Obfuscators** (ConfuserEx, .NET Reactor, SmartAssembly, Dotfuscator; DIE names them): de4dot isn't available (Windows-
  oriented). Work around it: names are mangled but the logic decompiles. String encryption usually goes through one static
  `string Decrypt(int)` method. Reimplement it in Python (`repy`) or C# (`dotnet` SDK 10 is installed: `dotnet new
  console`, paste the routine, `dotnet run`) and decrypt the constants. Control-flow flattening means you follow the
  switch dispatcher variable.
- **Unity**: start with `Assembly-CSharp.dll`; game logic lives in MonoBehaviour subclasses (`Update`, `Start`).

## Running
The .NET 10 SDK and runtime are installed, so a .NET Core/5+ console app (`dotnet App.dll`) can run under `strace`/`timeout`
if you need dynamic confirmation. .NET Framework or WinForms apps need Windows (wine + mono isn't installed by default).
