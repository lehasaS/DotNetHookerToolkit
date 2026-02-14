# Build and Troubleshooting

## Build Checklist (x86 / .NET Framework 4.8)

1. Open `ManagedHookHostProj.sln`
2. Select `Release | x86`
3. Build

If you are targeting a **32-bit** process, do not build x64 or AnyCPU for this helper DLL.

## NuGet / DllExport Package

This project uses the NuGet package `DllExport` (namespace `io.github._3F.DllExport`).

If restore fails:

1. Right-click project -> **Manage NuGet Packages**
2. Search for `DllExport` (publisher `github.com` / `3F`)
3. Install or update it
4. Clean + Rebuild

The export generation is performed at build time by the package's MSBuild targets.

## Verify That Exports Exist

Use a Developer Command Prompt:

```
dumpbin /exports bin\Release\ManagedHookHostProj.dll
```

If the export list is empty:

* Make sure the package restored successfully (check `obj\*.nuget.g.props/targets` are present).
* Clean and rebuild.
* Ensure you're building for the correct CPU architecture and modify [ManagedHookHostProj.csproj](/ManagedHookHostProj/ManagedHookHostProj.csproj) accordingly.

## Common Errors

### `The type or namespace name '???' could not be found`

NuGet package not restored/installed. Install `DllExport` package.

### `unsafe code requires the 'unsafe' command line option`

This project uses unsafe code for object ref helpers; `AllowUnsafeBlocks` is enabled in the csproj.
If you copied code into another project, enable unsafe.

### `BadImageFormatException` when loading the helper DLL

Bitness mismatch:

* 32-bit process cannot load a 64-bit helper DLL.
* 64-bit process cannot load a 32-bit helper DLL.

