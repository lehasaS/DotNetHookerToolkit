# ManagedHookHostProj (DllExport helper)

This project builds a **.NET Framework 4.8** class library that exposes a few **native exports** (via `io.github._3F.DllExport`) so a Frida agent can:

* Resolve a managed method by `AssemblyPath + TypeName + MethodName (+ optional parameter signature)`
* Force JIT compilation (`RuntimeHelpers.PrepareMethod`)
* Get the method's **native entrypoint** (`GetFunctionPointer`) so you can `Interceptor.attach()` to it

It also includes a couple of *best-effort* helper exports for logging managed objects.

This is intended for **legitimate diagnostics and instrumentation** of applications you own or have permission to test. Managed hooking by address is inherently fragile; see the docs for caveats.

## What This Exposes

Primary exports (preferred):

* `ResolveMethod` (cdecl): resolve by `assemblyPath + typeName + methodName + paramSig`
* `ResolveMethodByToken` (cdecl): resolve by metadata token
* `DescribeObjectUtf16` (cdecl): describe managed object, returned as unmanaged UTF-16 pointer
* `FreeUtf16` (cdecl): frees memory from `DescribeObjectUtf16`
* `GetLastErrorUtf16` (cdecl): thread-local helper error text as unmanaged UTF-16 pointer
* `ClearLastError` (cdecl): clears thread-local helper error text
* `GetManagedStackTraceUtf16` (cdecl): managed stack trace for current thread
* `ReadInt32` (cdecl)
* `WriteInt32` (cdecl)
* `WriteBool` (cdecl)

Legacy compatibility exports (use sparingly):

* `MakeString`, `BoxInt32`, `BoxBool`, `DescribeObject`
* These return raw managed object refs and are retained for old scripts only.

## Error and Memory Model

* Helper errors are **thread-local** (`_lastError` is per-thread), so hooks on one thread do not overwrite another thread's error text.
* `DescribeObjectUtf16`, `GetLastErrorUtf16`, and `GetManagedStackTraceUtf16` return unmanaged UTF-16 pointers.
* Free these pointers with `FreeUtf16`.
* `GetLastErrorUtf16` also reclaims its previous per-thread buffer automatically to reduce leaks if the caller forgot to free.

## Calling Convention

Exports are standardized to **cdecl** (including x86), which removes most stdcall decoration ambiguity in Frida scripts.

In scripts, use:

* `new NativeFunction(addr, ret, args, { abi: "cdecl" })` on ia32

# Output

Build output (example):

* `bin\Release\ManagedHookHostProj.dll`

You load this DLL into the target process from your Frida JavaScript using `Module.load(...)`.

# Prerequisites

* For building the project inside Visual Studio, you need Visual Studio with **.NET Framework 4.8** targeting pack (Developer Pack).
* NuGet restore enabled (the project uses the `DllExport` NuGet package).
* Determine your target's CPU architecture so that you can build this project for the same architecture.

# Building

* The steps below will explain how to build the project for  **x86** assuming the target process is 32-bit.

## Building in Visual Studio

1. Open `ManagedHookHostProj\ManagedHookHostProj.sln`
2. Select `Release | x86`
3. Build

If NuGet restore fails, open **Manage NuGet Packages** and install/upgrade the `DllExport` package (namespace `io.github._3F.DllExport`). A pop-up will appear, then select the following configuration as shown:

![How to configure .NET DllExport](/images/ConfiguringDllExport.png)


## Build via Developer Command Prompt

* First download [DllExport.bat](https://github.com/3F/DllExport/releases/) from the **.NET DllExport** repository, and place the file in the root of this project.

* Then run the following command:
```
DllExport.bat -action Configure
```

* Again, a pop-up will appear just as shown above, select the [ManagedHookHostProj.sln](ManagedHookHostProj.sln) file, then set the same configuration as shown in the image above.

* To build the solution, you can then run the following command:

```
msbuild ManagedHookHostProj.sln /p:Configuration=Release /p:Platform=x86
```

# Verify Exports after building

To ensure that the exported functions we wanted are there, from a **Developer Command Prompt** run the following command:

```
dumpbin /exports bin\Release\ManagedHookHostProj.dll
```

You should see exports like:

![Exported functions in ManagedHookHostProj.dll](/images/ManagedHookHostProjDllExports.png)

On **x86 + StdCall**, some toolchains decorate export names (e.g. `_ResolveMethod@16`). The provided agent [hook_managed.js](agent/hook_managed.js) includes a fallback that will locate decorated names if needed.

## Agent Scripts

* [hook_managed.js](agent/hook_managed.js): compact single-hook template
* [multihook_managed.js](agent/multihook_managed.js): multi-target framework with per-target decoders


# Usage With the Injector
For usage with the injector project and further details, see:

* [how-it-works.md](hook-host-docs/how-it-works.md)
* [build-and-troubleshooting.md](hook-host-docs/build-and-troubleshooting.md)
