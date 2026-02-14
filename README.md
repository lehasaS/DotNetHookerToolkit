# InjectorCli + ManagedHookHostProj

This repository contains two projects that are designed to be used together:

* [InjectorCli](/InjectorCli/): a **.NET Framework 4.8** console injector built on [frida-clr](https://github.com/frida/frida-clr) (`Frida.dll`)
* [ManagedHookHostProj](/ManagedHookHostProj/): a **.NET Framework 4.8** helper DLL with **native exports** (via  [3F .NET DllExport](https://github.com/3F/DllExport)) used to resolve managed methods to native entrypoints so Frida can attach

These projects target Windows and assume you are instrumenting processes you own or have permission to test.

## Why There Are Two Projects

Frida hooks **native** code addresses. On .NET Framework, managed methods are **JIT-compiled** into native code, but:

* Frida does not ship a stable “hook managed method by name” API for .NET Framework
* Method addresses are not known until the JIT compiles the method

So the overall pattern is:

1. Use `InjectorCli` to attach/spawn a target and load a Frida JavaScript agent.
2. Inside the target, use `ManagedHookHostProj.dll` to:
   * Find a managed method by reflection
   * Force it to JIT (`RuntimeHelpers.PrepareMethod`)
   * Return the method’s native entrypoint (`GetFunctionPointer`)
3. Back in the agent, call `Interceptor.attach(entrypoint, ...)` to trace calls/ log args/ (optionally) alter behavior.

## How They Work Together (Data Flow)

### InjectorCli (C#)

* Creates `Frida.DeviceManager` and selects a device
* Spawns or attaches to a process
* Creates a `Frida.Script` from your JavaScript file and loads it
* Prints messages from the agent via `script.Message`

### Agent (JavaScript)

* Can hook normal Win32 APIs directly (e.g. `CreateFileW`, `MessageBoxW`)
* Can optionally `Module.load()` the managed helper DLL
* Calls exported helpers (e.g. `ResolveMethod`) via `NativeFunction`
* Uses returned addresses to attach hooks

###  ManagedHookHostProj (C# class library with exports)

* Runs inside the target’s CLR
* Uses reflection to locate the method you want by name (+ optional overload signature)
* Forces JIT compilation and returns the native entrypoint address

## Quick Start (32-bit target)

To illustrate how all these work, we will assume that the target process is compiled to target **32-bit** (WoW64) CPU architecture.

### 1) Building `frida-clr` x86

* You need an **x86** `Frida.dll` to inject into an x86 target process.
* Example commands (from a Visual Studio Developer Command Prompt):

```cmd
cd C:\path\to\frida-clr
configure.bat --prefix="%CD%\dist-x86" --build=windows-x86-md

cd build

make.bat

make.bat install
```

Confirm you have:

* `dist-x86\bin\Frida.dll` (PE32)

### 2) Build `InjectorCli` (x86)

* You need to open [InjectorCli.sln](/InjectorCli/InjectorCli.sln) in Visual Studio, and set build target to `Release | x86`.

* Or from a Developer Command Prompt:

```bat
msbuild \InjectorCli\InjectorCli.sln /p:Configuration=Release /p:Platform=x86
```

* If your `Frida.dll` is not at `dist-x86\bin\Frida.dll`, update the reference in [InjectorCli.csproj](/InjectorCli/InjectorCli.csproj) accordingly.

### 3) (Optional) Build `ManagedHookHostProj` (x86)

* You need to open [ManagedHookHostProj.sln](/ManagedHookHostProj/ManagedHookHostProj.sln) in Visual Studio, and set build target to `Release | x86`.

* Or from a Developer Command Prompt:

```cmd
msbuild \ManagedHookHostProj\ManagedHookHostProj.sln /p:Configuration=Release /p:Platform=x86
```

* You can then verify exports by running the following command in the Developer Command Prompt:

```cmd
dumpbin /exports examples\ManagedHookHostProj\bin\Release\ManagedHookHostProj.dll
```

Note: on x86 + StdCall you may see decorated export names (e.g. `_ResolveMethod@16`). The provided agent script includes a fallback that locates decorated names.

### 4) Run: Native tracing (no managed helper needed)

* Attach to an existing PID:

```cmd
FridaClrInjector.exe --pid 1234 --script hooks\hook_createfilew.js
```

* Spawn suspended, inject, resume:

```cmd
FridaClrInjector.exe --spawn "C:\Windows\SysWOW64\notepad.exe" --script hooks\hook_messagebox.js
```

### 5) Run: Managed method resolution + tracing (uses the helper DLL)

* You should first edit [resolve_and_trace_managed.js](/ManagedHookHostProj/agent/resolve_and_trace_managed.js), by setting:

  * `helperDllPath` to the built `ManagedHookHostProj.dll`
  * `targetAssemblyPath`, `targetTypeName`, `targetMethodName`, `paramSig`

* Then run:

```cmd
FridaClrInjector.exe --pid 1234 --script "C:\path\to\resolve_and_trace_managed.js"
```

## Limitations

* **Inlining**: small methods may be inlined in Release builds, and your hook won’t trigger.
* **Overloads**: use `paramSig` to select the correct overload, otherwise you may hook the wrong one.
* **Bitness must match**: x86 target requires x86 injector + x86 `Frida.dll` + x86 helper DLL.
* **Managed object refs are fragile**: the helper’s object-ref helpers are best-effort and should only be used for short-lived logging.

## More Documentation

* Injector docs:
  * [Injector README](/InjectorCli/README.md)
  * [How-it-works](/InjectorCli/injector-docs/how-it-works.md)
  * [Troubleshooting](/InjectorCli/injector-docs/troubleshooting.md)

* Helper DLL docs:
  * [Helper DLL README](/ManagedHookHostProj/README.md)
  * [How-it-works](/ManagedHookHostProj/hook-host-docs/how-it-works.md)
  * [Troubleshooting](/ManagedHookHostProj/hook-host-docs/build-and-troubleshooting.md)