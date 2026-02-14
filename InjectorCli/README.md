# InjectorCli (frida-clr)

This is a minimal **console injector** for [frida-clr](https://github.com/frida/frida-clr) (Frida .NET bindings), designed for automation and repeatability providing CLI arguments.

## Prerequisites

### 1) Build frida-clr for your target bitness

For a **32-bit** target process, you need an **x86** `Frida.dll`.

This project expects the following path by default:

* `dist-x86\bin\Frida.dll`

If your `Frida.dll` lives somewhere else, edit the `<HintPath>` in:

* [InjectorCli.csproj](InjectorCli.csproj)

### 2) Build the injector as x86

Your injector process must match the target process bitness:

* 32-bit target -> build/run injector as x86
* 64-bit target -> build/run injector as x64

### 3) Permissions

If the target process is elevated / high integrity, run the injector elevated too.

## Build

* Open [InjectorCli.sln](InjectorCli.sln) in Visual Studio and build.

* Or from a Developer Command Prompt, run the command:

```
msbuild InjectorCli.sln /p:Configuration=Release /p:Platform=x86
```

## Running the Injector

* Attach by PID:

```
FridaClrInjector.exe --pid 1234 --script hooks\hook_messagebox.js
```

* Attach by process name (first match):

```
FridaClrInjector.exe --name notepad.exe --script hooks\hook_createfilew.js
```

* Spawn suspended, inject, then resume:

```
FridaClrInjector.exe --spawn "C:\Windows\SysWOW64\notepad.exe" --script hooks\hook_createfilew.js
```

* Spawn with args (args are parsed using Windows `CommandLineToArgvW` rules):

```
FridaClrInjector.exe --spawn "C:\Path\to\app.exe" --args "--flag \"value with spaces\"" --script hooks\hook_createfilew.js
```

## How It Works (High Level)

* `frida-clr` delivers callbacks (e.g. `script.Message`) on a WPF `Dispatcher`.
* WPF apps already have a dispatcher loop, but console apps do not.
* This injector creates a dedicated STA thread and runs `Dispatcher.Run()` so Frida events can be marshalled correctly.

See additional docs:

* [how-it-works.md](/InjectorCli/injector-docs/how-it-works.md)
* [build-and-troubleshooting.md](/InjectorCli/injector-docs/troubleshooting.md)
