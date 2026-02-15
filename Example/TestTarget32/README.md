# TestTarget32

`TestTarget32` is a tiny **.NET Framework 4.8** **x86** console program meant to be an easy target for:

- native API tracing hooks (e.g. `MessageBoxW`, `CreateFileW`)
- managed method resolution/tracing via `ManagedHookHostProj` + Frida `Interceptor.attach()`

This is intentionally not “realistic”; it exists so you can validate your build + injection pipeline quickly.

## Build

Open:

- `examples\\TestTarget32\\TestTarget32.sln`

Build:

- `Release | x86`

Or from a Developer Command Prompt:

```bat
msbuild examples\\TestTarget32\\TestTarget32.sln /p:Configuration=Release /p:Platform=x86
```

## Run

Start the EXE and note the PID printed on startup.

Then use the keyboard menu:

- `M` -> calls `MessageBoxW`
- `F` -> writes a temp file (`File.WriteAllText`), typically triggers `CreateFileW`
- `P` -> calls managed `PotatoVerifier.CheckIsPotato(string)`
- `O` -> calls managed overload `PotatoVerifier.CheckIsPotato(string,int)`

## Hooking

Use `InjectorCli` to attach or spawn.

Native hooks:

- `examples\\InjectorCli\\hooks\\trace_messagebox.js`
- `examples\\InjectorCli\\hooks\\hook_createfilew.js`
- `examples\\InjectorCli\\hooks\\change_messagebox_text.js`

Managed tracing:

- `examples\\ManagedHookHostProj\\agent\\resolve_and_trace_managed.js`

Update that agent script with:

- `targetAssemblyPath` -> path to `TestTarget32.exe`
- `targetTypeName` -> `TestTarget32.PotatoVerifier`
- `targetMethodName` -> `CheckIsPotato`
- `paramSig` -> `System.String` (or `System.String|System.Int32` for the overload)

