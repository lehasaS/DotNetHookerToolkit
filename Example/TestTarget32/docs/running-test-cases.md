# Usage With InjectorCli

## 1) Build TestTarget32

Build `Release | x86` so the EXE is a 32-bit .NET Framework program.

## 2) Run TestTarget32

Run it and note the PID it prints.

You can now attach to it with `InjectorCli`.

## 3) Attach and trace MessageBoxW

1. Press `M` in the target to show a message box.
2. Attach and trace:

```bat
FridaClrInjector.exe --pid <PID> --script hooks\hook_messagebox.js
```

## 4) Attach and trace CreateFileW (via File.WriteAllText)

1. Press `F` in the target to write a temp file.
2. Attach and trace:

```bat
FridaClrInjector.exe --pid <PID> --script hooks\hook_createfilew.js
```

## 5) Managed method tracing (requires ManagedHookHostProj)

1. Build `ManagedHookHostProj` as `Release | x86`.
2. Edit [hook_managed.js](/ManagedHookHostProj/agent/hook_managed.js):
   - `helperDllPath`: path to `ManagedHookHostProj.dll`
   - `targetAssemblyPath`: path to `TestTarget32.exe`
   - `targetTypeName`: `TestTarget32.PotatoVerifier`
   - `targetMethodName`: `CheckIsPotato`
   - `paramSig`: `System.String` (or `System.String|System.Int32`)
3. Run the injector:

```bat
FridaClrInjector.exe --pid <PID> --script "C:\path\to\hook_managed.js"
```

4. Press `P` or `O` in the target and you should see `[script] ...` messages for enter/leave.

