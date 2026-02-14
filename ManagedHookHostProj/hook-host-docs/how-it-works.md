# How It Works

## What This DLL Is For

Frida is great at intercepting **native** code. On .NET Framework, managed methods are JIT compiled and live as native code too, but Frida doesn't provide a stable "hook managed method by name" API for .NET Framework out of the box.

This helper DLL provides a bridge:

1. Frida loads this DLL into the target process (`Module.load()`).
2. Frida calls an exported function (`ResolveMethod`) which runs inside the CLR.
3. `ResolveMethod` uses reflection to find the target method, forces it to JIT compile, then returns the native entrypoint address.
4. Frida attaches `Interceptor` to that address and can trace calls.

## ResolveMethod

Signature (native):

* `IntPtr ResolveMethod(wchar_t* assemblyPath, wchar_t* typeName, wchar_t* methodName, wchar_t* paramSig)`

Inputs:

* `assemblyPath`: full path to the managed assembly (EXE/DLL) containing the method.
* `typeName`: full type name, e.g. `MyNamespace.PotatoVerifier`.
* `methodName`: method name, e.g. `CheckIsPotato`.
* `paramSig`: optional overload selector. Empty string means "pick first method with this name".
  * Format: `ParameterTypeFullName|ParameterTypeFullName|...`
  * Example: `System.String|System.Int32`

Output:

* Returns the native code pointer for that method body, or `NULL` on failure.

## Managed Object Helpers

These exports operate on **raw managed object references** (`IntPtr`) and are provided for logging/debugging:

* `DescribeObject(IntPtr objRef)` -> returns a managed `System.String` object reference describing the object
* `MakeString(wchar_t* text)` -> returns a managed `System.String` object reference
* `BoxInt32(int v)` / `BoxBool(int v)` -> return boxed object references

### Safety Notes

These helpers are intentionally "best effort" and **fragile**:

* Managed object pointers can move during GC; don't persist these pointers.
* Some property getters can have side effects or throw; `DescribeObject` tries to be conservative but isn't perfect.

## Why the CPU architecture matters

`Module.load()` loads a DLL into the target process, so the helper DLL must match the target process bitness:

* 32-bit target -> build helper DLL x86
* 64-bit target -> build helper DLL x64

## Common Reasons Hooks Don't Trigger

* The method was inlined by the JIT (common for small methods in Release).
* You resolved the wrong overload (use `paramSig`).
* The target assembly path is wrong or the assembly was loaded from a different location.

