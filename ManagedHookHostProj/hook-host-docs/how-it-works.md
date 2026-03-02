# How It Works

## Problem Statement: What This DLL Is For

Frida is great at intercepting **native** code. On .NET Framework, managed methods are JIT compiled and live as native code too, but Frida doesn't provide a stable "hook managed method by name" API for .NET Framework out of the box.

This helper provides a bridge to that gap:

1. Frida loads this DLL into the target process (`Module.load()`).
2. Frida calls an exported function (`ResolveMethod`) which runs inside the CLR.
3. `ResolveMethod` uses reflection to find the target method, forces it to JIT compile, then returns the native entrypoint address.
4. Frida attaches `Interceptor` to that address and can trace calls.

## Runtime Flow

1. Injector loads your Frida script.
2. Script loads `ManagedHookHostProj.dll` in the target process (`Module.load()`).
3. Script calls `ResolveMethod` (or `ResolveMethodByToken`).
4. Helper finds the method via reflection, calls `RuntimeHelpers.PrepareMethod`, returns native entrypoint pointer.
5. Script attaches `Interceptor` to that pointer.

## Why the New Helper Shape Is Safer

The high-risk pattern is passing raw managed object refs and decoding CLR object layouts in JS.

Current preferred pattern:

* JS asks helper for unmanaged UTF-16 text (`DescribeObjectUtf16`)
* JS frees that text with `FreeUtf16`
* JS reads/writes by-ref primitives through helper exports (`ReadInt32`, `WriteInt32`, `WriteBool`)
* JS reads helper diagnostics through `GetLastErrorUtf16` when resolution/inspection fails

This removes:

* CLR string layout assumptions in JS
* direct JS `Memory.write*` calls for by-ref primitives

## Exports and Intended Use

Resolution:

* `ResolveMethod(assemblyPath, typeName, methodName, paramSig)`
* `ResolveMethodByToken(assemblyPath, typeName, methodToken)`

Object inspection:

* `DescribeObjectUtf16(objRef)` -> unmanaged UTF-16 pointer
* `FreeUtf16(ptr)` -> frees pointer returned by `DescribeObjectUtf16`

Diagnostics:

* `GetLastErrorUtf16()` -> unmanaged UTF-16 pointer (thread-local last helper error)
* `ClearLastError()` -> clear thread-local error
* `GetManagedStackTraceUtf16()` -> managed stack of current thread

All three UTF-16-returning diagnostics follow the same ownership rule: read then `FreeUtf16(ptr)`.

Primitive by-ref helpers:

* `ReadInt32(ptr)`
* `WriteInt32(ptr, value)`
* `WriteBool(ptr, 0|1)`

Legacy compatibility (raw managed refs):

* `DescribeObject`, `MakeString`, `BoxInt32`, `BoxBool`

Use these only when unavoidable.

## Threading and Last-Error Semantics

* `_lastError` is thread-local (`[ThreadStatic]`), so concurrent hooks do not clobber each other.
* Error text is set only by helper operations on the current thread.
* `GetLastErrorUtf16` returns the current thread's error text.

## UTF-16 Pointer Ownership

The helper allocates UTF-16 buffers with unmanaged memory and tracks helper-owned pointers.

Rules:

1. Read the string immediately in JS.
2. Call `FreeUtf16(ptr)` when done.
3. Never write to returned buffers.

Implementation detail:

* `FreeUtf16` ignores unknown pointers and is idempotent for helper-owned pointers.
* `GetLastErrorUtf16` additionally reclaims the previous per-thread error buffer automatically to reduce leak risk.

## Resolution Theory: Signature vs Metadata Token

`ResolveMethod` with `paramSig` is easy to configure, but can miss if signature text is wrong.

`ResolveMethodByToken` is stricter:

* Use token from dnSpy/ILSpy metadata
* Avoids overload ambiguity

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

## x86 Calling Convention Notes

Exports are standardized to `cdecl`.

In Frida on ia32, create `NativeFunction` with `{ abi: "cdecl" }`.

Managed method argument placement on x86 varies by method shape/JIT stub. For instance methods, `ECX` often holds `this`; by-ref args are often observed in `EDX` for common cases. Always verify against observed behavior in your target.

## Managed Object Helpers

These exports operate on **raw managed object references** (`IntPtr`) and are provided for logging/debugging:

* `DescribeObject(IntPtr objRef)` -> returns a managed `System.String` object reference describing the object
* `MakeString(wchar_t* text)` -> returns a managed `System.String` object reference
* `BoxInt32(int v)` / `BoxBool(int v)` -> return boxed object references

### Safety Notes

These helpers are intentionally "best effort" and **fragile**:

* Managed object pointers can move during GC; don't persist these pointers.
* Some property getters can have side effects or throw; `DescribeObject` tries to be conservative but isn't perfect.

## Script Model (Single vs Multi Hook)

* [hook_managed.js](agent/hook_managed.js):
  * one target method
  * simplest path for initial validation
* [multihook_managed.js](agent/multihook_managed.js):
  * list of hook targets
  * per-target decoder selection
  * optional per-target by-ref mutation (`mutateRefTo`)

The multi-hook script includes a guard for the `noargs/noargs_state` path so `thisPtr` is always explicitly returned in decoded state.

## Why the CPU architecture matters

`Module.load()` loads a DLL into the target process, so the helper DLL must match the target process bitness:

* 32-bit target -> build helper DLL x86
* 64-bit target -> build helper DLL x64

## Common Reasons Hooks Don't Trigger

* The method was inlined by the JIT (common for small methods in Release).
* You resolved the wrong overload (use `paramSig`).
* The target assembly path is wrong or the assembly was loaded from a different location.

