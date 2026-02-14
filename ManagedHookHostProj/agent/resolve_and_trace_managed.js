'use strict';
// Managed-method resolver/tracer for .NET Framework using a DllExport helper.
//
// - Uses Module.load() to load helper by path (Process.getModuleByName() is for already-loaded modules).
// - Uses Frida 17+ pointer read APIs (ptr.readUtf16String(), etc.).
// - Logs using console.log() only.
// - Handles x86 stdcall name decoration (_ResolveMethod@16, etc.)

// Example: use ManagedHookHostProj.dll to resolve a managed method to a native entrypoint
// and attach a tracer to it.
//
// Notes:
// - This is for .NET Framework targets where you know the method exists in the target assembly.
// - Inlining can prevent calls from hitting the method body (and thus your hook).
// - Bitness must match: x86 helper DLL for x86 target processes.

const helperDllPath = "C:\\\\Path\\\\To\\\\ManagedHookHostProj.dll";

// The managed assembly containing the method you want to trace.
const targetAssemblyPath = "C:\\\\Path\\\\To\\\\my_application.exe";
const targetTypeName = "MyNamespace.PotatoVerifier";
const targetMethodName = "CheckIsPotato";

// Optional overload selection: join parameter type full-names with '|'
// Example for (string,int): "System.String|System.Int32"
const paramSig = "System.String";

// If you know the method is static, set this true.
// For instance methods, args[0] is `this` and args[1] is first param.
const IS_STATIC = false;

// --- load helper ---
const helper = Module.load(helperDllPath);
console.log(`[+] Loaded helper module from: ${helperDllPath}`);

// --- export lookup with x86 decoration fallback ---
function getExportAny(mod, preferred) {
  // On x86/StdCall some toolchains decorate names (e.g. _ResolveMethod@16).
  // Prefer the exact name, but fall back to a contains-match.
  // Prefer exact name, but fall back to decorated names on x86 stdcall.
  try {
    const addr = mod.getExportByName(preferred);
    console.log(`[+] Using export ${preferred} @ ${addr}`);
    return addr;
  } catch (e) {
    const exps = mod.enumerateExports();
    const hit = exps.find(x => x.name === preferred) || exps.find(x => x.name.includes(preferred));
    if (!hit) {
      throw new Error(`Export not found: ${preferred}`);
    }
    console.log(`[+] Using decorated export for ${preferred}: ${hit.name} @ ${hit.address}`);
    return hit.address;
  }
}

const ResolveMethod = new NativeFunction(
  getExportAny(helper, "ResolveMethod"),
  'pointer',
  ['pointer', 'pointer', 'pointer', 'pointer']
);

const DescribeObject = new NativeFunction(
  getExportAny(helper, "DescribeObject"),
  'pointer',
  ['pointer']
);

// --- helpers ---
function allocW(s) {
  // New-style: Memory.allocUtf16String is still fine; the newer change is about reading/writing.
  return (s === null || s === undefined) ? ptr(0) : Memory.allocUtf16String(s);
}


function readDotNetString(obj) {
  // .NET Framework string layout:
  // [MethodTable*][int length][char firstChar...]
  if (obj.isNull()) return null;

  // New-style reads:
  const len = obj.add(Process.pointerSize).readU32();
  if (len > 0x20000) return `[suspicious length=${len}]`; // sanity guard
  const chars = obj.add(Process.pointerSize + 4);
  return chars.readUtf16String(len);
}

function safeDescribe(objRef) {
  try {
    const sObj = DescribeObject(objRef);
    if (sObj.isNull()) return "<DescribeObject returned null>";
    const s = readDotNetString(sObj);
    return s ?? "<DescribeObject string decode failed>";
  } catch (e) {
    return `<DescribeObject failed: ${e}>`;
  }
}

// --- resolve target method ---
const addr = ResolveMethod(
  allocW(targetAssemblyPath),
  allocW(targetTypeName),
  allocW(targetMethodName),
  allocW(paramSig)
);

console.log(`[+] ResolveMethod -> ${addr}`);

if (addr.isNull()) {
  console.log("[-] ResolveMethod failed (type/method not found, assembly not loaded yet, overload mismatch, or JIT failed).");
} else {
  console.log(`[+] Hooking ${targetTypeName}.${targetMethodName} @ ${addr}`);

  Interceptor.attach(addr, {
    onEnter(args) {
      // Calling convention note:
      // - For instance methods: args[0]=this, args[1]=param0
      // - For static methods:   args[0]=param0
      const thisPtr = IS_STATIC ? ptr(0) : args[0];
      const arg0 = IS_STATIC ? args[0] : args[1];

      let arg0Str = null;
      try { arg0Str = readDotNetString(arg0); } catch (_) {}

      // Optional: For richer logging for complex objects,
      //           you can also ask the helper to DescribeObject()
      //           for best-effort logging
      //
      // const descObj = safeDescribe(arg0);
      //
      // const desc = readDotNetString(descObj);

      console.log(
        `[ENTER] ${targetTypeName}.${targetMethodName} ` +
        `this=${thisPtr} arg0=${arg0} arg0Str=${JSON.stringify(arg0Str)}`
      );
    },

    onLeave(retval) {
      // NOTE: if method returns object/string, retval is an object ref.
      // If it returns int/bool, retval is scalar. Here we log both ways safely.
      let asInt = null;
      try { asInt = retval.toInt32(); } catch (_) {}

      console.log(`[LEAVE] ${targetTypeName}.${targetMethodName} retval=${retval} (int32=${asInt})`);

      // If you want to change return values, do it here — but only when you know the return type.
      // Example for bool return:
      // retval.replace(ptr(1));
      //
      // Example for string return requires a helper export like MakeString(), then retval.replace(stringObjRef).
    }
  });
}

