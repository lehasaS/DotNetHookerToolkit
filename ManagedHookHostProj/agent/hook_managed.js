'use strict';

/*
  ============================================================
  Generic Managed-Method Resolver + Tracer (Frida 17+) for
  .NET Framework targets (CLR v4) using a DllExport helper DLL.
  ============================================================

  What this script gives you:
  - Resolve a *managed* method by (assembly path, type name, method name, param signature)
  - Force JIT (via helper) and obtain a native entrypoint pointer
  - Follow prestubs/thunks to reach the "real" JIT body (avoids hooking unstable stubs)
  - Interceptor.attach() the real code
  - Log parameters and return value via console.log()
  - Optional return-value forcing for simple scalar returns (demo)

  What you change per target:
  - helperDllPath
  - targetAssemblyPath
  - targetTypeName / targetMethodName
  - paramSig (overload selector)
  - IS_STATIC (method kind)
  - DECODE rules inside onEnter() if params are not a single string

  Assumptions / constraints:
  - Designed primarily for .NET Framework x86 (ia32). Includes some x64 stub patterns but
    the argument decoding logic below is x86-centric (ECX + stack scanning).
  - Inlining can prevent your target method from ever being called. If you control the code,
    compile with NoInlining/NoOptimization. If you don't, hook a caller or a different layer.
  - Tiered compilation / rejit can change entrypoints. For stubborn targets, re-resolve periodically.
*/

// ============================================================
// [1] USER CONFIG – change these for your target
// ============================================================

const CONFIG = {
  // Helper DLL that exports:
  //   ResolveMethod(wchar* asmPath, wchar* typeName, wchar* methodName, wchar* paramSig) -> void*
  //   DescribeObject(void* objRef) -> System.String object ref (best-effort)
  helperDllPath: "C:\\Users\\Saber\\Desktop\\Hook_Tooling\\ManagedHookHostProj.dll",

  // Managed assembly containing the target method.
  // NOTE: must match what the helper expects (often full path).
  targetAssemblyPath: "C:\\Users\\Saber\\Desktop\\Hook_Tooling\\TestTarget32.exe",

  // Fully-qualified type name:
  // Example: "MyNamespace.PotatoVerifier"
  targetTypeName: "TestTarget32.PotatoVerifier",

  // Method name (no args here):
  targetMethodName: "CheckIsPotato",

  // Overload selector: join parameter type full-names with '|'
  // Examples:
  //   (string)          => "System.String"
  //   (string,int)      => "System.String|System.Int32"
  //   (byte[])          => "System.Byte[]"
  //   (object,string)   => "System.Object|System.String"
  //
  // If you have multiple overloads and paramSig is wrong, ResolveMethod may return null or the wrong overload.
  paramSig: "System.String",

  // True for static methods; false for instance methods.
  // For instance methods on x86, `this` is commonly passed in ECX.
  IS_STATIC: false,

  // Optional demo: force scalar return values (e.g., bool/int) to true/1.
  // Do NOT use if return type is object/string unless you can create a valid managed object.
  FORCE_RETURN_TRUE: false,

  // Delay after resume before resolving (helps if assembly/type isn’t loaded yet).
  // For spawn-suspended, 200-800ms is a typical cheap fix.
  RESOLVE_DELAY_MS: 400,

  // How many stack slots to scan for a string parameter (x86).
  // If you have multiple string params, you’ll likely want deterministic decoding instead of scanning.
  STACK_SCAN_SLOTS: 12,
};

// ============================================================
// [2] LOAD HELPER + FIND EXPORTS (handles x86 stdcall decoration)
// ============================================================

function getExportAny(mod, preferred) {
  // On x86/StdCall some toolchains decorate names (e.g. _ResolveMethod@16).
  // Prefer exact name, else fall back to "contains".
  try {
    const addr = mod.getExportByName(preferred);
    console.log(`[+] Using export ${preferred} @ ${addr}`);
    return addr;
  } catch (_) {
    const exps = mod.enumerateExports();
    const hit = exps.find(e => e.name === preferred) || exps.find(e => e.name.includes(preferred));
    if (!hit) throw new Error(`Export not found: ${preferred}`);
    console.log(`[+] Using decorated export for ${preferred}: ${hit.name} @ ${hit.address}`);
    return hit.address;
  }
}

function allocW(s) {
  // Memory.allocUtf16String is fine; Frida 17+ changes mostly affected read/write helpers.
  return (s === null || s === undefined) ? ptr(0) : Memory.allocUtf16String(s);
}

console.log(`[+] arch=${Process.arch} ptrSize=${Process.pointerSize}`);
console.log(`[+] Loading helper: ${CONFIG.helperDllPath}`);

const helper = Module.load(CONFIG.helperDllPath);

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

// ============================================================
// [3] MANAGED TYPE HELPERS (currently: System.String + DescribeObject)
// ============================================================

// .NET Framework string layout (object ref points to MethodTable* first)
//   [MethodTable*][int length][char firstChar...]
function readDotNetString(obj) {
  if (obj.isNull()) return null;
  const len = obj.add(Process.pointerSize).readU32();
  if (len > 0x20000) return `[suspicious length=${len}]`; // sanity guard
  const chars = obj.add(Process.pointerSize + 4);
  return chars.readUtf16String(len);
}

function looksLikeManagedString(p) {
  // Heuristic: check if the "length" field is plausible
  if (p.isNull()) return false;
  try {
    const len = p.add(Process.pointerSize).readU32();
    return len > 0 && len < 0x2000;
  } catch (_) {
    return false;
  }
}

function safeDescribe(objRef) {
  // Best-effort stringification via helper (may call ToString() or similar).
  // WARNING: describing objects can have side effects depending on implementation.
  try {
    const sObj = DescribeObject(objRef);
    if (sObj.isNull()) return "<DescribeObject returned null>";
    return readDotNetString(sObj) ?? "<DescribeObject decode failed>";
  } catch (e) {
    return `<DescribeObject failed: ${e}>`;
  }
}

// ============================================================
// [4] STUB/PRESTUB AVOIDANCE – follow common jump patterns
// ============================================================

/*
  Critical: avoid hooking CLR prestubs/thunks.
  ResolveMethod may return an entrypoint that is just a jump stub.
  Hooking the stub can be unreliable (only runs once, gets patched, etc.).
  We follow common jump patterns to land on the “real” JIT body.
*/
function followJumps(p, maxHops = 16) {
  let cur = ptr(p);

  for (let i = 0; i < maxHops; i++) {
    const b0 = cur.readU8();

    // JMP rel32: E9 xx xx xx xx
    if (b0 === 0xE9) {
      const rel = cur.add(1).readS32();
      const next = cur.add(5).add(rel);
      console.log(`[+] hop${i}: jmp rel32 ${cur} -> ${next}`);
      cur = next;
      continue;
    }

    // JMP rel8: EB xx
    if (b0 === 0xEB) {
      const rel8 = cur.add(1).readS8();
      const next = cur.add(2).add(rel8);
      console.log(`[+] hop${i}: jmp rel8  ${cur} -> ${next}`);
      cur = next;
      continue;
    }

    // JMP [mem]: FF 25 disp32  (x86 absolute / x64 RIP-relative)
    if (b0 === 0xFF && cur.add(1).readU8() === 0x25) {
      const disp = cur.add(2).readS32();

      if (Process.pointerSize === 8) {
        // x64: FF 25 disp32 uses RIP-relative memory slot at (cur + 6 + disp)
        const slot = cur.add(6).add(disp);
        const next = slot.readPointer();
        console.log(`[+] hop${i}: jmp [rip+disp] ${cur} -> ${next} (slot=${slot})`);
        cur = next;
        continue;
      } else {
        // x86: various encodings exist; this is best-effort and worked in your case.
        const slot = ptr(cur.add(2).readU32());
        const next = slot.readPointer();
        console.log(`[+] hop${i}: jmp [abs] ${cur} -> ${next} (slot=${slot})`);
        cur = next;
        continue;
      }
    }

    // x64: mov rax, imm64; jmp rax  (48 B8 ... FF E0)
    if (Process.pointerSize === 8 &&
        b0 === 0x48 && cur.add(1).readU8() === 0xB8 &&
        cur.add(10).readU8() === 0xFF && cur.add(11).readU8() === 0xE0) {
      const imm = cur.add(2).readU64();
      const next = ptr(imm);
      console.log(`[+] hop${i}: mov rax; jmp rax ${cur} -> ${next}`);
      cur = next;
      continue;
    }

    break;
  }

  return cur;
}

function modNameForAddress(p) {
  const m = Process.findModuleByAddress(p);
  return m ? `${m.name}+0x${p.sub(m.base)}` : "<no module>";
}

// ============================================================
// [5] RESOLVE + HOOK
// ============================================================

console.log(`[+] Waiting ${CONFIG.RESOLVE_DELAY_MS}ms after resume before resolving/hooking...`);

setTimeout(() => {
  // Resolve managed method -> entrypoint pointer (may be prestub)
  const entry = ResolveMethod(
    allocW(CONFIG.targetAssemblyPath),
    allocW(CONFIG.targetTypeName),
    allocW(CONFIG.targetMethodName),
    allocW(CONFIG.paramSig)
  );

  console.log(`[+] ResolveMethod -> ${entry} (${modNameForAddress(entry)})`);

  if (entry.isNull()) {
    console.log("[-] ResolveMethod failed:");
    console.log("    - type/method not found");
    console.log("    - assembly not loaded yet");
    console.log("    - overload mismatch (paramSig wrong)");
    console.log("    - JIT/PrepareMethod failed");
    return;
  }

  // Follow stub/thunk jumps to real code
  const real = followJumps(entry);
  console.log(`[+] Final hook addr -> ${real} (${modNameForAddress(real)})`);
  console.log(`[+] Hooking ${CONFIG.targetTypeName}.${CONFIG.targetMethodName}(${CONFIG.paramSig}) @ ${real}`);

  // ============================================================
  // [6] PARAMETER DECODING (x86-focused)
  // ============================================================
  //
  // IMPORTANT:
  // - On x86 .NET Framework, `this` for instance methods is commonly in ECX.
  // - Parameters may not show up in Frida's args[] in a useful way for JITted code.
  // - This template uses stack scanning to locate a System.String parameter.
  //
  // If you have multiple parameters:
  // - Update this section to decode deterministically (recommended).
  // - For basic scalars (int/bool), you can read stack slots as U32/S32.
  // - For object refs, you can log the pointer or use safeDescribe(objRef).
  //

  Interceptor.attach(real, {
    onEnter(args) {
      const ctx = this.context;

      // x86: instance 'this' commonly in ECX; static: no 'this'
      const thisPtr = CONFIG.IS_STATIC ? ptr(0) : ptr(ctx.ecx);

      // x86 stack pointer
      const esp = ptr(ctx.esp);

      // ---- Example decoder: find first plausible System.String near top of stack ----
      // Works well for methods with a single string param.
      let arg0 = ptr(0);
      let arg0Str = null;

      for (let i = 1; i <= CONFIG.STACK_SCAN_SLOTS; i++) {
        const candidate = esp.add(i * 4).readPointer();
        if (looksLikeManagedString(candidate)) {
          arg0 = candidate;
          arg0Str = readDotNetString(candidate);
          break;
        }
      }

      // ---- Optional: richer object logging (can have side effects) ----
      // const arg0Desc = arg0.isNull() ? null : safeDescribe(arg0);

      console.log(
        `[ENTER] ${CONFIG.targetTypeName}.${CONFIG.targetMethodName} ` +
        `this=${thisPtr} arg0=${arg0} arg0Str=${JSON.stringify(arg0Str)} ` +
        `ecx=${ptr(ctx.ecx)} edx=${ptr(ctx.edx)} esp=${esp}`
      );

      // If you need more params, add them here. Examples:
      //
      // 1) If you *know* param1 is an Int32 and lives at a stable offset, do:
      //    const param1 = esp.add(?? * 4).readS32();
      //
      // 2) If you have an object ref and want a best-effort string:
      //    const obj = esp.add(?? * 4).readPointer();
      //    console.log(`obj=${obj} desc=${safeDescribe(obj)}`);
      //
      // 3) For byte[] you’ll likely want helper support (length + element data),
      //    or log pointer + describe first.
    },

    onLeave(retval) {
      // Scalar return values (bool/int) are typically returned in EAX; Frida provides it as retval.
      const before = retval.toInt32();
      console.log(`[LEAVE] ${CONFIG.targetTypeName}.${CONFIG.targetMethodName} retval(int32)=${before}`);

      // Demo: force return to true (ONLY safe for scalar bool/int cases)
      if (CONFIG.FORCE_RETURN_TRUE) {
        retval.replace(ptr(1));
        console.log(`[LEAVE] forced retval -> 1`);
      }

      // If return type is object/string, you MUST replace with a valid managed object ref.
      // That usually requires a helper export like MakeString()/BoxInt32() etc.
    }
  });

}, CONFIG.RESOLVE_DELAY_MS);