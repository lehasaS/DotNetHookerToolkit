'use strict';

/*
  ============================================================
  Generic Managed-Method Resolver + Tracer (Frida 17+) for
  .NET Framework targets (CLR v4) using a DllExport helper DLL.
  ============================================================

  What this script gives you:
  - Resolve a *managed* method by (assembly path, type name, method name, param signature)
  - Obtain a native entrypoint pointer (may be a prestub/thunk)
  - Follow common prestub/thunk jump patterns to the “real” JIT body
  - Interceptor.attach() the real code
  - Log parameters + return value
  - Optional return-value forcing for *scalar* returns (demo)
  - Optional: create/box managed values via helper (MakeString/BoxInt32/BoxBool)

  Key pitfall fixed here:
  - On x86, your helper exports are *not decorated* (dumpbin shows ResolveMethod, not _ResolveMethod@16),
    which usually means the export uses cdecl (NOT stdcall). Forcing stdcall can cause stack imbalance
    and show up as “system error”. We auto-detect ABI.

  Assumptions / constraints:
  - Primarily aimed at .NET Framework x86 (ia32). Some x64 stub patterns are included.
  - Param decoding is x86-centric (ECX + stack scanning). For multi-params, you should decode
    deterministically rather than scanning.
  - Inlining can prevent your method body from ever executing. If you control the code, add
    NoInlining/NoOptimization. If you don’t, hook a caller or lower layer.
*/

// ============================================================
// [1] USER CONFIG – change these for your target
// ============================================================

const CONFIG = {
  // Helper DLL (must match target bitness: x86 helper for x86 process)
  helperDllPath: "C:\\Users\\Saber\\Desktop\\Hook_Tooling\\ManagedHookHostProj.dll",

  // Managed assembly containing the method you want to resolve.
  // IMPORTANT: this must be what the helper expects (often the exact file path the CLR loads).
  targetAssemblyPath: "C:\\Users\\Saber\\Desktop\\Hook_Tooling\\TestTarget32.exe",

  // Fully-qualified managed type name:
  targetTypeName: "TestTarget32.PotatoVerifier",

  // Method name only:
  targetMethodName: "CheckIsPotato",

  // Overload selector: join parameter type full-names with '|'
  // Examples:
  //   (string)          => "System.String"
  //   (string,int)      => "System.String|System.Int32"
  //   (byte[])          => "System.Byte[]"
  //   (object,string)   => "System.Object|System.String"
  paramSig: "System.Boolean",

  // True for static methods; false for instance methods.
  // x86 instance 'this' commonly in ECX.
  IS_STATIC: false,

  // Demo-only: force scalar return values to true/1.
  // Do NOT enable if return type is object/string unless you replace with a valid managed object ref.
  FORCE_DIFFERENT_RETURN: true,

  // Delay after resume before resolving. Helps if assembly/type isn’t loaded yet.
  RESOLVE_DELAY_MS: 0,

  // Stack scan slots for finding a string parameter (x86).
  // For multi-param methods, prefer deterministic decoding.
  STACK_SCAN_SLOTS: 12,

  // Jump-following hops when walking prestubs/thunks.
  MAX_JUMP_HOPS: 16,
};

// ============================================================
// [2] BASIC UTILITIES
// ============================================================

function allocW(s) {
  return (s === null || s === undefined) ? ptr(0) : Memory.allocUtf16String(s);
}

function modNameForAddress(p) {
  const m = Process.findModuleByAddress(p);
  return m ? `${m.name}+0x${p.sub(m.base)}` : "<no module>";
}

function rangeFor(p) {
  try { return Process.findRangeByAddress(p); } catch (_) { return null; }
}

function isReadable(p) {
  const r = rangeFor(p);
  return r !== null && r.protection.includes('r');
}

function isExecutable(p) {
  const r = rangeFor(p);
  return r !== null && r.protection.includes('x');
}

function dumpRange(label, p) {
  const r = rangeFor(p);
  if (!r) {
    console.log(`[!] ${label}: ${p} -> <no range>`);
    return;
  }
  const end = r.base.add(r.size);
  console.log(
    `[+] ${label}: ${p} -> ${r.base}..${end} prot=${r.protection} file=${r.file ? r.file.path : "<anon>"}`
  );
}

function logNativeStackTrace(context) {
    try {
        console.log("[*] Native stack trace:\n" + Thread.backtrace(context, Backtracer.FUZZY)
            .map(DebugSymbol.fromAddress).join("\n"));
    } catch (err) {
        logError("Failed to log native stack: " + err.message);
    }
}


console.log(`[+] arch=${Process.arch} ptrSize=${Process.pointerSize}`);
console.log(`[+] Loading helper: ${CONFIG.helperDllPath}`);

// ============================================================
// [3] LOAD HELPER + EXPORT RESOLUTION WITH ABI AUTO-DETECT
// ============================================================

const helper = Module.load(CONFIG.helperDllPath);

/*
  On x86, export name decoration is a strong hint for calling convention:
  - stdcall often looks like: _ResolveMethod@16
  - cdecl often looks like: ResolveMethod  (undecorated) or _ResolveMethod (toolchain-dependent)
  - Check dumpbin output for the helper DLL, if it shows undecorated names, we default to cdecl on ia32 unless we find @N decoration.
*/
function resolveExport(mod, preferred) {
  const exps = mod.enumerateExports();

  // 1) Exact match first
  let hit = exps.find(e => e.name === preferred);

  // 2) If not found, look for decorated stdcall (_Name@N) or any contains-match
  if (!hit) {
    // prefer stdcall-style decoration when present
    hit = exps.find(e => e.name.startsWith(`_${preferred}@`)) ||
          exps.find(e => e.name.includes(preferred));
  }

  if (!hit) throw new Error(`Export not found: ${preferred}`);

  // ABI decision
  let abi = null;
  if (Process.arch === 'ia32') {
    // If name contains @<bytes> it’s almost certainly stdcall
    if (/@\d+$/.test(hit.name)) abi = 'stdcall';
    else abi = null; // safest default for undecorated exports on ia32
  }

  console.log(`[+] Export ${preferred} -> ${hit.name} @ ${hit.address} (abi=${abi ?? "default"})`);
  return { address: hit.address, abi };
}

function makeNativeFunction(mod, name, retType, argTypes) {
  const exp = resolveExport(mod, name);

  // Only specify abi when it’s stdcall (cdecl is default and “cdecl” is invalid in Frida)
  const opts = (Process.arch === 'ia32' && exp.abi === 'stdcall') ? { abi: 'stdcall' } : undefined;

  return opts
    ? new NativeFunction(exp.address, retType, argTypes, opts)
    : new NativeFunction(exp.address, retType, argTypes);
}

// Helper exports (per the dumpbin)
const ResolveMethod  = makeNativeFunction(helper, "ResolveMethod",  'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
const DescribeObject = makeNativeFunction(helper, "DescribeObject", 'pointer', ['pointer']);
const MakeString     = makeNativeFunction(helper, "MakeString",     'pointer', ['pointer']); // wchar* -> System.String object ref
const BoxInt32       = makeNativeFunction(helper, "BoxInt32",       'pointer', ['int32']);   // int32 -> boxed object ref
const BoxBool        = makeNativeFunction(helper, "BoxBool",        'pointer', ['int32']);   // 0/1 -> boxed bool object ref

// ============================================================
// [4] MANAGED TYPE HELPERS (String decode + best-effort DescribeObject)
// ============================================================

// .NET Framework string layout (object ref points to MethodTable* first)
//   [MethodTable*][int length][char firstChar...]
function readDotNetString(obj) {
  if (obj.isNull()) return null;
  const len = obj.add(Process.pointerSize).readU32();
  if (len > 0x20000) return `[suspicious length=${len}]`;
  const chars = obj.add(Process.pointerSize + 4);
  return chars.readUtf16String(len);
}

function looksLikeManagedString(p) {
  if (p.isNull()) return false;
  try {
    const len = p.add(Process.pointerSize).readU32();
    return len > 0 && len < 0x2000;
  } catch (_) {
    return false;
  }
}

function safeDescribe(objRef) {
  try {
    const sObj = DescribeObject(objRef);
    if (sObj.isNull()) return "<DescribeObject returned null>";
    return readDotNetString(sObj) ?? "<DescribeObject decode failed>";
  } catch (e) {
    return `<DescribeObject failed: ${e}>`;
  }
}

// ============================================================
// [5] STUB/PRESTUB AVOIDANCE – follow common jump patterns
// ============================================================

/*
  ResolveMethod may return a prestub/thunk entrypoint.
  Hooking that can be unreliable: it can be patched after first call, run once, etc.
  We follow common JMP patterns to reach the actual body.
*/
function followJumps(p, maxHops = CONFIG.MAX_JUMP_HOPS) {
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
        // x64 RIP-relative: slot = cur + 6 + disp
        const slot = cur.add(6).add(disp);
        const next = slot.readPointer();
        console.log(`[+] hop${i}: jmp [rip+disp] ${cur} -> ${next} (slot=${slot})`);
        cur = next;
        continue;
      } else {
        // x86 best-effort: treat disp32 as absolute address of slot
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

// ============================================================
// [6] RESOLVE + HOOK
// ============================================================

console.log(`[+] Waiting ${CONFIG.RESOLVE_DELAY_MS}ms after resume before resolving/hooking...`);

setTimeout(() => {
  let entry = ptr(0);

  try {
    entry = ResolveMethod(
      allocW(CONFIG.targetAssemblyPath),
      allocW(CONFIG.targetTypeName),
      allocW(CONFIG.targetMethodName),
      allocW(CONFIG.paramSig)
    );
  } catch (e) {
    console.log(`[!] ResolveMethod call threw: ${e}`);
    console.log(`[!] This is typically: wrong path/type/method/paramsig OR wrong calling convention.`);
    console.log(`[!] ABI auto-detect is enabled; next suspects are: bad targetAssemblyPath or helper-side exception.`);
    return;
  }

  console.log(`[+] ResolveMethod -> ${entry} (${modNameForAddress(entry)})`);
  dumpRange("entry", entry);

  if (entry.isNull()) {
    console.log("[-] ResolveMethod returned NULL:");
    console.log("    - assembly path wrong / not loadable");
    console.log("    - type or method not found");
    console.log("    - overload mismatch (paramSig wrong)");
    console.log("    - assembly not loaded yet");
    return;
  }

  if (!isReadable(entry)) {
    console.log(`[-] entry is not readable/mapped. Likely a failure sentinel or bad pointer.`);
    console.log(`    Re-check: targetAssemblyPath, type name, method name, paramSig, bitness.`);
    return;
  }

  let real = entry;
  try {
    real = followJumps(entry);
  } catch (e) {
    console.log(`[!] followJumps failed at ${real}: ${e}`);
    return;
  }

  console.log(`[+] Final hook addr -> ${real} (${modNameForAddress(real)})`);
  dumpRange("real", real);

  if (!isExecutable(real)) {
    console.log(`[-] real is not executable. Refusing to attach to avoid crashing the process.`);
    console.log(`    This can happen if we resolved to data, a stub slot, or a non-code thunk.`);
    return;
  }

  console.log(`[+] Hooking ${CONFIG.targetTypeName}.${CONFIG.targetMethodName}(${CONFIG.paramSig}) @ ${real}`);

  // ============================================================
  // [7] PARAMETER DECODING TEMPLATE (x86-focused)
  // ============================================================
  //
  // IMPORTANT:
  // - On x86 .NET Framework, instance `this` is commonly in ECX.
  // - For JIT code, Frida's args[] is often NOT reliable.
  // - Here we scan stack for a plausible System.String for demo convenience.
  //
  // For real work (multi-params / mixed types):
  // - Decode deterministically by known calling convention + stack layout,
  //   OR hook a wrapper/caller where args[] is sane,
  //   OR build helper exports that extract argument values safely.
  //

  try {
    Interceptor.attach(real, {
      onEnter(args) {
        const ctx = this.context;
	logNativeStackTrace(ctx);

        // x86 instance 'this' commonly in ECX (for instance methods)
        const thisPtr = CONFIG.IS_STATIC ? ptr(0) : ptr(ctx.ecx);

        // x86 stack pointer at entry
        const esp = ptr(ctx.esp);

        // Demo: find first plausible System.String near top of stack
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

        // Optional: best-effort object description (may have side effects)
        // const arg0Desc = arg0.isNull() ? null : safeDescribe(arg0);

        console.log(
          `[ENTER] ${CONFIG.targetTypeName}.${CONFIG.targetMethodName} ` +
          `this=${thisPtr} arg0=${arg0} arg0Str=${JSON.stringify(arg0Str)} ` +
          `ecx=${ptr(ctx.ecx)} edx=${ptr(ctx.edx)} esp=${esp}`
        );

        // ---- Add deterministic decoding here for multi-params ----
        // Examples (x86 stack slots are 4 bytes each):
        //
        //   const p1_int32 = esp.add(?? * 4).readS32();
        //   const p2_obj   = esp.add(?? * 4).readPointer();
        //   console.log(`p1=${p1_int32} p2=${p2_obj} p2desc=${safeDescribe(p2_obj)}`);
      },

      onLeave(retval) {
        const before = retval.toInt32();
        console.log(`[LEAVE] ${CONFIG.targetTypeName}.${CONFIG.targetMethodName} retval(int32)=${before}`);

        if (CONFIG.FORCE_DIFFERENT_RETURN) {
          const before = retval.toInt32();
          console.log(`[LEAVE] Original Retval -> ${before}`)
          // Safe only for scalar bool/int-style returns
          retval.replace(ptr(1)); // Success
          console.log(`[LEAVE] Forced return: Success`);
        }

        // If return type is a managed object, you must replace with a valid object ref.
        // With your helper exports, examples could look like:
        //
        //   // Return a managed string:
        //   const s = MakeString(allocW("hello from hook"));
        //   retval.replace(s);
        //
        //   // Return boxed int:
        //   const boxed = BoxInt32(1337);
        //   retval.replace(boxed);
      }
    });
  } catch (e) {
    console.log(`[!] Interceptor.attach failed: ${e}`);
    return;
  }

}, CONFIG.RESOLVE_DELAY_MS);