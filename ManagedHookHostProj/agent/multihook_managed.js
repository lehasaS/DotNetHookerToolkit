'use strict';

/*
  ============================================================
  Generic Multi-Hook Framework for .NET (Frida 17+)
  using a DllExport helper DLL (ResolveMethod + UTF-16 helpers)
  ============================================================

  Goals:
  - Spawn-safe (wait for CLR readiness)
  - Resolve managed methods to native entrypoints
  - Follow common thunk/jump patterns to reach executable code
  - Attach multiple hooks consistently
  - Safe helper usage (DescribeObjectUtf16 only for managed object refs)
  - Optional: Managed stack trace from helper (per-thread)

  Notes:
  - Argument decoding is intentionally conservative.
  - On x86, prefer stack (ESP+4, ESP+8...) for args rather than register guesses.
  - For complex signatures, add deterministic decoders per target.
*/

const CONFIG = {
  helperDllPath: "C:\\Path\\To\\ManagedHookHostProj.dll",

  // Spawn-safety: wait for CLR readiness before loading helper
  WAIT_FOR_CLR: true,
  CLR_POLL_MS: 100,
  CLR_TIMEOUT_MS: 15000,

  // Retry unresolved targets (lazy-loaded assemblies / late JIT)
  ENABLE_RETRY: true,
  RETRY_EVERY_MS: 1000,

  MAX_JUMP_HOPS: 16,

  LOG_NATIVE_STACK: false,
  LOG_MANAGED_STACK: false, // uses helper GetManagedStackTraceUtf16 if enabled
};

/*
  ============================================================
  TARGETS (FILL THESE IN)
  ============================================================

  Each target object supports:
  - name: label for logs
  - targetAssemblyPath: full path to managed assembly
  - targetTypeName: fully qualified type name
  - targetMethodName: method name
  - paramSig: "Full.Type|Full.Type&|..." (pipe-separated FullName strings)
  - IS_STATIC: true/false

  - DECODER: selects a decoder in decodeArgs():
      "noargs"
      "stack_i32"
      "stack_bool"
      "stack_ptr"
      "ref_i32_bool"
      "custom" (implement per target via t.decodeCustom)

  - RET: "i32" | "bool" | "string" | "" (defaults to i32-ish)

  - FORCE_DIFFERENT_RETURN: true/false
  - FORCE_RETVAL_INT32: int to force (bool uses 0/1)
  - FORCE_REF_I32: for ref_i32_bool decoder: write *refPtr = this value
*/

const HOOK_TARGETS = [
  // Example template entries (replace with your own)
  // {
  //   name: "Example.InstanceMethod(int, bool)",
  //   targetAssemblyPath: "C:\\Path\\To\\SomeAssembly.dll",
  //   targetTypeName: "Namespace.TypeName",
  //   targetMethodName: "MethodName",
  //   paramSig: "System.Int32|System.Boolean",
  //   IS_STATIC: false,
  //   DECODER: "stack_i32_bool",
  //   RET: "bool",
  //   FORCE_DIFFERENT_RETURN: false,
  // },
];

/* ============================================================
   Utilities
   ============================================================ */

function allocW(s) {
  return (s === null || s === undefined) ? ptr(0) : Memory.allocUtf16String(String(s));
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
  console.log(`[+] ${label}: ${p} -> ${r.base}..${end} prot=${r.protection} file=${r.file ? r.file.path : "<anon>"}`
  );
}

function logNativeStackTrace(context) {
  try {
    console.log(
      "[*] Native stack trace:\n" +
      Thread.backtrace(context, Backtracer.FUZZY)
        .map(DebugSymbol.fromAddress)
        .join("\n")
    );
  } catch (err) {
    console.log(`[!] Failed to log native stack: ${err.message}`);
  }
}

// .NET Framework string layout: [MethodTable*][int length][chars...]
function readDotNetString(obj) {
  if (obj.isNull()) return null;
  const len = obj.add(Process.pointerSize).readU32();
  if (len > 0x20000) return `[suspicious length=${len}]`;
  const chars = obj.add(Process.pointerSize + 4);
  return chars.readUtf16String(len);
}

/* ============================================================
   Jump/thunk peeling
   ============================================================ */

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

    // JMP [mem]: FF 25 disp32 (x86 abs / x64 RIP-relative)
    if (b0 === 0xFF && cur.add(1).readU8() === 0x25) {
      const disp = cur.add(2).readS32();

      if (Process.pointerSize === 8) {
        const slot = cur.add(6).add(disp);
        const next = slot.readPointer();
        console.log(`[+] hop${i}: jmp [rip+disp] ${cur} -> ${next} (slot=${slot})`);
        cur = next;
        continue;
      } else {
        const slot = ptr(cur.add(2).readU32());
        const next = slot.readPointer();
        console.log(`[+] hop${i}: jmp [abs] ${cur} -> ${next} (slot=${slot})`);
        cur = next;
        continue;
      }
    }

    // x64: mov rax, imm64; jmp rax (48 B8 ... FF E0)
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

/* ============================================================
   Spawn-safe CLR readiness
   ============================================================ */

function getModuleSafe(name) {
  try { return Process.getModuleByName(name); } catch (_) { return null; }
}

function waitForClrReady(cb) {
  if (!CONFIG.WAIT_FOR_CLR) return cb();

  const start = Date.now();
  const timer = setInterval(() => {
    const clr = getModuleSafe("clr.dll") || getModuleSafe("coreclr.dll");
    const mscorlib = getModuleSafe("mscorlib.ni.dll") || getModuleSafe("mscorlib.dll") ||
                     getModuleSafe("System.Private.CoreLib.dll"); // coreclr

    if (clr && mscorlib) {
      clearInterval(timer);
      console.log(`[+] CLR ready: ${clr.name} + ${mscorlib.name}`);
      cb();
      return;
    }

    if (Date.now() - start > CONFIG.CLR_TIMEOUT_MS) {
      clearInterval(timer);
      console.log("[!] Timed out waiting for CLR; continuing anyway.");
      cb();
    }
  }, CONFIG.CLR_POLL_MS);
}

/* ============================================================
   Helper loading + exports
   ============================================================ */

function resolveExport(mod, name) {
  const exps = mod.enumerateExports();
  const hit = exps.find(e => e.name === name) || exps.find(e => e.name.includes(name));
  if (!hit) throw new Error(`Export not found: ${name}`);
  console.log(`[+] export ${name} @ ${hit.address}`);
  return hit.address;
}

let helper = null;
let ResolveMethod = null;
let DescribeObjectUtf16 = null;
let FreeUtf16 = null;
let GetManagedStackTraceUtf16 = null;
let GetLastErrorUtf16 = null;
let ClearLastError = null;

function initHelper() {
  console.log(`[+] Loading helper: ${CONFIG.helperDllPath}`);
  helper = Module.load(CONFIG.helperDllPath);

  ResolveMethod = new NativeFunction(resolveExport(helper, "ResolveMethod"), "pointer",["pointer", "pointer", "pointer", "pointer"]);
  DescribeObjectUtf16 = new NativeFunction(resolveExport(helper, "DescribeObjectUtf16"), "pointer",["pointer"]);
  FreeUtf16 = new NativeFunction(resolveExport(helper, "FreeUtf16"), "void", ["pointer"]);
  GetManagedStackTraceUtf16 = new NativeFunction(resolveExport(helper, "GetManagedStackTraceUtf16"), "pointer", []);
  ClearLastError = new NativeFunction(resolveExport(helper, "ClearLastError"), "void", []);
  GetLastErrorUtf16 = new NativeFunction(resolveExport(helper, "GetLastErrorUtf16"), "pointer", []);
}

function readUtf16AndFree(p) {
  if (p.isNull()) return null;
  let s;
  try { s = p.readUtf16String(); } catch (e) { s = `<utf16 read failed: ${e}>`; }
  try { FreeUtf16(p); } catch (_) {}
  return s;
}

function helperLastError() {
  try {
    const p = GetLastErrorUtf16();
    return p.isNull() ? "" : readUtf16AndFree(p);
  } catch (_) {
    return "";
  }
}

function describeManaged(objRef) {
  if (objRef.isNull()) return "<null>";
  try {
    ClearLastError();
    const p = DescribeObjectUtf16(objRef);
    return readUtf16AndFree(p) ?? "<null-desc>";
  } catch (e) {
    const le = helperLastError();
    return `<DescribeObjectUtf16 failed: ${e}${le ? " | " + le : ""}>`;
  }
}

function getManagedStack() {
  try {
    ClearLastError();
    const p = GetManagedStackTraceUtf16();
    return readUtf16AndFree(p) ?? "<null-stack>";
  } catch (e) {
    const le = helperLastError();
    return `<GetManagedStackTraceUtf16 failed: ${e}${le ? " | " + le : ""}>`;
  }
}

/* ============================================================
   Decoders (generic, deterministic)
   ============================================================

  IMPORTANT:
  - Do NOT pass scalars to DescribeObjectUtf16.
  - Only pass managed object references (System.String, objects, boxed, etc.).
*/

function getThisPtr(t, ctx) {
  // For x86 instance methods, ECX typically holds `this`.
  // For x64, it’s more complex; but we log ECX/RCX anyway.
  if (t.IS_STATIC) return ptr(0);

  if (Process.arch === "ia32") return ptr(ctx.ecx);
  if (Process.arch === "x64")  return ptr(ctx.rcx); // best-effort label only

  return ptr(0);
}

function decode_noargs(t, ctx) {
  return { thisPtr: getThisPtr(t, ctx) };
}

function decode_stack_i32(t, ctx, slotIndex = 1) {
  // x86: args start at [ESP+4] => slotIndex=1
  const esp = ptr(ctx.esp);
  let v = 0;
  try { v = esp.add(slotIndex * 4).readS32(); } catch (_) {}
  return { thisPtr: getThisPtr(t, ctx), v };
}

function decode_stack_bool(t, ctx, slotIndex = 1) {
  const esp = ptr(ctx.esp);
  let v = 0;
  try { v = esp.add(slotIndex * 4).readU32() & 1; } catch (_) {}
  return { thisPtr: getThisPtr(t, ctx), v };
}

function decode_stack_ptr(t, ctx, slotIndex = 1) {
  const esp = ptr(ctx.esp);
  let p = ptr(0);
  try { p = esp.add(slotIndex * 4).readPointer(); } catch (_) {}
  return { thisPtr: getThisPtr(t, ctx), p };
}

function decode_ref_i32_bool(t, ctx) {
  // Common x86 pattern for instance method(ref int, bool):
  // this in ECX, refPtr at [ESP+4], bool at [ESP+8]
  const esp = ptr(ctx.esp);

  let refPtr = ptr(0);
  let boolv = 0;

  try { refPtr = esp.add(4).readPointer(); } catch (_) {}
  try { boolv = esp.add(8).readU32() & 1; } catch (_) {}

  let refVal = null;
  try { refVal = refPtr.isNull() ? null : refPtr.readS32(); } catch (_) { refVal = "<unreadable>"; }

  return { thisPtr: getThisPtr(t, ctx), refPtr, refVal, boolv };
}

function decodeArgs(t, ctx) {
  switch ((t.DECODER || "").toLowerCase()) {
    case "noargs":
      return { kind: "noargs", ...decode_noargs(t, ctx) };

    case "stack_i32":
      return { kind: "stack_i32", ...decode_stack_i32(t, ctx, 1) };

    case "stack_bool":
      return { kind: "stack_bool", ...decode_stack_bool(t, ctx, 1) };

    case "stack_ptr":
      return { kind: "stack_ptr", ...decode_stack_ptr(t, ctx, 1) };

    case "ref_i32_bool":
      return { kind: "ref_i32_bool", ...decode_ref_i32_bool(t, ctx) };

    case "custom":
      if (typeof t.decodeCustom === "function") {
        return { kind: "custom", ...t.decodeCustom(t, ctx) };
      }
      return { kind: "custom", thisPtr: getThisPtr(t, ctx), note: "missing decodeCustom" };

    default:
      return { kind: "unknown", thisPtr: getThisPtr(t, ctx) };
  }
}

function decodeRetval(t, retval) {
  const mode = (t.RET || "").toLowerCase();

  if (mode === "string") {
    if (retval.isNull()) return "<null>";
    try { return readDotNetString(retval) ?? "<decode-null>"; }
    catch (e) { return `<string decode exception: ${e}>`; }
  }

  if (mode === "bool") {
    return (retval.toInt32() & 1) ? 1 : 0;
  }

  // default: treat as i32-ish
  return retval.toInt32();
}

/* ============================================================
   Hook engine
   ============================================================ */

console.log(`[+] arch=${Process.arch} ptrSize=${Process.pointerSize}`);

function targetKey(t) {
  return `${t.targetAssemblyPath}::${t.targetTypeName}::${t.targetMethodName}(${t.paramSig || ""})`;
}

const ATTACHED = new Map();

function resolveManagedEntrypoint(t, label) {
  ClearLastError();

  let entry = ptr(0);
  try {
    entry = ResolveMethod(
      allocW(t.targetAssemblyPath),
      allocW(t.targetTypeName),
      allocW(t.targetMethodName),
      allocW(t.paramSig || "")
    );
  } catch (e) {
    const le = helperLastError();
    throw new Error(`ResolveMethod threw: ${e}${le ? " | " + le : ""}`);
  }

  if (entry.isNull()) {
    const le = helperLastError();
    throw new Error(`ResolveMethod returned NULL${le ? " | " + le : ""}`);
  }

  return entry;
}

function attachOne(t) {
  const key = targetKey(t);
  if (ATTACHED.has(key)) return true;

  const label = t.name || `${t.targetTypeName}.${t.targetMethodName}(${t.paramSig || ""})`;

  let entry;
  try {
    entry = resolveManagedEntrypoint(t, label);
  } catch (e) {
    console.log(`[-] [${label}] ${e.message}`);
    return false;
  }

  console.log(`[+] [${label}] entry -> ${entry} (${modNameForAddress(entry)})`);
  dumpRange(`[${label}] entry`, entry);

  if (!isReadable(entry)) {
    console.log(`[-] [${label}] entry not readable/mapped: ${entry}`);
    return false;
  }

  let real = entry;
  try {
    real = followJumps(entry, CONFIG.MAX_JUMP_HOPS);
  } catch (e) {
    console.log(`[-] [${label}] followJumps failed: ${e}`);
    return false;
  }

  console.log(`[+] [${label}] hook -> ${real} (${modNameForAddress(real)})`);
  dumpRange(`[${label}] real`, real);

  if (!isExecutable(real)) {
    console.log(`[-] [${label}] real not executable; refusing to attach`);
    return false;
  }

  const forceReturn = !!t.FORCE_DIFFERENT_RETURN;
  const forcedVal = (t.FORCE_RETVAL_INT32 !== undefined) ? (t.FORCE_RETVAL_INT32 | 0) : 1;

  try {
    Interceptor.attach(real, {
      onEnter() {
        const ctx = this.context;

        if (CONFIG.LOG_NATIVE_STACK) logNativeStackTrace(ctx);
        if (CONFIG.LOG_MANAGED_STACK) {
          console.log(`[MSTACK] [${label}]\n${getManagedStack()}`);
        }

        const d = decodeArgs(t, ctx);

        // Save ref pointer for later writes (only when decoder provides it)
        if (d.kind === "ref_i32_bool") {
          this._refPtr = d.refPtr;
        }

        // CONSISTENT enter log format
        console.log(`[ENTER] [${label}] kind=${d.kind} this=${d.thisPtr}`);

        // Optional structured details per decoder
        if (d.kind === "stack_i32") console.log(`        arg(i32)=${d.v}`);
        if (d.kind === "stack_bool") console.log(`        arg(bool)=${d.v}`);
        if (d.kind === "stack_ptr") console.log(`        arg(ptr)=${d.p}`);
        if (d.kind === "ref_i32_bool") console.log(`        ref=${d.refPtr} *ref=${d.refVal} bool=${d.boolv}`);

        // If you *know* a stack_ptr is a managed object ref, you may describe it:
        // console.log(`        desc=\n${describeManaged(d.p)}`);
      },

      onLeave(retval) {
        const decoded = decodeRetval(t, retval);
        console.log(`[LEAVE] [${label}] retval=${JSON.stringify(decoded)}`);

        // Write ref value if requested
        if (t.DECODER === "ref_i32_bool" && t.FORCE_REF_I32 !== undefined) {
          if (this._refPtr && !this._refPtr.isNull()) {
            try {
              this._refPtr.writeS32(t.FORCE_REF_I32 | 0);
              console.log(`[LEAVE] [${label}] wrote *ref=${(t.FORCE_REF_I32 | 0)}`);
            } catch (e) {
              console.log(`[!] [${label}] failed to write ref: ${e}`);
            }
          }
        }

        // Force scalar return
        if (forceReturn) {
          retval.replace(ptr(forcedVal));
          console.log(`[LEAVE] [${label}] forcedReturn=${forcedVal}`);
        }
      }
    });
  } catch (e) {
    console.log(`[-] [${label}] Interceptor.attach failed: ${e}`);
    return false;
  }

  ATTACHED.set(key, real);
  console.log(`[+] [${label}] attached OK`);
  return true;
}

function attachAllOnce() {
  let ok = 0;
  for (const t of HOOK_TARGETS) if (attachOne(t)) ok++;
  console.log(`[+] attach pass: ${ok}/${HOOK_TARGETS.length} attached`);
  return ok === HOOK_TARGETS.length;
}

/* ============================================================
   Startup
   ============================================================ */

waitForClrReady(() => {
  initHelper();

  const done = attachAllOnce();
  if (!done && CONFIG.ENABLE_RETRY) {
    console.log(`[+] some targets not ready; retry every ${CONFIG.RETRY_EVERY_MS}ms`);
    const timer = setInterval(() => {
      const all = attachAllOnce();
      if (all) {
        clearInterval(timer);
        console.log("[+] all targets attached; stopping retry loop");
      }
    }, CONFIG.RETRY_EVERY_MS);
  }
});