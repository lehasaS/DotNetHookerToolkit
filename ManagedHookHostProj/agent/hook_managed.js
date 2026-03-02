'use strict';

/*
  ============================================================
  Generic Single-Hook Framework for .NET (Frida 17+)
  using a DllExport helper DLL (ResolveMethod + UTF-16 helpers)
  ============================================================
*/

const CONFIG = {
  helperDllPath: "C:\\Path\\To\\ManagedHookHostProj.dll",

  WAIT_FOR_CLR: true,
  CLR_POLL_MS: 100,
  CLR_TIMEOUT_MS: 15000,

  MAX_JUMP_HOPS: 16,

  LOG_NATIVE_STACK: false,
  LOG_MANAGED_STACK: false,

  // Force scalar returns (0/1/int32). Keep false unless you know return is scalar.
  FORCE_DIFFERENT_RETURN: false,
  FORCE_RETVAL_INT32: 1,
};

const TARGET = {
  name: "Example.TargetMethod(...)",
  targetAssemblyPath: "C:\\Path\\To\\SomeAssembly.dll",
  targetTypeName: "Namespace.TypeName",
  targetMethodName: "MethodName",
  paramSig: "System.Int32|System.Boolean",
  IS_STATIC: false,

  DECODER: "ref_i32_bool", // choose from the multi-hook decoders
  RET: "bool",             // "bool" | "string" | ""(i32)
};

/* ============================================================
   Utilities + helper init (same as multi-hook)
   ============================================================ */

function allocW(s) { return (s === null || s === undefined) ? ptr(0) : Memory.allocUtf16String(String(s)); }

function getModuleSafe(name) { try { return Process.getModuleByName(name); } catch (_) { return null; } }

function waitForClrReady(cb) {
  if (!CONFIG.WAIT_FOR_CLR) return cb();
  const start = Date.now();
  const timer = setInterval(() => {
    const clr = getModuleSafe("clr.dll") || getModuleSafe("coreclr.dll");
    const mscorlib = getModuleSafe("mscorlib.ni.dll") || getModuleSafe("mscorlib.dll") || getModuleSafe("System.Private.CoreLib.dll");
    if (clr && mscorlib) { clearInterval(timer); console.log(`[+] CLR ready: ${clr.name} + ${mscorlib.name}`); cb(); return; }
    if (Date.now() - start > CONFIG.CLR_TIMEOUT_MS) { clearInterval(timer); console.log("[!] Timed out waiting for CLR; continuing anyway."); cb(); }
  }, CONFIG.CLR_POLL_MS);
}

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

  ResolveMethod = new NativeFunction(resolveExport(helper, "ResolveMethod"), "pointer", ["pointer","pointer","pointer","pointer"]);
  DescribeObjectUtf16 = new NativeFunction(resolveExport(helper, "DescribeObjectUtf16"), "pointer", ["pointer"]);
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
  try { const p = GetLastErrorUtf16(); return p.isNull() ? "" : readUtf16AndFree(p); } catch (_) { return ""; }
}

function getManagedStack() {
  try { ClearLastError(); return readUtf16AndFree(GetManagedStackTraceUtf16()) ?? "<null-stack>"; }
  catch (e) { const le = helperLastError(); return `<GetManagedStackTraceUtf16 failed: ${e}${le ? " | " + le : ""}>`; }
}

// .NET string: [MT*][len][chars...]
function readDotNetString(obj) {
  if (obj.isNull()) return null;
  const len = obj.add(Process.pointerSize).readU32();
  if (len > 0x20000) return `[suspicious length=${len}]`;
  return obj.add(Process.pointerSize + 4).readUtf16String(len);
}

function logNativeStackTrace(context) {
  try {
    console.log("[*] Native stack trace:\n" + Thread.backtrace(context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join("\n"));
  } catch (err) {
    console.log(`[!] Failed to log native stack: ${err.message}`);
  }
}

function modNameForAddress(p) {
  const m = Process.findModuleByAddress(p);
  return m ? `${m.name}+0x${p.sub(m.base)}` : "<no module>";
}
function rangeFor(p) { try { return Process.findRangeByAddress(p); } catch (_) { return null; } }
function isReadable(p) { const r = rangeFor(p); return r !== null && r.protection.includes('r'); }
function isExecutable(p) { const r = rangeFor(p); return r !== null && r.protection.includes('x'); }
function dumpRange(label, p) {
  const r = rangeFor(p);
  if (!r) return console.log(`[!] ${label}: ${p} -> <no range>`);
  console.log(`[+] ${label}: ${p} -> ${r.base}..${r.base.add(r.size)} prot=${r.protection} file=${r.file ? r.file.path : "<anon>"}`);
}

function followJumps(p, maxHops = CONFIG.MAX_JUMP_HOPS) {
  let cur = ptr(p);
  for (let i = 0; i < maxHops; i++) {
    const b0 = cur.readU8();
    if (b0 === 0xE9) { const rel = cur.add(1).readS32(); const next = cur.add(5).add(rel); console.log(`[+] hop${i}: jmp rel32 ${cur} -> ${next}`); cur = next; continue; }
    if (b0 === 0xEB) { const rel8 = cur.add(1).readS8(); const next = cur.add(2).add(rel8); console.log(`[+] hop${i}: jmp rel8  ${cur} -> ${next}`); cur = next; continue; }
    if (b0 === 0xFF && cur.add(1).readU8() === 0x25) {
      const disp = cur.add(2).readS32();
      if (Process.pointerSize === 8) { const slot = cur.add(6).add(disp); const next = slot.readPointer(); console.log(`[+] hop${i}: jmp [rip+disp] ${cur} -> ${next} (slot=${slot})`); cur = next; continue; }
      const slot = ptr(cur.add(2).readU32()); const next = slot.readPointer(); console.log(`[+] hop${i}: jmp [abs] ${cur} -> ${next} (slot=${slot})`); cur = next; continue;
    }
    if (Process.pointerSize === 8 && b0 === 0x48 && cur.add(1).readU8() === 0xB8 && cur.add(10).readU8() === 0xFF && cur.add(11).readU8() === 0xE0) {
      const imm = cur.add(2).readU64(); const next = ptr(imm); console.log(`[+] hop${i}: mov rax; jmp rax ${cur} -> ${next}`); cur = next; continue;
    }
    break;
  }
  return cur;
}

// ---- Minimal decoders (reuse from multi-hook) ----
function getThisPtr(t, ctx) {
  if (t.IS_STATIC) return ptr(0);
  if (Process.arch === "ia32") return ptr(ctx.ecx);
  if (Process.arch === "x64")  return ptr(ctx.rcx);
  return ptr(0);
}

function decode_ref_i32_bool(t, ctx) {
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
    case "ref_i32_bool": return { kind: "ref_i32_bool", ...decode_ref_i32_bool(t, ctx) };
    default: return { kind: "unknown", thisPtr: getThisPtr(t, ctx) };
  }
}

function decodeRetval(t, retval) {
  const mode = (t.RET || "").toLowerCase();
  if (mode === "string") { if (retval.isNull()) return "<null>"; try { return readDotNetString(retval) ?? "<decode-null>"; } catch (e) { return `<string decode exception: ${e}>`; } }
  if (mode === "bool") return (retval.toInt32() & 1) ? 1 : 0;
  return retval.toInt32();
}

/* ============================================================
   Resolve + attach
   ============================================================ */

console.log(`[+] arch=${Process.arch} ptrSize=${Process.pointerSize}`);

waitForClrReady(() => {
  initHelper();

  const label = TARGET.name || `${TARGET.targetTypeName}.${TARGET.targetMethodName}(${TARGET.paramSig || ""})`;

  let entry = ptr(0);
  try {
    ClearLastError();
    entry = ResolveMethod(allocW(TARGET.targetAssemblyPath), allocW(TARGET.targetTypeName), allocW(TARGET.targetMethodName), allocW(TARGET.paramSig || ""));
  } catch (e) {
    const le = helperLastError();
    console.log(`[-] [${label}] ResolveMethod threw: ${e}${le ? " | " + le : ""}`);
    return;
  }

  console.log(`[+] [${label}] entry -> ${entry} (${modNameForAddress(entry)})`);
  dumpRange(`[${label}] entry`, entry);

  if (entry.isNull() || !isReadable(entry)) {
    const le = helperLastError();
    console.log(`[-] [${label}] invalid entry${le ? " | " + le : ""}`);
    return;
  }

  const real = followJumps(entry, CONFIG.MAX_JUMP_HOPS);
  console.log(`[+] [${label}] hook -> ${real} (${modNameForAddress(real)})`);
  dumpRange(`[${label}] real`, real);

  if (!isExecutable(real)) {
    console.log(`[-] [${label}] real not executable; refusing to attach`);
    return;
  }

  try {
    Interceptor.attach(real, {
      onEnter() {
        const ctx = this.context;

        if (CONFIG.LOG_NATIVE_STACK) logNativeStackTrace(ctx);
        if (CONFIG.LOG_MANAGED_STACK) console.log(`[MSTACK] [${label}]\n${getManagedStack()}`);

        const d = decodeArgs(TARGET, ctx);
        if (d.kind === "ref_i32_bool") this._refPtr = d.refPtr;

        console.log(`[ENTER] [${label}] kind=${d.kind} this=${d.thisPtr}`);
        if (d.kind === "ref_i32_bool") console.log(`        ref=${d.refPtr} *ref=${d.refVal} bool=${d.boolv}`);
      },

      onLeave(retval) {
        const decoded = decodeRetval(TARGET, retval);
        console.log(`[LEAVE] [${label}] retval=${JSON.stringify(decoded)}`);

        if (CONFIG.FORCE_DIFFERENT_RETURN) {
          const forced = (CONFIG.FORCE_RETVAL_INT32 | 0);
          retval.replace(ptr(forced));
          console.log(`[LEAVE] [${label}] forcedReturn=${forced}`);
        }
      }
    });
  } catch (e) {
    console.log(`[-] [${label}] attach failed: ${e}`);
  }
});