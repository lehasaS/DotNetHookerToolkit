using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using io.github._3F.DllExport;

namespace ManagedHookHostProj
{
    public static class ManagedHookHost
    {
        [ThreadStatic]
        private static string _lastError;

        [ThreadStatic]
        private static IntPtr _threadLastErrorPtr;

        // Tracks unmanaged UTF-16 blocks allocated by this helper so FreeUtf16 is idempotent
        // and ignores unknown pointers instead of freeing arbitrary memory.
        private static readonly ConcurrentDictionary<IntPtr, byte> _ownedUtf16 = new ConcurrentDictionary<IntPtr, byte>();

        private static void SetLastError(Exception ex, string context)
        {
            try { _lastError = $"[{context}] {ex}"; }
            catch { _lastError = "<failed to format last error>"; }
        }

        private static void ClearLastError()
        {
            _lastError = string.Empty;
        }

        private static IntPtr AllocUtf16(string s)
        {
            IntPtr p = Marshal.StringToHGlobalUni(s ?? string.Empty);
            if (p != IntPtr.Zero)
                _ownedUtf16[p] = 0;
            return p;
        }

        private static void FreeUtf16Internal(IntPtr p)
        {
            if (p == IntPtr.Zero)
                return;

            // Only free pointers allocated by this helper.
            if (_ownedUtf16.TryRemove(p, out _))
                Marshal.FreeHGlobal(p);
        }

        private static string PtrToUni(IntPtr p) => p == IntPtr.Zero ? null : Marshal.PtrToStringUni(p);

        // ----------------------------
        // UTF-16 unmanaged string lifecycle
        // ----------------------------
        [DllExport("FreeUtf16", CallingConvention = CallingConvention.Cdecl)]
        public static void FreeUtf16(IntPtr p)
        {
            FreeUtf16Internal(p);
        }

        [DllExport("ClearLastError", CallingConvention = CallingConvention.Cdecl)]
        public static void ClearLastErrorExport()
        {
            ClearLastError();
        }

        [DllExport("GetLastErrorUtf16", CallingConvention = CallingConvention.Cdecl)]
        public static IntPtr GetLastErrorUtf16()
        {
            try
            {
                // Reclaim previous per-thread error buffer if caller forgot to free it.
                FreeUtf16Internal(_threadLastErrorPtr);
                _threadLastErrorPtr = IntPtr.Zero;

                string message = _lastError ?? string.Empty;
                if (message.Length == 0)
                    return IntPtr.Zero;

                _threadLastErrorPtr = AllocUtf16(message);
                return _threadLastErrorPtr;
            }
            catch
            {
                return IntPtr.Zero;
            }
        }

        // ----------------------------
        // Method resolution
        // ----------------------------
        [DllExport("ResolveMethod", CallingConvention = CallingConvention.Cdecl)]
        public static IntPtr ResolveMethod(IntPtr assemblyPathPtr, IntPtr typeNamePtr, IntPtr methodNamePtr, IntPtr paramSigPtr)
        {
            try
            {
                ClearLastError();

                string asmPath = PtrToUni(assemblyPathPtr);
                string typeName = PtrToUni(typeNamePtr);
                string methodName = PtrToUni(methodNamePtr);
                string paramSig = PtrToUni(paramSigPtr) ?? string.Empty;

                if (string.IsNullOrWhiteSpace(asmPath) ||
                    string.IsNullOrWhiteSpace(typeName) ||
                    string.IsNullOrWhiteSpace(methodName))
                {
                    _lastError = "ResolveMethod: invalid args (empty asmPath/typeName/methodName).";
                    return IntPtr.Zero;
                }

                var asm =
                    AppDomain.CurrentDomain.GetAssemblies()
                        .FirstOrDefault(a => !a.IsDynamic &&
                                             string.Equals(a.Location, asmPath, StringComparison.OrdinalIgnoreCase))
                    ?? Assembly.LoadFrom(asmPath);

                var t = asm.GetType(typeName, throwOnError: true);

                string[] paramTypes = paramSig.Length == 0 ? Array.Empty<string>() : paramSig.Split('|');

                var candidates = t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static)
                                  .Where(m => m.Name == methodName)
                                  .ToArray();

                MethodInfo chosen = null;

                if (paramTypes.Length > 0)
                {
                    chosen = candidates.FirstOrDefault(m =>
                    {
                        var ps = m.GetParameters();
                        if (ps.Length != paramTypes.Length) return false;

                        for (int i = 0; i < ps.Length; i++)
                        {
                            if (!string.Equals(ps[i].ParameterType.FullName, paramTypes[i], StringComparison.Ordinal))
                                return false;
                        }
                        return true;
                    });
                }

                chosen ??= candidates.FirstOrDefault();

                if (chosen == null)
                {
                    _lastError = $"ResolveMethod: not found type={typeName} method={methodName} sig='{paramSig}'";
                    return IntPtr.Zero;
                }

                RuntimeHelpers.PrepareMethod(chosen.MethodHandle);
                return chosen.MethodHandle.GetFunctionPointer();
            }
            catch (Exception ex)
            {
                SetLastError(ex, "ResolveMethod");
                return IntPtr.Zero;
            }
        }

        [DllExport("ResolveMethodByToken", CallingConvention = CallingConvention.Cdecl)]
        public static IntPtr ResolveMethodByToken(IntPtr assemblyPathPtr, IntPtr typeNamePtr, int methodToken)
        {
            try
            {
                ClearLastError();

                string asmPath = PtrToUni(assemblyPathPtr);
                string typeName = PtrToUni(typeNamePtr);

                if (string.IsNullOrWhiteSpace(asmPath) ||
                    string.IsNullOrWhiteSpace(typeName) ||
                    methodToken == 0)
                {
                    _lastError = "ResolveMethodByToken: invalid args (empty asmPath/typeName or token=0).";
                    return IntPtr.Zero;
                }

                var asm =
                    AppDomain.CurrentDomain.GetAssemblies()
                        .FirstOrDefault(a => !a.IsDynamic &&
                                             string.Equals(a.Location, asmPath, StringComparison.OrdinalIgnoreCase))
                    ?? Assembly.LoadFrom(asmPath);

                var t = asm.GetType(typeName, throwOnError: true);
                var mb = t.Module.ResolveMethod(methodToken);

                if (mb is MethodInfo mi)
                {
                    RuntimeHelpers.PrepareMethod(mi.MethodHandle);
                    return mi.MethodHandle.GetFunctionPointer();
                }

                if (mb is ConstructorInfo ci)
                {
                    RuntimeHelpers.PrepareMethod(ci.MethodHandle);
                    return ci.MethodHandle.GetFunctionPointer();
                }

                _lastError = $"ResolveMethodByToken: unsupported MethodBase type: {mb?.GetType().FullName ?? "<null>"}";
                return IntPtr.Zero;
            }
            catch (Exception ex)
            {
                SetLastError(ex, "ResolveMethodByToken");
                return IntPtr.Zero;
            }
        }

        // ----------------------------
        // Safer describe + managed stack trace (UTF-16)
        // ----------------------------
        [DllExport("DescribeObjectUtf16", CallingConvention = CallingConvention.Cdecl)]
        public static IntPtr DescribeObjectUtf16(IntPtr objRef)
        {
            try
            {
                ClearLastError();
                object obj = ObjectFromRef(objRef);
                string description = DescribeObjectCore(obj);
                return AllocUtf16(description);
            }
            catch (Exception ex)
            {
                SetLastError(ex, "DescribeObjectUtf16");
                return AllocUtf16("<DescribeObjectUtf16 failed>");
            }
        }

        [DllExport("GetManagedStackTraceUtf16", CallingConvention = CallingConvention.Cdecl)]
        public static IntPtr GetManagedStackTraceUtf16()
        {
            try
            {
                ClearLastError();
                // Environment.StackTrace captures the managed stack of the current thread.
                return AllocUtf16(Environment.StackTrace ?? "<no stack>");
            }
            catch (Exception ex)
            {
                SetLastError(ex, "GetManagedStackTraceUtf16");
                return AllocUtf16("<GetManagedStackTraceUtf16 failed>");
            }
        }

        private static bool IsSimple(Type x) =>
            x.IsPrimitive || x.IsEnum ||
            x == typeof(string) ||
            x == typeof(decimal) ||
            x == typeof(DateTime) ||
            x == typeof(Guid);

        private static string DescribeObjectCore(object obj)
        {
            if (obj == null) return "<null>";

            var t = obj.GetType();
            var sb = new StringBuilder();

            sb.Append(t.FullName);

            try
            {
                string ts = obj.ToString();
                if (!string.IsNullOrEmpty(ts) && ts != t.FullName)
                    sb.Append(" :: ").Append(ts);
            }
            catch { }

            var props = t.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                        .Where(p => p.GetIndexParameters().Length == 0 && p.GetGetMethod() != null)
                        .Take(40);

            foreach (var p in props)
            {
                sb.AppendLine();
                sb.Append("  ").Append(p.Name).Append(" = ");
                try
                {
                    object val = p.GetValue(obj);
                    if (val == null)
                        sb.Append("<null>");
                    else
                        sb.Append(IsSimple(val.GetType()) ? val.ToString() : $"<{val.GetType().FullName}>");
                }
                catch
                {
                    sb.Append("<error>");
                }
            }

            return sb.ToString();
        }

        // ----------------------------
        // Primitive helpers (optional but handy)
        // ----------------------------
        [DllExport("WriteInt32", CallingConvention = CallingConvention.Cdecl)]
        public static void WriteInt32(IntPtr p, int value)
        {
            if (p == IntPtr.Zero) return;
            Marshal.WriteInt32(p, value);
        }

        [DllExport("WriteBool", CallingConvention = CallingConvention.Cdecl)]
        public static void WriteBool(IntPtr p, int value)
        {
            if (p == IntPtr.Zero) return;
            Marshal.WriteByte(p, (byte)(value != 0 ? 1 : 0));
        }

        [DllExport("ReadInt32", CallingConvention = CallingConvention.Cdecl)]
        public static int ReadInt32(IntPtr p)
        {
            if (p == IntPtr.Zero) return 0;
            return Marshal.ReadInt32(p);
        }

        // ----------------------------
        // Managed object creation for forcing returns (keep these)
        // ----------------------------
        [DllExport("MakeString", CallingConvention = CallingConvention.Cdecl)]
        public static IntPtr MakeString(IntPtr textPtr)
        {
            try
            {
                ClearLastError();
                string s = PtrToUni(textPtr) ?? string.Empty;
                object o = s;
                return GetObjectRef(o);
            }
            catch (Exception ex)
            {
                SetLastError(ex, "MakeString");
                return IntPtr.Zero;
            }
        }

        [DllExport("BoxInt32", CallingConvention = CallingConvention.Cdecl)]
        public static IntPtr BoxInt32(int v)
        {
            try
            {
                ClearLastError();
                object o = v;
                return GetObjectRef(o);
            }
            catch (Exception ex)
            {
                SetLastError(ex, "BoxInt32");
                return IntPtr.Zero;
            }
        }

        [DllExport("BoxBool", CallingConvention = CallingConvention.Cdecl)]
        public static IntPtr BoxBool(int v)
        {
            try
            {
                ClearLastError();
                object o = (v != 0);
                return GetObjectRef(o);
            }
            catch (Exception ex)
            {
                SetLastError(ex, "BoxBool");
                return IntPtr.Zero;
            }
        }

        // ----------------------------
        // Raw managed object ref magic (fragile by nature)
        // ----------------------------
        private static unsafe IntPtr GetObjectRef(object o)
        {
            TypedReference tr = __makeref(o);
            return *(IntPtr*)(&tr);
        }

        private static unsafe object ObjectFromRef(IntPtr objRef)
        {
            if (objRef == IntPtr.Zero) return null;

            object dummy = null;
            TypedReference tr = __makeref(dummy);
            *(IntPtr*)(&tr) = objRef;
            return __refvalue(tr, object);
        }
    }
}
