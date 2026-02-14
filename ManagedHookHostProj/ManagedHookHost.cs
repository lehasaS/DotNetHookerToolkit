using System;
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
        // ----------------------------
        // 1) Method resolution
        // ----------------------------
        [DllExport("ResolveMethod", CallingConvention = CallingConvention.StdCall)]
        public static IntPtr ResolveMethod(
            IntPtr assemblyPathPtr,
            IntPtr typeNamePtr,
            IntPtr methodNamePtr,
            IntPtr paramSigPtr
        )
        {
            try
            {
                string asmPath = PtrToUni(assemblyPathPtr);
                string typeName = PtrToUni(typeNamePtr);
                string methodName = PtrToUni(methodNamePtr);
                string paramSig = PtrToUni(paramSigPtr) ?? string.Empty;

                if (string.IsNullOrWhiteSpace(asmPath) ||
                    string.IsNullOrWhiteSpace(typeName) ||
                    string.IsNullOrWhiteSpace(methodName))
                {
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
                    return IntPtr.Zero;

                // Force JIT and obtain native entrypoint.
                RuntimeHelpers.PrepareMethod(chosen.MethodHandle);
                return chosen.MethodHandle.GetFunctionPointer();
            }
            catch
            {
                return IntPtr.Zero;
            }
        }

        // ----------------------------
        // 2) Managed object helpers
        // ----------------------------

        // Create a managed System.String object and return its object reference.
        [DllExport("MakeString", CallingConvention = CallingConvention.StdCall)]
        public static IntPtr MakeString(IntPtr textPtr)
        {
            try
            {
                string s = PtrToUni(textPtr) ?? string.Empty;
                object o = s;
                return GetObjectRef(o);
            }
            catch { return IntPtr.Zero; }
        }

        // Box an Int32 and return object ref (useful for object-return methods).
        [DllExport("BoxInt32", CallingConvention = CallingConvention.StdCall)]
        public static IntPtr BoxInt32(int v)
        {
            try
            {
                object o = v;
                return GetObjectRef(o);
            }
            catch { return IntPtr.Zero; }
        }

        [DllExport("BoxBool", CallingConvention = CallingConvention.StdCall)]
        public static IntPtr BoxBool(int v) // pass 0/1
        {
            try
            {
                object o = (v != 0);
                return GetObjectRef(o);
            }
            catch { return IntPtr.Zero; }
        }

        // Best-effort "describe an object" for logging (property dump).
        // Returns a managed string object reference.
        [DllExport("DescribeObject", CallingConvention = CallingConvention.StdCall)]
        public static IntPtr DescribeObject(IntPtr objRef)
        {
            try
            {
                object obj = ObjectFromRef(objRef);
                if (obj == null)
                {
                    object sObj = "<null>";
                    return GetObjectRef(sObj);
                }

                var t = obj.GetType();
                var sb = new StringBuilder();

                sb.Append(t.FullName);

                // If it has a useful ToString, include it.
                try
                {
                    string ts = obj.ToString();
                    if (!string.IsNullOrEmpty(ts) && ts != t.FullName)
                        sb.Append(" :: ").Append(ts);
                }
                catch { }

                // Dump simple public props (avoid heavy side effects).
                var props = t.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                            .Where(p => p.GetIndexParameters().Length == 0)
                            .Take(40);

                foreach (var p in props)
                {
                    sb.AppendLine();
                    sb.Append("  ").Append(p.Name).Append(" = ");
                    try
                    {
                        object val = p.GetValue(obj);
                        sb.Append(val == null ? "<null>" : val.ToString());
                    }
                    catch
                    {
                        sb.Append("<error>");
                    }
                }

                object sObj = sb.ToString();
                return GetObjectRef(sObj);
            }
            catch
            {
                object sObj = "<DescribeObject failed>";
                return GetObjectRef(sObj);
            }
        }

        // ----------------------------
        // Internals: object ref magic
        // ----------------------------
        private static string PtrToUni(IntPtr p) => p == IntPtr.Zero ? null : Marshal.PtrToStringUni(p);

        private static unsafe IntPtr GetObjectRef(object o)
        {
            // Returns the raw managed object reference (an interior pointer tracked by the GC).
            // Do not persist these across safepoints unless you really know what you're doing.
            TypedReference tr = __makeref(o);
            return *(IntPtr*)(&tr);
        }

        private static unsafe object ObjectFromRef(IntPtr objRef)
        {
            // objRef is a raw managed object reference.
            // We re-wrap it as an object by writing it into a TypedReference.
            // This is fragile: prefer using it only for quick logging helpers.
            if (objRef == IntPtr.Zero) return null;

            object dummy = null;
            TypedReference tr = __makeref(dummy);
            *(IntPtr*)(&tr) = objRef;
            return __refvalue(tr, object);
        }
    }
}

