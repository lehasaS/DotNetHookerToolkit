using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace TestTarget32
{
    internal static class Program
    {
        [DllImport("user32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int MessageBoxW(IntPtr hWnd, string lpText, string lpCaption, uint uType);

        private static int Main(string[] args)
        {
            Console.Title = "TestTarget32";
            Console.WriteLine("TestTarget32 (.NET Framework 4.8, x86)");
            Console.WriteLine("PID: " + Process.GetCurrentProcess().Id);
            Console.WriteLine("Is64BitProcess: " + Environment.Is64BitProcess);
            Console.WriteLine();
            Console.WriteLine("Keys:");
            Console.WriteLine("  M  -> call MessageBoxW()");
            Console.WriteLine("  F  -> write a file (should hit CreateFileW)");
            Console.WriteLine("  P  -> call PotatoVerifier.CheckIsPotato(string)");
            Console.WriteLine("  O  -> call PotatoVerifier.CheckIsPotato(string,int) overload");
            Console.WriteLine("  Q  -> quit");
            Console.WriteLine();

            var pv = new PotatoVerifier();

            // Do one call early so spawn-suspended + inject + resume can catch it if desired.
            bool warmup = pv.CheckIsPotato("potato");
            Console.WriteLine("Warmup CheckIsPotato(\"potato\") = " + warmup);

            while (true)
            {
                Console.Write("> ");
                var key = Console.ReadKey(intercept: true);
                Console.WriteLine(key.KeyChar);

                switch (char.ToUpperInvariant(key.KeyChar))
                {
                    case 'M':
                        CallMessageBox();
                        break;
                    case 'F':
                        WriteTestFile();
                        break;
                    case 'P':
                        CallManaged(pv);
                        break;
                    case 'O':
                        CallManagedOverload(pv);
                        break;
                    case 'Q':
                        return 0;
                    default:
                        Console.WriteLine("Unknown key.");
                        break;
                }
            }
        }

        private static void CallMessageBox()
        {
            Console.WriteLine("Calling MessageBoxW...");
            MessageBoxW(IntPtr.Zero, "Hello from TestTarget32", "TestTarget32", 0);
        }

        private static void WriteTestFile()
        {
            string path = Path.Combine(Path.GetTempPath(), "frida-clr-testtarget32.txt");
            string content = "Time: " + DateTime.Now.ToString("O") + Environment.NewLine +
                             "PID: " + Process.GetCurrentProcess().Id + Environment.NewLine;
            Console.WriteLine("Writing: " + path);
            File.WriteAllText(path, content, Encoding.UTF8);
            Console.WriteLine("Wrote " + content.Length + " bytes.");
        }

        private static void CallManaged(PotatoVerifier pv)
        {
            string input = DateTime.Now.Second % 2 == 0 ? "potato" : "tomato";
            bool result = pv.CheckIsPotato(input);
            Console.WriteLine($"CheckIsPotato(\"{input}\") = {result}");
        }

        private static void CallManagedOverload(PotatoVerifier pv)
        {
            string input = "potato";
            int times = 3;
            bool result = pv.CheckIsPotato(input, times);
            Console.WriteLine($"CheckIsPotato(\"{input}\", {times}) = {result}");
        }
    }

    public sealed class PotatoVerifier
    {
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public bool CheckIsPotato(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return false;

            return string.Equals(input.Trim(), "potato", StringComparison.OrdinalIgnoreCase);
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public bool CheckIsPotato(string input, int times)
        {
            if (times <= 0)
                return false;

            bool ok = CheckIsPotato(input);
            return ok && times == 3;
        }
    }
}

