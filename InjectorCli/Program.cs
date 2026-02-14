using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Threading;

namespace FridaClrInjector
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            try
            {
                string scriptPath = GetArg(args, "--script");
                string pidStr = GetArg(args, "--pid");
                string spawnPath = GetArg(args, "--spawn");
                string spawnArgs = GetArg(args, "--args"); // optional (parsed with CommandLineToArgvW)
                string procName = GetArg(args, "--name");   // optional alternative to --pid
                string deviceId = GetArg(args, "--device"); // optional

                if (HasFlag(args, "--help") || HasFlag(args, "-h"))
                {
                    PrintUsage();
                    return 0;
                }

                if (string.IsNullOrWhiteSpace(scriptPath))
                {
                    Console.Error.WriteLine("Missing --script");
                    PrintUsage();
                    return 2;
                }

                scriptPath = Path.GetFullPath(scriptPath);
                if (!File.Exists(scriptPath))
                {
                    Console.Error.WriteLine("Script not found: " + scriptPath);
                    return 2;
                }

                int modeCount = 0;
                if (!string.IsNullOrWhiteSpace(pidStr)) modeCount++;
                if (!string.IsNullOrWhiteSpace(spawnPath)) modeCount++;
                if (!string.IsNullOrWhiteSpace(procName)) modeCount++;
                if (modeCount != 1)
                {
                    Console.Error.WriteLine("Specify exactly one of: --pid, --spawn, --name");
                    PrintUsage();
                    return 2;
                }

                // frida-clr marshals callbacks onto a WPF Dispatcher; keep one alive on an STA thread.
                Dispatcher dispatcher = null;
                var dispatcherReady = new ManualResetEvent(false);

                var dispatcherThread = new Thread(() =>
                {
                    dispatcher = Dispatcher.CurrentDispatcher;
                    dispatcherReady.Set();
                    Dispatcher.Run();
                })
                {
                    IsBackground = true
                };
                dispatcherThread.SetApartmentState(ApartmentState.STA);
                dispatcherThread.Start();
                dispatcherReady.WaitOne();

                // Create device manager and pick a device.
                var dm = new Frida.DeviceManager(dispatcher);
                var devices = dm.EnumerateDevices();
                var device = !string.IsNullOrWhiteSpace(deviceId)
                    ? devices.FirstOrDefault(d => string.Equals(d.Id, deviceId, StringComparison.OrdinalIgnoreCase))
                    : devices.FirstOrDefault(d => d.Type == Frida.DeviceType.Local);

                if (device == null)
                {
                    Console.Error.WriteLine(string.IsNullOrWhiteSpace(deviceId)
                        ? "No local Frida device found."
                        : "No device found with id: " + deviceId);
                    ShutdownDispatcher(dispatcher, dispatcherThread);
                    return 1;
                }

                uint targetPid;
                bool spawned = false;

                if (!string.IsNullOrWhiteSpace(spawnPath))
                {
                    spawnPath = Path.GetFullPath(spawnPath);
                    if (!File.Exists(spawnPath))
                    {
                        Console.Error.WriteLine("Spawn target not found: " + spawnPath);
                        ShutdownDispatcher(dispatcher, dispatcherThread);
                        return 2;
                    }

                    string[] argv = BuildArgv(spawnPath, spawnArgs);

                    // Spawn suspended so we can inject before the first instructions run.
                    targetPid = device.Spawn(spawnPath, argv, null, null, null);
                    spawned = true;
                    Console.WriteLine("[+] Spawned PID: " + targetPid);
                }
                else if (!string.IsNullOrWhiteSpace(pidStr))
                {
                    if (!uint.TryParse(pidStr, out targetPid))
                    {
                        Console.Error.WriteLine("Invalid PID: " + pidStr);
                        ShutdownDispatcher(dispatcher, dispatcherThread);
                        return 2;
                    }
                }
                else
                {
                    // Attach by process name (first match).
                    var procs = device.EnumerateProcesses(Frida.Scope.Minimal);
                    var matches = procs.Where(p => string.Equals(p.Name, procName, StringComparison.OrdinalIgnoreCase)).ToArray();
                    if (matches.Length == 0)
                    {
                        Console.Error.WriteLine("No process found with name: " + procName);
                        ShutdownDispatcher(dispatcher, dispatcherThread);
                        return 1;
                    }
                    if (matches.Length > 1)
                    {
                        Console.Error.WriteLine("Multiple processes matched. Use --pid instead. Matches:");
                        foreach (var p in matches)
                            Console.Error.WriteLine("  " + p.Pid + " " + p.Name);
                        ShutdownDispatcher(dispatcher, dispatcherThread);
                        return 1;
                    }

                    targetPid = matches[0].Pid;
                }

                var session = device.Attach(targetPid);
                session.Detached += (s, e) =>
                {
                    Console.WriteLine("[session] detached: " + e.Reason);
                };

                string scriptSource = File.ReadAllText(scriptPath);
                var script = session.CreateScript(scriptSource, Path.GetFileName(scriptPath));

                script.Message += (s, e) =>
                {
                    Console.WriteLine("[script] " + e.Message);
                };

                script.Load();
                Console.WriteLine("[+] Script loaded: " + scriptPath);

                if (spawned)
                {
                    device.Resume(targetPid);
                    Console.WriteLine("[+] Resumed PID: " + targetPid);
                }

                var done = new ManualResetEvent(false);
                Console.CancelKeyPress += (s, e) =>
                {
                    e.Cancel = true;
                    done.Set();
                };

                Console.WriteLine("[*] Press Enter or Ctrl+C to detach...");
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    try { Console.ReadLine(); } catch { }
                    done.Set();
                });
                done.WaitOne();

                try { script.Unload(); } catch { }
                try { session.Detach(); } catch { }

                ShutdownDispatcher(dispatcher, dispatcherThread);
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[!] Fatal: " + ex);
                return 1;
            }
        }

        private static void PrintUsage()
        {
            Console.Error.WriteLine("Usage:");
            Console.Error.WriteLine("  FridaClrInjector.exe --pid <pid> --script <file.js> [--device <id>]");
            Console.Error.WriteLine("  FridaClrInjector.exe --name <process.exe> --script <file.js> [--device <id>]");
            Console.Error.WriteLine("  FridaClrInjector.exe --spawn <fullpath.exe> [--args \"<args>\"] --script <file.js> [--device <id>]");
            Console.Error.WriteLine();
            Console.Error.WriteLine("Examples:");
            Console.Error.WriteLine("  FridaClrInjector.exe --pid 1234 --script hooks\\hook_messagebox.js");
            Console.Error.WriteLine("  FridaClrInjector.exe --spawn \"C:\\\\Windows\\\\SysWOW64\\\\notepad.exe\" --script hooks\\hook_createfilew.js");
        }

        private static bool HasFlag(string[] args, string name)
        {
            return args.Any(a => string.Equals(a, name, StringComparison.OrdinalIgnoreCase));
        }

        private static string GetArg(string[] args, string name)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                    return args[i + 1];
            }
            return null;
        }

        private static string[] BuildArgv(string exePath, string argString)
        {
            if (string.IsNullOrWhiteSpace(argString))
                return new[] { exePath };

            // Use Windows' own command-line parsing rules (quotes/backslashes) so argv matches what the
            // target would see as Environment.GetCommandLineArgs().
            string cmdline = QuoteArg(exePath) + " " + argString;
            string[] parsed = ParseCommandLine(cmdline);
            if (parsed.Length == 0)
                return new[] { exePath };

            // Ensure argv[0] is the real executable path.
            parsed[0] = exePath;
            return parsed;
        }

        private static string QuoteArg(string s)
        {
            if (string.IsNullOrEmpty(s))
                return "\"\"";
            if (s.IndexOfAny(new[] { ' ', '\t', '\n', '\v', '"' }) == -1)
                return s;
            return "\"" + s.Replace("\"", "\\\"") + "\"";
        }

        private static string[] ParseCommandLine(string cmdLine)
        {
            IntPtr argv = CommandLineToArgvW(cmdLine, out int argc);
            if (argv == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CommandLineToArgvW failed");

            try
            {
                var result = new string[argc];
                for (int i = 0; i < argc; i++)
                {
                    IntPtr p = Marshal.ReadIntPtr(argv, i * IntPtr.Size);
                    result[i] = Marshal.PtrToStringUni(p);
                }
                return result;
            }
            finally
            {
                LocalFree(argv);
            }
        }

        private static void ShutdownDispatcher(Dispatcher dispatcher, Thread dispatcherThread)
        {
            try
            {
                dispatcher.BeginInvokeShutdown(DispatcherPriority.Normal);
            }
            catch { }

            try
            {
                if (dispatcherThread.IsAlive)
                    dispatcherThread.Join();
            }
            catch { }
        }

        [DllImport("shell32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CommandLineToArgvW(string lpCmdLine, out int pNumArgs);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);
    }
}

