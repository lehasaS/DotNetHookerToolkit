# Troubleshooting

## `BadImageFormatException`

Bitness mismatch. Ensure:

* x86 injector + x86 `Frida.dll` + x86 target process
* x64 injector + x64 `Frida.dll` + x64 target process

If your target is 32-bit on a 64-bit OS, the process will run under WoW64 and you must use x86.

## Script loads but you never see `[script] ...` messages
* 
This usually means the dispatcher is not running.

This injector starts a dedicated dispatcher thread. If you copied code elsewhere:

* ensure the `Dispatcher.Run()` thread stays alive for the duration of the session

## `Access is denied` / cannot attach

Run the injector elevated if the target is elevated.

## Target exits immediately when spawning

Common causes:

* wrong argv (some programs require specific args)
* missing working directory / environment variables

Try launching the target normally first, then attach by PID to confirm it stays alive.

