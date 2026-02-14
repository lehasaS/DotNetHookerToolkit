# How It Works

## Architecture

There are two parts:

1. **Injector (C#/.NET Framework)** using `Frida.dll` from `frida-clr`
2. **Agent (Frida JavaScript)** that actually performs hooks inside the target process

The injector:

* Enumerates devices (`new Frida.DeviceManager(dispatcher).EnumerateDevices()`)
* Spawns or attaches (`device.Spawn()` / `device.Attach(pid)`)
* Creates a script (`session.CreateScript(jsSource, name)`)
* Subscribes to script messages (`script.Message += ...`)
* Loads it (`script.Load()`)
* Optionally resumes the spawned process (`device.Resume(pid)`)

## The Dispatcher Requirement

`frida-clr` was implemented with a WPF `Dispatcher`-based callback model. In `src/Script.cpp` you can see messages are delivered with:

* If you are on the dispatcher thread: raise `Message(...)` directly
* Otherwise: `dispatcher.BeginInvoke(...)`

WPF apps already have an active dispatcher loop, but a console app does not, so this injector creates an STA thread and calls `Dispatcher.Run()`.

Without an active dispatcher loop:

* Your script may still load and run
* Callbacks like `script.Message` will never arrive

## Spawn vs Attach

* `--spawn`: starts the process suspended, injects your script, then resumes it. Use this if you need to hook very early.
* `--pid` / `--name`: attaches to an already-running process. Use this if the process is already running and you want to inspect current state.

