# frida [![docs.rs](https://docs.rs/frida/badge.svg)](https://docs.rs/frida)

Rust bindings for [Frida](https://frida.re).

## Before Installing

- Build Frida or download the [latest supported package](https://github.com/frida/frida/releases/)
- Move `frida-core.h` and `libfrida-core.a` into `/usr/local/include` and `/usr/local/lib` (or a more appropriate folder that Rust can detect)

Or: use the `auto-download` feature to install Frida.

See the documentation for usage instructions.

## `frida::gir`: the generated API

`frida::gir` is frida-core's whole public API, generated from the `frida-core.gir` file
that ships in every frida-core devkit, the same description frida-python, frida-node and
frida-swift are generated from. It sits beside the older hand-written types at the crate
root, which it is meant to replace.

```rust,no_run
use frida::{DeviceManager, SpawnOptions};

fn main() -> Result<(), frida::Error> {
    let manager = DeviceManager::new()?;
    let device = manager.get_local_device()?;
    let pid = device.spawn("/bin/ls", Some(&SpawnOptions::new().argv(["ls", "-l"])), None)?;
    let session = device.attach(pid, None, None)?;
    let script = session.create_script("console.log('hello')", None, None)?;
    script.load(None)?;
    device.resume(pid, None)?;
    Ok(()) // dropping script, session and manager unloads, detaches and closes
}
```

In short:

- Every call that can fail returns `frida::Error`, which has a `kind()` to match on.
  Nothing panics on input it cannot pass to C (a string holding a NUL byte), or on a value
  frida-core returns that its declaration rules out.
- Options are plain values built in one expression; lists are `Vec`s; waits are
  `Duration`s; local paths are `Path`s.
- What a call acquires (a session, a script, a device manager) comes back as an `Owned`,
  which releases it when dropped and never blocks doing so. Signal handlers are closures,
  disconnected when their guard is dropped.
- Every handle is `Send` and `Sync`; the evidence, from frida-core's sources, is in
  `frida/src/gir/runtime.rs` and `frida_rust/customization.py`.
- Blocking calls are generated; async ones are a later step.

`examples/core/gir_hello`, `gir_console_log` and `gir_rpc_execute_function` are the
`hello`, `console_log` and `rpc_execute_function` examples written with it.

### How it is generated

`frida_rust/` (a Python package that needs nothing but the standard library) reads the
GIR of a Linux devkit and of a Windows devkit, which differ in a few items, and writes one
Rust module per class into `frida/src/gir/generated/`, formatted with `rustfmt`. It reads
them through `frida_bindgen_core`, the core Frida's other generated bindings share, which
is the `frida-bindgen` submodule, together with the GLib, GObject and Gio GIRs of the same
frida-core release, and generates every method, constructor, property and signal from the
core's model of it. The few kinds of item the core leaves out are read in
`frida_rust/supplements.py`, and counted. The output is committed, so building the crate
needs neither Python nor the submodule. What the GIR cannot say (which
strings are paths, which classes frida-core never changes after construction, what a call
acquires) is in `frida_rust/customization.py`, each entry with where its
answer comes from; a handful of conveniences are written by hand beside the generated
code, in `frida/src/gir/`. The generator counts every item in the GIR, and stops without
writing anything if one is neither generated nor listed as skipped with a reason, or if a
table entry no longer matches anything.

### After a Frida release

1. Bump `FRIDA_VERSION` and its copies in `frida-sys` and `frida-gum-sys`.
2. Run `scripts/update-headers.sh` so the vendored headers match the release, then
   `scripts/update-bindings.sh`. The latter downloads the Linux and Windows x86_64 core
   devkits of that release, and frida-core's GLib, GObject and Gio GIRs at its tag (or
   uses the ones in `~/.cache/frida/devkits`), checks out the `frida-bindgen` submodule
   if it is missing, and regenerates. Running it again changes nothing.
3. If it stops, it says what it could not generate: add a rule to the generator, or an
   entry to the tables in `customization.py`, and check the entries it names against
   frida-core's source at the new release.
4. Run `PYTHONPATH=frida-bindgen python3 -m unittest discover -s frida_rust/tests -t .`
   from the repository root and `cargo test -p frida --features auto-download`, and
   commit the result.
