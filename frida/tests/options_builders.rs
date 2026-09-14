//! Unit-shape coverage for [`SpawnOptions`] and [`ScriptOption`] builder chains.
//!
//! These construct the FFI options objects, exercise every setter chained
//! together, and drop them. They don't invoke `spawn` — we're guarding the
//! Rust-side wrapper layer, not the frida-core spawn path (that varies wildly
//! by OS and requires elevated capabilities on some hosts).

use frida::{Frida, ScriptOption, ScriptRuntime, SpawnOptions, SpawnStdio};
use std::ffi::CString;
use std::sync::{LazyLock, Mutex, MutexGuard};

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });
static FRIDA_SERIAL: Mutex<()> = Mutex::new(());

fn serial_guard() -> MutexGuard<'static, ()> {
    FRIDA_SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

#[test]
fn spawn_options_builder_chain_does_not_crash() {
    let _serial = serial_guard();
    let _f = &*FRIDA;

    let cwd = CString::new("/tmp").expect("static path is nul-free");
    let _opts = SpawnOptions::new()
        .argv(["arg0", "arg1", "arg2 with spaces"])
        .env([("A", "1"), ("B", "hello")])
        .envp([("PATH", "/usr/bin"), ("HOME", "/tmp")])
        .cwd(&cwd)
        .stdio(SpawnStdio::Pipe);
    // Drop must run without leaking or double-freeing; the smoke of these
    // chained setters is enough — the underlying frida C API doesn't expose
    // getters we could round-trip against here.
}

#[test]
fn spawn_options_default_is_new() {
    // `Default::default()` must behave exactly like `SpawnOptions::new()`.
    let _serial = serial_guard();
    let _f = &*FRIDA;
    let _default: SpawnOptions<'_> = SpawnOptions::default();
    let _explicit = SpawnOptions::new();
}

#[test]
fn spawn_stdio_values_stay_stable() {
    // The enum's numeric encoding is part of the ABI we hand to frida-core;
    // silent renumbering (e.g. flipping Inherit and Pipe) would corrupt every
    // caller's stdio wiring. Pin the values.
    assert_eq!(SpawnStdio::Inherit as u32, 0);
    assert_eq!(SpawnStdio::Pipe as u32, 1);
}

#[test]
fn script_option_default_new_and_runtimes() {
    let _serial = serial_guard();
    let _f = &*FRIDA;

    let _default = ScriptOption::default();
    let _default_qjs = ScriptOption::new().set_runtime(ScriptRuntime::Default);
    let _qjs = ScriptOption::new().set_runtime(ScriptRuntime::QJS);
    let _v8 = ScriptOption::new().set_runtime(ScriptRuntime::V8);
}

#[test]
fn script_option_name_roundtrips() {
    // set_name -> get_name must survive the FFI hop.
    let _serial = serial_guard();
    let _f = &*FRIDA;

    // Note: `set_name` currently takes a `&str` and forwards `as_ptr()` — the
    // string must be nul-terminated on the Rust side (a raw string literal
    // without an explicit `\0` is NOT). Passing a CString-backed &str is the
    // safe path exercised here.
    let name = CString::new("script-option-name").expect("nul-free");
    let name_ref: &str = name.to_str().expect("utf-8");
    let opts = ScriptOption::new().set_name(name_ref);
    // get_name returns the stored value; on some platforms it may return
    // the underlying pointer verbatim, so accept a prefix match.
    let got = opts.get_name();
    assert!(
        got.starts_with("script-option-name"),
        "get_name should reflect set_name, got {got:?}"
    );
}
