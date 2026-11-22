//! Integration tests for `Device::enumerate_processes_with_options` and
//! `Process::get_parameters`.
//!
//! Tests run against the real frida-core (auto-downloaded via the
//! `auto-download` feature) and inspect a process known to be running: the
//! test process itself, or on Android the one that started it.
//!
//! The tests share one device manager, as a program has one for its whole life.
//! On Android a listing starts a Java VM in the calling process, which
//! frida-core 17.27 shuts down when the manager closes, and ART cannot be
//! started a second time in one process.
//!
//! No `device.attach(0)` happens here: enumerate_processes only reads
//! /proc-style host metadata, so the docker test job does not need
//! `--cap-add=SYS_PTRACE`.

use frida::{Device, DeviceManager, Frida, Scope, Variant};
use std::sync::{LazyLock, Mutex, MutexGuard};

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

// Frida-core is a process-wide singleton; serialize the tests so two
// threads don't race the device-manager / process-enumeration state.
static FRIDA_SERIAL: Mutex<()> = Mutex::new(());

fn serial_guard() -> MutexGuard<'static, ()> {
    FRIDA_SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

struct SharedManager(DeviceManager<'static>);

// SAFETY: a test uses the manager only while it holds `FRIDA_SERIAL`, so it is
// never used from two threads at once, and frida-core's device manager does not
// belong to the thread that created it.
unsafe impl Send for SharedManager {}
unsafe impl Sync for SharedManager {}

static MANAGER: LazyLock<SharedManager> =
    LazyLock::new(|| SharedManager(DeviceManager::obtain(&FRIDA)));

fn local_device() -> Device<'static> {
    MANAGER
        .0
        .get_local_device()
        .expect("local device should be available")
}

/// The pid of a process a listing is sure to hold: this one, except on Android.
/// There frida-core lists processes through a helper inside the calling process,
/// which leaves that process out, so it is the process that started this one.
fn known_pid() -> u32 {
    #[cfg(target_os = "android")]
    {
        std::os::unix::process::parent_id()
    }
    #[cfg(not(target_os = "android"))]
    {
        std::process::id()
    }
}

#[test]
fn get_parameters_returns_data_under_full_scope() {
    let _serial = serial_guard();
    let device = local_device();

    let processes = device.enumerate_processes_with_options(Scope::Full);
    assert!(
        !processes.is_empty(),
        "Scope::Full enumeration returned no processes"
    );

    let known = known_pid();
    let process = processes
        .iter()
        .find(|p| p.get_pid() == known)
        .expect("a process known to be running should appear in the Scope::Full enumeration");

    let params = process.get_parameters();
    assert!(
        !params.is_empty(),
        "Scope::Full Process::get_parameters() must populate the parameter table"
    );

    // Don't hard-code key names: those differ by host OS (e.g. Windows
    // emits `icons`, Linux emits `user` as a Map of uid/gid/name).
    // Assert structural shape instead: at least one Variant decoded
    // into String and at least one decoded into Int64. That covers the
    // common ppid (Int64 widened from uint32) + path (String) shape and
    // catches the original `todo!()` panic regression on unknown sigs.
    let has_string = params.values().any(|v| matches!(v, Variant::String(_)));
    let has_int = params.values().any(|v| matches!(v, Variant::Int64(_)));
    assert!(
        has_string,
        "expected at least one String-typed parameter, got: {:?}",
        params.keys().collect::<Vec<_>>()
    );
    assert!(
        has_int,
        "expected at least one Int64-typed parameter, got: {:?}",
        params.keys().collect::<Vec<_>>()
    );
}

#[test]
fn variant_iteration_never_panics_on_unknown_signatures() {
    // Core regression target of this PR: `Variant::from_ptr` previously
    // `todo!()`d on any GVariant signature the wrapper hadn't enumerated,
    // which panicked the whole process the first time frida-core handed
    // back something unexpected — Windows packs process icons as "ay"
    // byte arrays, so `get_parameters()` died on the first matching pid.
    //
    // The fix: route unknown sigs into `Variant::Unsupported(sig)`. This
    // test enumerates everything frida emits and exercises each accessor;
    // a future regression that reintroduces a panic on unknown sigs will
    // crash this test instead of a production caller.
    let _serial = serial_guard();
    let device = local_device();

    let processes = device.enumerate_processes_with_options(Scope::Full);
    for p in &processes {
        for (_key, v) in p.get_parameters() {
            // Run every accessor and the Debug impl — any panic here
            // breaks the contract that Variant must survive arbitrary
            // GVariant input from frida-core.
            let _ = v.get_string();
            let _ = v.get_int();
            let _ = v.get_bool();
            let _ = v.get_map();
            let _ = v.get_maplist();
            let _ = format!("{v:?}");
        }
    }
}

#[test]
fn get_parameters_is_empty_under_minimal_scope() {
    let _serial = serial_guard();
    let device = local_device();

    // Minimal scope must NOT populate the parameter table — that's the
    // whole reason Scope::Full exists. The plain enumerate_processes()
    // alias also uses Minimal; regressions here would silently bloat
    // every caller's enumeration.
    let processes = device.enumerate_processes_with_options(Scope::Minimal);
    let known = known_pid();
    let process = processes
        .iter()
        .find(|p| p.get_pid() == known)
        .expect("a process known to be running should appear in the Scope::Minimal enumeration");

    let params = process.get_parameters();
    assert!(
        params.is_empty(),
        "Scope::Minimal Process::get_parameters() must return an empty map, got keys {:?}",
        params.keys().collect::<Vec<_>>()
    );
}
