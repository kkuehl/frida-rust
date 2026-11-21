//! Tests for the [`Frida`] singleton itself: initialization idempotency,
//! version reporting, and the `schedule_on_main` glib-context bridge.

use frida::{DeviceManager, Frida};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};

// Serialize with the other integration tests that touch the singleton.
static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });
static FRIDA_SERIAL: Mutex<()> = Mutex::new(());

fn serial_guard() -> MutexGuard<'static, ()> {
    FRIDA_SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

#[test]
fn version_matches_devkit_and_is_non_empty() {
    let _serial = serial_guard();
    let _f = &*FRIDA;

    let version = Frida::version();
    assert!(
        !version.is_empty(),
        "Frida::version() must return the linked devkit version, got empty string"
    );
    // Every stable devkit release ships as "MAJOR.MINOR.PATCH"; enforce shape
    // so nightly-only builds that drift from that don't quietly slip in.
    let parts: Vec<&str> = version.split('.').collect();
    assert!(
        parts.len() >= 3 && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit())),
        "Frida::version() should look like MAJOR.MINOR.PATCH, got {version:?}"
    );
    // The devkit must be the release FRIDA_VERSION names. A build that downloads it asks for
    // that release by name, and one placed by hand has to be the same one: the bindings are
    // written against that release's API.
    let pinned = include_str!("../../FRIDA_VERSION").trim();
    assert_eq!(
        version, pinned,
        "the linked devkit is Frida {version}, but FRIDA_VERSION says {pinned}"
    );
    // The header the bindings were generated from came with the same devkit.
    let header = std::ffi::CStr::from_bytes_with_nul(frida_sys::FRIDA_VERSION)
        .expect("the header's version is a C string")
        .to_str()
        .expect("the header's version is ASCII");
    assert_eq!(
        header, pinned,
        "the devkit's header is Frida {header}, but FRIDA_VERSION says {pinned}"
    );
}

#[test]
fn version_files_agree() {
    // The Gum devkit carries no version of its own to check, so this is what keeps it the same
    // release as the core devkit: each sys crate downloads the one its own file names.
    let root = include_str!("../../FRIDA_VERSION").trim();
    assert_eq!(include_str!("../../frida-sys/FRIDA_VERSION").trim(), root);
    assert_eq!(
        include_str!("../../frida-gum-sys/FRIDA_VERSION").trim(),
        root
    );
}

#[test]
fn version_is_stable_across_calls() {
    // The Frida wrapper is a process-lifetime singleton (drop calls
    // `frida_deinit`), so we can't churn constructors. But repeated reads of
    // the version string on the shared singleton must be stable and non-empty.
    let _serial = serial_guard();
    let _f = &*FRIDA;
    let first = Frida::version().to_string();
    let second = Frida::version().to_string();
    assert_eq!(first, second, "version must be stable across calls");
    assert!(!first.is_empty(), "version must never be empty");
}

#[test]
fn schedule_on_main_runs_the_closure() {
    // `schedule_on_main` posts an idle source to frida's glib main context.
    // The main loop is running (frida-core drives it internally), so the
    // closure must eventually fire.
    let _serial = serial_guard();
    let f = &*FRIDA;

    let fired = Arc::new(AtomicBool::new(false));
    let fired_c = fired.clone();
    f.schedule_on_main(move || {
        fired_c.store(true, Ordering::SeqCst);
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if fired.load(Ordering::SeqCst) {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("schedule_on_main closure never fired within 5s");
}

#[test]
fn device_manager_survives_repeated_obtain() {
    // Regression guard: the DeviceManager borrows the Frida handle by
    // lifetime, so churning managers without touching the singleton should
    // not accumulate state or leak. Doing this on a fresh singleton is what
    // real callers do on process startup / hot-reload paths.
    let _serial = serial_guard();
    for _ in 0..3 {
        let dm = DeviceManager::obtain(&FRIDA);
        let _local = dm
            .get_local_device()
            .expect("local device should always exist");
    }
}
