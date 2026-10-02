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
    // We bump the crate to 17.18.0 in FRIDA_VERSION; the devkit should follow.
    assert_eq!(parts[0], "17", "unexpected major version: {version:?}");
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
