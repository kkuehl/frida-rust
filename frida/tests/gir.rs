/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Tests of `frida::gir` that need no device but the machine they run on: enumerations,
//! ownership, owners, device listing, attaching to this process, and errors from real
//! failing calls and from arguments that cannot be passed to C.

// The helpers of these tests fail the test by panicking, as the tests themselves may
// (clippy.toml allows that in a test, but not in a helper outside one).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use frida::{
    AuthenticationService, Cancellable, Device, DeviceManager, DeviceType, ErrorKind, FileMonitor,
    Object, ObjectType, Owned, Process, Realm, Relay, RelayKind, Scope, ScriptOptions,
    SessionOptions, SpawnOptions, StaticAuthenticationService, XnuMachTrap,
};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Attaching to this process from two tests at once is not something to test by accident.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

/// The reference count of the object behind a handle.
fn ref_count<T: ObjectType>(handle: &T) -> u32 {
    unsafe { (*handle.as_object().as_ptr()).ref_count }
}

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Waits for the reference count to settle at `expected`. Dropping a handle calls
/// `frida_unref`, which gives the reference back on frida-core's main loop, not at once.
fn assert_ref_count_settles<T: ObjectType>(handle: &T, expected: u32, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while ref_count(handle) != expected && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(ref_count(handle), expected, "{what}");
}

#[test]
fn enumerations_convert_display_and_parse() {
    for scope in [Scope::Minimal, Scope::Metadata, Scope::Full] {
        assert_eq!(Scope::from_raw(scope.into_raw()), scope);
        assert_eq!(scope.to_string().parse::<Scope>().unwrap(), scope);
    }
    assert_eq!(Scope::Full.into_raw(), 2);
    assert_eq!(Scope::from(1), Scope::Metadata);
    assert_eq!(frida_sys::FridaScope::from(Scope::Minimal), 0);
    assert_eq!(DeviceType::Usb.to_string(), "usb");
    assert_eq!(RelayKind::TurnUdp.to_string(), "turn-udp");
    assert_eq!("turn-tls".parse::<RelayKind>().unwrap(), RelayKind::TurnTls);

    let unknown = Scope::from_raw(99);
    assert_eq!(unknown, Scope::Unknown(99));
    assert_eq!(unknown.into_raw(), 99);
    assert_eq!(unknown.to_string(), "unknown");

    // Negative values, which the C side keeps in a signed type.
    assert_eq!(XnuMachTrap::from_raw(-10), XnuMachTrap::MachVmAllocate);
    assert_eq!(XnuMachTrap::MachVmAllocate.into_raw(), -10);
    assert_eq!(XnuMachTrap::from_raw(12345), XnuMachTrap::Unknown(12345));
}

#[test]
fn a_name_that_is_not_a_nick_does_not_parse() {
    let error = "sideways".parse::<Scope>().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    assert!(error.to_string().contains("sideways"), "{error}");
}

#[test]
fn error_kinds_describe_themselves() {
    assert_eq!(
        ErrorKind::ProcessNotFound.to_string(),
        "no process matched the request"
    );
    assert_eq!(ErrorKind::Cancelled.to_string(), "operation was cancelled");
}

#[test]
fn options_are_values_built_in_one_expression() {
    let options = SpawnOptions::new()
        .argv(["ls", "-l"])
        .env([("LANG", "C")])
        .cwd("/tmp");
    assert_eq!(
        options.argv.as_deref(),
        Some(&["ls".to_string(), "-l".to_string()][..])
    );
    assert_eq!(
        options.env,
        Some(vec![("LANG".to_string(), "C".to_string())])
    );
    assert_eq!(options.cwd.as_deref(), Some("/tmp"));
    assert_eq!(options.clone(), options);
    assert_ne!(options, SpawnOptions::default());

    let session = SessionOptions::new()
        .realm(Realm::Emulated)
        .persist_timeout(Duration::from_secs(30));
    assert_eq!(session.persist_timeout, Duration::from_secs(30));
    let debug = format!("{session:?}");
    assert!(
        debug.contains("Emulated") && debug.contains("30s"),
        "{debug}"
    );

    // For frida-sys, a value builds the frida-core object it stands for.
    let object = options.to_object().unwrap();
    assert_eq!(object.type_name(), "FridaSpawnOptions");
    assert!(!object.as_ptr().is_null());
    let error = SpawnOptions::new().cwd("a\0b").to_object().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);

    let script = ScriptOptions::new().name("probe");
    assert_eq!(script.name.as_deref(), Some("probe"));
}

#[test]
fn handles_own_exactly_one_reference() {
    let relay = Relay::new("192.0.2.1:3478", "user", "pass", RelayKind::TurnTcp).unwrap();
    assert_eq!(
        ref_count(&relay),
        1,
        "a constructor's transfer-full result is taken, not reffed"
    );
    let copy = relay.clone();
    assert_eq!(ref_count(&relay), 2, "a clone takes one reference");
    assert_eq!(copy, relay, "and refers to the same object");
    drop(copy);
    assert_ref_count_settles(&relay, 1, "dropping the clone gives it back");

    let object: Object = relay.clone().into();
    assert_eq!(
        ref_count(&relay),
        2,
        "an upcast keeps the clone's reference"
    );
    drop(object);
    assert_ref_count_settles(&relay, 1, "dropping the upcast gives it back");
}

#[test]
fn records_read_back_and_debug_print_their_properties() {
    let relay = Relay::new("192.0.2.1:3478", "user", "pass", RelayKind::TurnTcp).unwrap();
    assert_eq!(relay.address(), "192.0.2.1:3478");
    assert_eq!(relay.username(), "user");
    assert_eq!(relay.kind(), RelayKind::TurnTcp);
    let debug = format!("{relay:?}");
    assert!(
        debug.starts_with("Relay {") && debug.contains("192.0.2.1:3478"),
        "{debug}"
    );
}

#[test]
fn upcasts_and_downcasts_follow_the_type_hierarchy() {
    let service = StaticAuthenticationService::new("secret").unwrap();
    let iface: &AuthenticationService = service.as_ref();
    assert_eq!(iface.type_name(), "FridaStaticAuthenticationService");

    let object: Object = service.clone().into();
    assert!(object.is::<AuthenticationService>());
    assert!(!object.is::<Device>());
    assert_eq!(
        object.downcast::<StaticAuthenticationService>(),
        Some(service.clone())
    );
    assert_eq!(object.downcast::<Relay>(), None);
}

#[test]
fn every_type_can_cross_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DeviceManager>();
    assert_send_sync::<Owned<DeviceManager>>();
    assert_send_sync::<Device>();
    assert_send_sync::<Process>();
    assert_send_sync::<Cancellable>();
    assert_send_sync::<Object>();
    assert_send_sync::<SpawnOptions>();
    assert_send_sync::<SessionOptions>();
    assert_send_sync::<frida::BareboneConfig>();
    assert_send_sync::<frida::LanguageServer>();
    assert_send_sync::<frida::PortalService>();
    assert_send_sync::<frida::PackageManager>();
    assert_send_sync::<frida::Error>();
}

#[test]
fn devices_are_listed() {
    let _serial = serial();
    let manager = DeviceManager::new().unwrap();
    let devices: Vec<Device> = manager.enumerate_devices(None).unwrap();
    let local = devices
        .iter()
        .find(|d| d.id() == "local")
        .expect("the local device is listed");
    assert_eq!(local.device_type(), DeviceType::Local);
    assert!(!local.name().is_empty());
    assert!(!local.is_lost());
    let debug = format!("{local:?}");
    assert!(debug.contains("\"local\""), "{debug}");
    let params = local.query_system_parameters(None).unwrap();
    assert!(params.contains_key("os"), "{params:?}");
    manager.close(None).expect("close the manager");
}

#[test]
fn a_predicate_closure_finds_a_device_and_its_panic_comes_back() {
    let _serial = serial();
    let manager = DeviceManager::new().unwrap();
    let mut seen = Vec::new();
    let found = manager
        .find_device(
            |device: &Device| {
                seen.push(device.id());
                device.device_type() == DeviceType::Local
            },
            Some(Duration::from_secs(1)),
            None,
        )
        .unwrap();
    assert_eq!(found.map(|d| d.id()).as_deref(), Some("local"));
    assert!(seen.iter().any(|id| id == "local"), "{seen:?}");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = manager.find_device(
            |_: &Device| panic!("from the predicate"),
            Some(Duration::from_secs(1)),
            None,
        );
    }));
    let panic = result.expect_err("the predicate's panic is raised again");
    assert_eq!(panic.downcast_ref::<&str>(), Some(&"from the predicate"));
}

#[test]
fn a_device_that_does_not_appear_in_time_is_an_error() {
    let manager = DeviceManager::new().unwrap();
    let started = Instant::now();
    let error = manager
        .get_device_by_id("no-such-device", Some(Duration::from_millis(200)), None)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument, "{error}");
    assert!(started.elapsed() >= Duration::from_millis(150));
    // A wait longer than frida-core can, refused before anything is asked.
    let error = manager
        .get_device_by_id("local", Some(Duration::from_secs(u64::MAX)), None)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    // And a NUL byte in the id.
    let error = manager
        .get_device_by_id("lo\0cal", Some(Duration::ZERO), None)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);
}

#[test]
fn attaching_to_this_process_creates_and_loads_a_script() {
    let _serial = serial();
    let manager = DeviceManager::new().unwrap();
    let device = manager.get_local_device().unwrap();

    let session = device.attach(0, None, None).unwrap();
    // The session reports the pid it was asked for, and 0 means this process.
    assert_eq!(session.pid(), 0);
    assert!(!session.is_detached());

    let options = ScriptOptions::new().name("gir-test");
    let script = session
        .create_script("const answer = 6 * 7;", Some(&options), None)
        .unwrap();
    assert!(!script.is_destroyed());
    script.load(None).unwrap();
    let handle = script.clone();
    script.unload(None).expect("unload the script, explicitly");
    assert!(handle.is_destroyed());

    session.detach(None).expect("detach, explicitly");
    manager.close(None).expect("close the manager, explicitly");
}

#[test]
fn dropping_owners_releases_in_order() {
    let _serial = serial();
    let manager = DeviceManager::new().unwrap();
    let device = manager.get_local_device().unwrap();
    let session = device.attach(0, None, None).unwrap();
    let script = session.create_script("1;", None, None).unwrap();
    script.load(None).unwrap();
    let (script_handle, session_handle, manager_handle) =
        (script.clone(), session.clone(), manager.clone());

    drop(script);
    wait_for("the script to be unloaded", || script_handle.is_destroyed());
    assert!(
        !session_handle.is_detached(),
        "only the script's owner went"
    );

    drop(session);
    wait_for("the session to be detached", || {
        session_handle.is_detached()
    });

    drop(manager);
    wait_for("the manager to be closed", || {
        manager_handle
            .enumerate_devices(None)
            .is_err_and(|e| e.kind() == ErrorKind::InvalidOperation)
    });
    // A handle outlives its owner, and calls on it fail rather than misbehave.
    let error = script_handle.load(None).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidOperation, "{error}");
}

#[test]
fn keep_leaves_what_an_owner_owns_open() {
    let _serial = serial();
    let manager = DeviceManager::new().unwrap();
    let device = manager.get_local_device().unwrap();
    let session = device.attach(0, None, None).unwrap().keep();
    std::thread::sleep(Duration::from_millis(200));
    assert!(!session.is_detached(), "keep releases nothing");
    session.detach(None).unwrap();
    assert!(session.is_detached());
}

#[test]
fn releasing_twice_reports_the_second_as_an_error() {
    let _serial = serial();
    let manager = DeviceManager::new().unwrap();
    let device = manager.get_local_device().unwrap();
    let session = device.attach(0, None, None).unwrap();
    let script = session.create_script("1;", None, None).unwrap();
    script.unload(None).unwrap();
    // The owner's release consumed it; a handle can still ask again.
    let other = session.create_script("2;", None, None).unwrap();
    let handle = other.clone();
    other.unload(None).unwrap();
    let error = handle.unload(None).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidOperation, "{error}");
}

#[test]
fn a_script_that_does_not_compile_is_an_error_with_a_message() {
    let _serial = serial();
    let manager = DeviceManager::new().unwrap();
    let device = manager.get_local_device().unwrap();
    let session = device.attach(0, None, None).unwrap();

    let error = session
        .create_script("this is not javascript (", None, None)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument, "{error}");
    assert!(!error.message().is_empty());
    assert_eq!(error.domain().map(|(d, _)| d), Some("frida-error-quark"));

    let error = session.create_script("a\0b", None, None).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    assert!(error.message().contains("NUL"), "{error}");
}

/// A pid nothing runs under: one that existed a moment ago, and has been reaped. The child
/// is this test binary listing its tests, which exits at once.
#[cfg(not(windows))]
fn unused_pid() -> u32 {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--list")
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    child.wait().unwrap();
    pid
}

/// A pid nothing runs under. Not that of a child that has exited: Windows keeps a process,
/// and its pid, for as long as anything holds a handle to it, which security software may,
/// and frida-core 17.27.4 never returns from attaching to one (its helper drops the Gum
/// error it gets allocating memory there). Pids are multiples of four, far below this one.
#[cfg(windows)]
fn unused_pid() -> u32 {
    u32::MAX - 3
}

#[test]
fn attaching_to_a_pid_that_does_not_exist_is_process_not_found() {
    let _serial = serial();
    let pid = unused_pid();

    let manager = DeviceManager::new().unwrap();
    let device = manager.get_local_device().unwrap();
    let error = device.attach(pid, None, None).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ProcessNotFound, "{error}");
    assert!(!error.to_string().is_empty());
}

#[test]
fn an_option_that_cannot_be_passed_fails_before_anything_is_spawned() {
    let manager = DeviceManager::new().unwrap();
    let device = manager.get_local_device().unwrap();
    let options = SpawnOptions::new().env([("NAME=VALUE", "x")]);
    let error = device
        .spawn("/no/such/program", Some(&options), None)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument, "{error}");
    let options = SpawnOptions::new().aux("x", frida::Variant::Unsupported("q".into()));
    let error = device
        .spawn("/no/such/program", Some(&options), None)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument, "{error}");
}

#[test]
fn a_cancelled_call_fails_as_cancelled() {
    let _serial = serial();
    let cancellable = Cancellable::new().unwrap();
    assert!(!cancellable.is_cancelled());
    cancellable.cancel();
    assert!(cancellable.is_cancelled());

    let manager = DeviceManager::new().unwrap();
    let device = manager.get_local_device().unwrap();
    let error = device.attach(0, None, Some(&cancellable)).unwrap_err();
    assert!(error.is_cancelled(), "{error:?}");
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert_eq!(error.domain(), Some(("g-io-error-quark", 19)));
}

#[test]
fn cancellables_can_cross_threads() {
    let cancellable = Cancellable::new().unwrap();
    let other = cancellable.clone();
    std::thread::spawn(move || other.cancel()).join().unwrap();
    assert!(cancellable.is_cancelled());
}

#[test]
fn a_file_monitor_takes_a_path_and_refuses_a_bad_one() {
    let dir = tempfile::tempdir().unwrap();
    let monitor = FileMonitor::new(dir.path()).unwrap();
    assert_eq!(monitor.path(), dir.path());
    monitor.enable(None).unwrap();
    // Its owner disables it; doing it again by hand is the error frida-core reports.
    let handle = monitor.clone();
    monitor.disable(None).unwrap();
    let error = handle.disable(None).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidOperation, "{error}");

    let error = FileMonitor::new(Path::new("/tmp/a\0b")).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);
}

#[test]
fn the_version_is_the_one_frida_version_names() {
    let expected = include_str!("../../FRIDA_VERSION").trim();
    assert_eq!(frida::version(), expected);
}
