//! Integration tests for [`DeviceManager`] and [`Device`] basic accessors.
//!
//! These hit the real frida-core (auto-download) but stay in read-only /
//! metadata territory so they don't need elevated privileges.

use frida::{Device, DeviceManager, DeviceType, Frida};
use std::sync::{LazyLock, Mutex, MutexGuard};

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });
static FRIDA_SERIAL: Mutex<()> = Mutex::new(());

fn serial_guard() -> MutexGuard<'static, ()> {
    FRIDA_SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

fn local<'a>(dm: &'a DeviceManager<'a>) -> Device<'a> {
    dm.get_local_device()
        .expect("local device should always exist")
}

#[test]
fn get_local_device_and_by_id_agree() {
    let _serial = serial_guard();
    let dm = DeviceManager::obtain(&FRIDA);

    let by_type = local(&dm);
    assert_eq!(
        by_type.get_type(),
        DeviceType::Local,
        "get_local_device() must return DeviceType::Local"
    );
    let id = by_type.get_id().to_owned();
    assert!(!id.is_empty(), "local device id must not be empty");

    let by_id = dm
        .get_device_by_id(&id)
        .expect("get_device_by_id(local id)");
    assert_eq!(by_id.get_id(), id, "device fetched by id must round-trip");
    assert_eq!(
        by_id.get_type(),
        DeviceType::Local,
        "device fetched by local id must be Local"
    );
}

#[test]
fn enumerate_all_devices_includes_local() {
    let _serial = serial_guard();
    let dm = DeviceManager::obtain(&FRIDA);

    let devices = dm.enumerate_all_devices();
    assert!(
        !devices.is_empty(),
        "enumerate_all_devices should always return at least the local device"
    );
    assert!(
        devices.iter().any(|d| d.get_type() == DeviceType::Local),
        "enumerate_all_devices must contain the local device"
    );
}

#[test]
fn local_device_reports_name_and_is_not_lost() {
    let _serial = serial_guard();
    let dm = DeviceManager::obtain(&FRIDA);
    let dev = local(&dm);

    let name = dev.get_name();
    assert!(!name.is_empty(), "local device name should not be empty");
    assert!(
        !dev.is_lost(),
        "freshly-obtained local device must not report as lost"
    );
}

#[test]
fn query_system_parameters_populates_os_key() {
    // frida-core always ships an "os" entry in the system parameters map.
    // If this shape ever changes, dependent tooling breaks — catch it here.
    let _serial = serial_guard();
    let dm = DeviceManager::obtain(&FRIDA);
    let dev = local(&dm);

    let params = dev
        .query_system_parameters()
        .expect("query_system_parameters should succeed for the local device");
    assert!(
        params.contains_key("os"),
        "system parameters must contain an \"os\" key, got: {:?}",
        params.keys().collect::<Vec<_>>()
    );
}

#[test]
fn enumerate_processes_includes_this_test_process() {
    let _serial = serial_guard();
    let dm = DeviceManager::obtain(&FRIDA);
    let dev = local(&dm);

    let procs = dev.enumerate_processes();
    let own = std::process::id();
    let me = procs
        .iter()
        .find(|p| p.get_pid() == own)
        .expect("the running test process must appear in enumerate_processes()");
    assert!(
        !me.get_name().is_empty(),
        "enumerated process must have a name"
    );
}

#[test]
fn device_type_display_and_equality() {
    // Cheap unit-shape checks so a rename in the underlying enum trips a test
    // before it silently breaks Display consumers (logs / CLI output).
    assert_eq!(format!("{}", DeviceType::Local), "Local");
    assert_eq!(format!("{}", DeviceType::Remote), "Remote");
    assert_eq!(format!("{}", DeviceType::USB), "USB");
    assert_ne!(DeviceType::Local, DeviceType::Remote);
}

#[test]
fn get_device_by_id_returns_error_for_bogus_id() {
    let _serial = serial_guard();
    let dm = DeviceManager::obtain(&FRIDA);
    let err = dm.get_device_by_id("this-device-does-not-exist-anywhere");
    assert!(
        err.is_err(),
        "get_device_by_id must fail for a nonexistent id"
    );
}
