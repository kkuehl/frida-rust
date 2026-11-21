//! A string the caller passes may hold a NUL, which C cannot be given. Each
//! such call fails with `Error::CStringFailed` instead of panicking.

use frida::{DeviceManager, Error, Frida, Inject, Injector, SpawnOptions};
use std::sync::{LazyLock, Mutex, MutexGuard};

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });
static FRIDA_SERIAL: Mutex<()> = Mutex::new(());

fn serial_guard() -> MutexGuard<'static, ()> {
    FRIDA_SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

fn is_cstring_failed<T>(result: frida::Result<T>) -> bool {
    matches!(result, Err(Error::CStringFailed))
}

#[test]
fn spawn_a_program_with_a_nul() {
    let _serial = serial_guard();
    let dm = DeviceManager::obtain(&FRIDA);
    let mut device = dm.get_local_device().expect("local device");
    let result = device.spawn("/bin/\0echo", &SpawnOptions::new());
    assert!(is_cstring_failed(result));
}

#[test]
fn look_up_a_device_id_with_a_nul() {
    let _serial = serial_guard();
    let dm = DeviceManager::obtain(&FRIDA);
    assert!(is_cstring_failed(dm.get_device_by_id("lo\0cal")));
}

#[test]
fn inject_with_a_nul_in_the_entrypoint_or_data() {
    let _serial = serial_guard();
    let _f = &*FRIDA;
    let mut injector = Injector::in_process();
    let blob = [0u8; 4];
    assert!(is_cstring_failed(injector.inject_library_file_sync(
        0,
        "/nonexistent.dylib",
        "entry\0point",
        "data",
    )));
    assert!(is_cstring_failed(injector.inject_library_file_sync(
        0,
        "/nonexistent.dylib",
        "entrypoint",
        "da\0ta",
    )));
    assert!(is_cstring_failed(injector.inject_library_blob_sync(
        0,
        &blob,
        "entry\0point",
        "data",
    )));
    assert!(is_cstring_failed(injector.inject_library_blob_sync(
        0,
        &blob,
        "entrypoint",
        "da\0ta",
    )));
}

#[test]
fn inject_through_a_device_with_a_nul_in_the_entrypoint_or_data() {
    let _serial = serial_guard();
    let dm = DeviceManager::obtain(&FRIDA);
    let mut device = dm.get_local_device().expect("local device");
    let blob = [0u8; 4];
    assert!(is_cstring_failed(device.inject_library_file_sync(
        0,
        "/nonexistent.dylib",
        "entry\0point",
        "data",
    )));
    assert!(is_cstring_failed(device.inject_library_file_sync(
        0,
        "/nonexistent.dylib",
        "entrypoint",
        "da\0ta",
    )));
    assert!(is_cstring_failed(device.inject_library_blob_sync(
        0,
        &blob,
        "entry\0point",
        "data",
    )));
    assert!(is_cstring_failed(device.inject_library_blob_sync(
        0,
        &blob,
        "entrypoint",
        "da\0ta",
    )));
}
