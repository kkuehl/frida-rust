/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! `frida::deinit`, alone in its own test binary: deinitializing frida-core ends it for
//! the rest of the process.

use frida::{Cancellable, DeviceManager, ErrorKind};

#[test]
fn deinit_waits_for_every_handle_and_then_is_final() {
    let manager = DeviceManager::new().unwrap();
    let device = manager.get_local_device().unwrap();
    let error = frida::deinit().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidOperation, "{error}");

    // Still running: the refusal changed nothing.
    assert!(!device.name().is_empty());
    let cancellable = Cancellable::new().unwrap();
    drop((manager, device));
    let error = frida::deinit().unwrap_err();
    assert_eq!(
        error.kind(),
        ErrorKind::InvalidOperation,
        "the cancellable is alive"
    );
    drop(cancellable);

    // The manager's close was queued when its owner dropped; its handle goes once it runs.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match frida::deinit() {
            Ok(()) => break,
            Err(error) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "never released: {error}"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
    frida::deinit().expect("deinitializing again does nothing");

    // Where a constructor used to panic, it now says why it cannot.
    let error = DeviceManager::new().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidOperation, "{error}");
    let error = Cancellable::new().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
}
