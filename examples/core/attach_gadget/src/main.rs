/*
 * Attach to an already-running app on a non-rooted Android device, the way
 * Frida 17.27's "Jailed Android" backend does: it breaks on
 * Binder.execTransact(), triggers it with `dumpsys meminfo`, injects Gadget on
 * that binder thread, then detaches from JDWP.
 *
 * Usage: attach_gadget <PID> [GADGET_PATH]
 *
 *   - <PID>        the pid of a debuggable, already-running Android app
 *   - GADGET_PATH  optional path to a custom frida-gadget.so to inject
 *                  (SessionOptions.gadget_path); omit for the bundled Gadget
 */

use frida::{DeviceManager, Frida};
use std::ffi::CString;
use std::sync::LazyLock;

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <PID> [GADGET_PATH]", args[0]);
        std::process::exit(1);
    }
    let pid: u32 = args[1].parse().expect("PID");

    let gadget_path = args.get(2).map(|p| CString::new(p.as_str()).unwrap());

    let device_manager = DeviceManager::obtain(&FRIDA);
    // Pick the USB device (the device the app is running on).
    let device = device_manager
        .enumerate_all_devices()
        .into_iter()
        .next()
        .expect("no device");

    let options = frida::SessionOptions::new();
    let options = match &gadget_path {
        Some(path) => options.gadget_path(path.as_c_str()),
        None => options,
    };

    let session = device
        .attach_with_options(pid, options)
        .expect("attach failed");
    assert!(!session.is_detached(), "session is detached");
    println!("attached (gadget_path = {:?})", gadget_path);

    session.detach().expect("detach");
    println!("detached");
}
