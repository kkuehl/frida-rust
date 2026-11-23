/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Tests of the parts of `frida::gir` written by hand beside the kernel, pattern and
//! injector classes, and of `schedule_on_frida_thread`. No device is needed.

// The helpers of these tests fail the test by panicking, as the tests themselves may
// (clippy.toml allows that in a test, but not in a helper outside one).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use frida::{
    DeviceManager, ErrorKind, Inject, Injector, LinuxSystemMap, PatternCompileOptions,
    PatternCompiler,
};
use std::path::Path;
use std::sync::mpsc::channel;
use std::time::Duration;

const SYSTEM_MAP: &str = "\
ffffffff81000000 T _text
ffffffff81000100 t helper
ffffffff82000000 D some_data
";

#[test]
fn a_system_map_is_split_into_lines_whichever_way_they_end() {
    let with_crlf = SYSTEM_MAP.replace('\n', "\r\n");
    for text in [SYSTEM_MAP, &with_crlf, SYSTEM_MAP.trim_end()] {
        let map = LinuxSystemMap::from_blob(text.as_bytes()).unwrap();
        assert_eq!(
            map.try_find_symbol("helper").unwrap(),
            Some(0xffff_ffff_8100_0100),
            "{text:?}"
        );
        assert!(map.has_symbol("some_data").unwrap());
    }
}

#[test]
fn a_system_map_is_read_no_further_than_its_bytes() {
    // frida-core reads the blob as a C string: without the NUL these bindings add, it
    // would read on into `beyond`.
    let buffer = "ffffffff81000000 T _text\nffffffff81000100 T beyond\n";
    let map = LinuxSystemMap::from_blob(&buffer.as_bytes()[..25]).unwrap();
    assert!(map.has_symbol("_text").unwrap());
    assert!(!map.has_symbol("beyond").unwrap());
}

#[test]
fn a_system_map_is_read_from_a_path_and_a_bad_one_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("System.map");
    std::fs::write(&path, SYSTEM_MAP).unwrap();
    let map = LinuxSystemMap::open(&path).unwrap();
    assert_eq!(
        map.try_find_symbol("_text").unwrap(),
        Some(0xffff_ffff_8100_0000)
    );

    let error = LinuxSystemMap::open(&dir.path().join("missing")).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    assert!(std::error::Error::source(&error).is_some(), "the I/O error");

    let error = LinuxSystemMap::from_blob(b"nothing to see here\n").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument, "{error}");

    let error = map.has_symbol("hel\0per").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);
}

const PATTERN: &str = "\
struct Vec3 {
\tfloat x;
\tfloat y;
\tfloat z;
};

struct Player {
\tu32 hitpoints;
\tVec3 position;
};
";

#[test]
fn a_pattern_compiles_and_decodes_into_vecs_and_floats() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("player.hexpat"), PATTERN).unwrap();
    let options = PatternCompileOptions::new()
        .project_root(dir.path())
        .platform("darwin")
        .arch("arm64");
    let module = PatternCompiler::new()
        .unwrap()
        .compile("player.hexpat", Some(&options), None)
        .unwrap();
    let diagnostics: Vec<String> = module
        .diagnostics()
        .unwrap()
        .iter()
        .map(|d| d.message())
        .collect();
    assert!(diagnostics.is_empty(), "{diagnostics:?}");

    let types = module.types().unwrap();
    let player = types.iter().find(|t| t.name() == "Player").unwrap();
    let fields: Vec<String> = player.fields().unwrap().iter().map(|f| f.name()).collect();
    assert_eq!(fields, ["hitpoints", "position"]);

    let mut data = [0u8; 16];
    data[0] = 94;
    data[4..8].copy_from_slice(&1.5f32.to_le_bytes());
    let value = module.decode("Player", &data, 0x1000, None, None).unwrap();
    let fields = value.fields().unwrap();
    assert_eq!(fields[0].value_as_f64(), None, "an integer is not a float");
    let position = fields[1].fields().unwrap();
    assert_eq!(position[0].value_as_f64(), Some(1.5));
}

#[test]
fn inject_spans_devices_and_injectors() {
    fn inject(into: &impl Inject, pid: u32) -> frida::Error {
        into.inject_library_file(pid, Path::new("/no/such/agent.so"), "main", "", None)
            .expect_err("no process to inject into")
    }
    // A pid that existed a moment ago, and has been reaped.
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--list")
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    child.wait().unwrap();

    let manager = DeviceManager::new().unwrap();
    let device = manager.get_local_device().unwrap();
    let from_device = inject(&device, pid);
    let injector = Injector::new().unwrap();
    let from_injector = inject(&*injector, pid);
    for error in [from_device, from_injector] {
        assert_ne!(error.kind(), ErrorKind::Unexpected, "{error}");
        assert!(!error.message().is_empty());
    }
    injector.close(None).expect("close the injector");
}

#[test]
fn a_closure_scheduled_on_fridas_thread_runs_there_once() {
    // The thread frida-core's signals are emitted on, which is not this one.
    let monitor = frida::FileMonitor::new(&std::env::temp_dir()).unwrap();
    let (sender, receiver) = channel();
    frida::schedule_on_frida_thread(move || {
        let _ = sender.send(std::thread::current().id());
    })
    .unwrap();
    let ran_on = receiver.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_ne!(ran_on, std::thread::current().id());
    assert!(
        receiver.recv_timeout(Duration::from_millis(100)).is_err(),
        "once"
    );
    // A blocking call made from there runs directly, as on frida-core's own thread.
    let (sender, receiver) = channel();
    let handle = monitor.handle().clone();
    frida::schedule_on_frida_thread(move || {
        let _ = sender.send((std::thread::current().id(), handle.enable(None).is_ok()));
    })
    .unwrap();
    let (again, enabled) = receiver.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(again, ran_on, "the same thread each time");
    assert!(enabled);

    // A panic there is caught, and the thread carries on.
    frida::schedule_on_frida_thread(|| panic!("on frida-core's thread")).unwrap();
    let (sender, receiver) = channel();
    frida::schedule_on_frida_thread(move || {
        let _ = sender.send(());
    })
    .unwrap();
    receiver.recv_timeout(Duration::from_secs(10)).unwrap();
}
