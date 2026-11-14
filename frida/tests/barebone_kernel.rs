//! Tests for the Barebone configuration objects and the kernels they are given. Nothing here
//! connects to a target: the objects are built, read back and checked.

use frida::{
    BareboneConfig, BareboneConnectionConfig, BareboneGoldfishPipeTransportConfig,
    BareboneLinuxKernelConfig, BareboneSerialTransportConfig, BareboneStubFlavor,
    BareboneVsockPipeTransportConfig, BareboneXnuKernelcacheConfig, Error, Frida, LinuxKernelImage,
    LinuxSystemMap, XnuKernelcache,
};
use std::sync::{LazyLock, Mutex, MutexGuard};

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

// Frida-core is a process-wide singleton, so all tests that talk to it must
// serialize (same convention as `compile_script.rs`).
static FRIDA_SERIAL: Mutex<()> = Mutex::new(());

fn serial_guard() -> MutexGuard<'static, ()> {
    let _frida = &*FRIDA;
    FRIDA_SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

const SYSTEM_MAP: &str = "ffffffff81000000 T _text\n\
                          ffffffff81000100 t helper\n\
                          not a symbol line\n\
                          ffffffff82000000 D some_data\n";

/// The message of the error a `check` gave, or `None` if it found nothing wrong.
fn complaint(checked: frida::Result<()>) -> Option<String> {
    match checked {
        Ok(()) => None,
        Err(Error::BareboneConfigInvalid { message, .. }) => Some(message),
        Err(other) => panic!("a check should fail with BareboneConfigInvalid, not {other:?}"),
    }
}

/// The message of the error reading a kernel gave.
fn read_failure<T>(read: frida::Result<T>) -> String {
    match read {
        Ok(_) => panic!("the kernel should not have been readable"),
        Err(Error::KernelReadFailed { message, .. }) => message,
        Err(other) => panic!("reading should fail with KernelReadFailed, not {other:?}"),
    }
}

#[test]
fn a_connection_defaults_to_a_local_gdb_stub() {
    let _serial = serial_guard();
    let connection = BareboneConnectionConfig::new();

    assert_eq!(connection.host().as_deref(), Some("127.0.0.1"));
    assert_eq!(connection.port(), 3333);
    assert_eq!(connection.pid(), 0);
    assert_eq!(connection.flavor(), BareboneStubFlavor::GdbRemote);
    assert_eq!(complaint(connection.check()), None);
}

#[test]
fn a_connection_keeps_what_it_is_set_to() {
    let _serial = serial_guard();
    let connection = BareboneConnectionConfig::new();

    connection.set_host("stub.example");
    connection.set_port(1234);
    connection.set_pid(4321);
    connection.set_flavor(BareboneStubFlavor::VirtualBoxConsole);
    connection.set_host("ignored\0host");

    assert_eq!(connection.host().as_deref(), Some("stub.example"));
    assert_eq!(connection.port(), 1234);
    assert_eq!(connection.pid(), 4321);
    assert_eq!(connection.flavor(), BareboneStubFlavor::VirtualBoxConsole);
}

#[test]
fn a_connection_to_a_hosted_stub_needs_the_process_that_hosts_it() {
    let _serial = serial_guard();

    for flavor in [BareboneStubFlavor::Vz, BareboneStubFlavor::AndroidEmulator] {
        let connection = BareboneConnectionConfig::new();
        connection.set_flavor(flavor);
        let without_pid = complaint(connection.check());
        connection.set_pid(1);
        let with_pid = complaint(connection.check());

        assert!(
            without_pid
                .as_deref()
                .is_some_and(|message| message.contains("connection.pid")),
            "{flavor:?}: {without_pid:?}"
        );
        assert_eq!(with_pid, None, "{flavor:?}");
    }
}

#[test]
fn a_transport_needs_its_path() {
    let _serial = serial_guard();
    let serial = BareboneSerialTransportConfig::new();
    let vsock = BareboneVsockPipeTransportConfig::new();
    let goldfish = BareboneGoldfishPipeTransportConfig::new();

    let unset = [
        (serial.path(), complaint(serial.check())),
        (vsock.socket_path(), complaint(vsock.check())),
        (goldfish.socket_path(), complaint(goldfish.check())),
    ];
    serial.set_path("/dev/ttyS1");
    vsock.set_socket_path("/tmp/vsock.sock");
    goldfish.set_socket_path("/tmp/goldfish.sock");

    for (path, complaint) in unset {
        assert_eq!(path, None);
        assert!(
            complaint
                .as_deref()
                .is_some_and(|message| message.contains("agent.transport")),
            "{complaint:?}"
        );
    }
    assert_eq!(serial.path().as_deref(), Some("/dev/ttyS1"));
    assert_eq!(vsock.socket_path().as_deref(), Some("/tmp/vsock.sock"));
    assert_eq!(
        goldfish.socket_path().as_deref(),
        Some("/tmp/goldfish.sock")
    );
    assert_eq!(complaint(serial.check()), None);
    assert_eq!(complaint(vsock.check()), None);
    assert_eq!(complaint(goldfish.check()), None);
}

#[test]
fn a_system_map_names_the_symbols_on_its_lines() {
    let _serial = serial_guard();
    let map = LinuxSystemMap::from_bytes(SYSTEM_MAP.as_bytes()).expect("the map should parse");

    assert_eq!(map.try_find_symbol("_text"), Some(0xffff_ffff_8100_0000));
    assert_eq!(map.try_find_symbol("helper"), Some(0xffff_ffff_8100_0100));
    assert_eq!(
        map.try_find_symbol("some_data"),
        Some(0xffff_ffff_8200_0000)
    );
    assert_eq!(map.try_find_symbol("symbol"), None);
    assert_eq!(map.try_find_symbol("hel\0per"), None);
    assert!(map.has_symbol("helper"));
    assert!(!map.has_symbol("no_such_symbol"));
    assert!(!map.has_symbol("hel\0per"));
}

#[test]
fn a_system_map_is_split_into_lines_whichever_way_they_end() {
    let _serial = serial_guard();
    let with_crlf = SYSTEM_MAP.replace('\n', "\r\n");
    let without_a_last_line_ending = SYSTEM_MAP.trim_end();

    for text in [SYSTEM_MAP, &with_crlf, without_a_last_line_ending] {
        let map = LinuxSystemMap::from_bytes(text.as_bytes()).unwrap();

        assert_eq!(
            ["_text", "helper", "some_data"].map(|name| map.try_find_symbol(name)),
            [
                Some(0xffff_ffff_8100_0000),
                Some(0xffff_ffff_8100_0100),
                Some(0xffff_ffff_8200_0000)
            ],
            "{text:?}"
        );
    }
}

#[test]
fn a_system_map_is_read_no_further_than_its_bytes() {
    let _serial = serial_guard();
    // The symbol after the map's bytes is in the buffer, but not in what is passed.
    let buffer = "ffffffff81000000 T _text\nffffffff81000100 T beyond\n";
    let map = &buffer.as_bytes()[..25];

    let map = LinuxSystemMap::from_bytes(map).unwrap();

    assert!(map.has_symbol("_text"));
    assert!(!map.has_symbol("beyond"));
}

#[test]
fn a_system_map_can_be_read_from_a_file() {
    let _serial = serial_guard();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("System.map");
    std::fs::write(&path, SYSTEM_MAP).unwrap();

    let map = LinuxSystemMap::open(path.to_str().unwrap()).expect("the map should be readable");

    assert_eq!(map.try_find_symbol("helper"), Some(0xffff_ffff_8100_0100));
}

#[test]
fn a_map_with_no_symbols_is_not_a_system_map() {
    let _serial = serial_guard();

    let message = read_failure(LinuxSystemMap::from_bytes(b"nothing to see here\n"));

    assert!(message.contains("no symbols"), "{message}");
}

#[test]
fn kernels_that_are_not_there_cannot_be_read() {
    let _serial = serial_guard();
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("missing");
    let missing = missing.to_str().unwrap();

    assert!(!read_failure(LinuxSystemMap::open(missing)).is_empty());
    assert!(!read_failure(LinuxKernelImage::open(missing)).is_empty());
    assert!(!read_failure(XnuKernelcache::open(missing)).is_empty());
    assert!(matches!(
        LinuxSystemMap::open("interior\0nul"),
        Err(Error::CStringFailed)
    ));
}

#[test]
fn bytes_without_kallsyms_tables_are_not_a_kernel_image() {
    let _serial = serial_guard();

    let message = read_failure(LinuxKernelImage::from_bytes(&[0x5a; 4096]));

    assert!(!message.is_empty());
}

#[test]
fn a_linux_kernel_config_needs_its_kernel() {
    let _serial = serial_guard();
    let image = BareboneLinuxKernelConfig::new();
    let without_kernel = (image.kernel().is_some(), complaint(image.check()));

    let map = LinuxSystemMap::from_bytes(SYSTEM_MAP.as_bytes()).unwrap();
    image.set_kernel(&map);
    drop(map);

    assert_eq!(without_kernel.0, false);
    assert!(
        without_kernel
            .1
            .as_deref()
            .is_some_and(|message| message.contains("image.kernel")),
        "{without_kernel:?}"
    );
    assert_eq!(complaint(image.check()), None);
    let kernel = image.kernel().expect("the kernel that was set");
    assert_eq!(
        kernel.try_find_symbol("helper"),
        Some(0xffff_ffff_8100_0100),
        "the config keeps the kernel alive"
    );
}

#[test]
fn an_xnu_kernelcache_config_needs_its_kernelcache() {
    let _serial = serial_guard();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("kernelcache");
    std::fs::write(&path, b"any bytes: they are not looked at yet").unwrap();
    let image = BareboneXnuKernelcacheConfig::new();
    let without_kernelcache = (image.kernelcache().is_some(), complaint(image.check()));

    image.set_kernelcache(&XnuKernelcache::from_bytes(b"held as it arrived"));
    let from_bytes = (image.kernelcache().is_some(), complaint(image.check()));
    image.set_kernelcache(&XnuKernelcache::open(path.to_str().unwrap()).unwrap());

    assert_eq!(without_kernelcache.0, false);
    assert!(
        without_kernelcache
            .1
            .as_deref()
            .is_some_and(|message| message.contains("image.kernelcache")),
        "{without_kernelcache:?}"
    );
    assert_eq!(from_bytes, (true, None));
    assert_eq!(complaint(image.check()), None);
}

#[test]
fn a_config_checks_what_it_is_given() {
    let _serial = serial_guard();
    let config = BareboneConfig::new();
    let by_default = complaint(config.check());

    let connection = BareboneConnectionConfig::new();
    connection.set_flavor(BareboneStubFlavor::Vz);
    config.set_connection(&connection);
    let with_a_bad_connection = complaint(config.check());
    connection.set_pid(1);
    let with_a_good_connection = complaint(config.check());

    config.set_linux_kernel(&BareboneLinuxKernelConfig::new());
    let with_a_linux_kernel_unset = complaint(config.check());
    config.set_xnu_kernelcache(&BareboneXnuKernelcacheConfig::new());
    let with_a_kernelcache_unset = complaint(config.check());

    assert_eq!(by_default, None);
    assert!(
        with_a_bad_connection
            .as_deref()
            .is_some_and(|message| message.contains("connection.pid")),
        "{with_a_bad_connection:?}"
    );
    assert_eq!(with_a_good_connection, None);
    assert!(
        with_a_linux_kernel_unset
            .as_deref()
            .is_some_and(|message| message.contains("image.kernel")),
        "{with_a_linux_kernel_unset:?}"
    );
    assert!(
        with_a_kernelcache_unset
            .as_deref()
            .is_some_and(|message| message.contains("image.kernelcache")),
        "{with_a_kernelcache_unset:?}"
    );
}
