/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Unit tests of what integration tests cannot reach: option values built into frida-core
//! objects and read back with frida-core's own getters, and the errors that stand in for
//! what used to panic.

use std::collections::HashMap;
use std::time::Duration;

use crate::Variant;
use crate::gir::marshal;
use crate::gir::{
    ApplicationQueryOptions, BareboneCallArgument, BareboneCallArgumentRole,
    BareboneLinuxKernelConfig, BarebonePhysicalAllocatorConfig, BareboneSocketTransportConfig,
    BareboneTransportConfig, EndpointParameters, ErrorKind, Object, ObjectType, PeerOptions,
    ProcessMatchOptions, ProcessQueryOptions, Realm, Relay, RelayKind, RemoteDeviceOptions,
    ScriptOptions, ScriptRuntime, SessionOptions, SpawnOptions, StaticAuthenticationService, Stdio,
    WatchOptions,
};

/// The string a getter returned, which the object still owns.
fn text(ptr: *const std::os::raw::c_char) -> Option<String> {
    // SAFETY: a getter's transfer-none string, alive while the object is.
    unsafe { marshal::string(ptr, false) }
}

fn ref_count(object: &Object) -> u32 {
    // SAFETY: reading a live object's reference count.
    unsafe { (*object.as_ptr()).ref_count }
}

#[test]
fn session_options_reach_frida_core() {
    let options = SessionOptions::new()
        .realm(Realm::Emulated)
        .persist_timeout(Duration::from_secs(1234))
        .emulated_agent_path("/tmp/agent.so")
        .exit_monitor(false)
        .add_linker_notifier_offset(0x1234)
        .add_linker_notifier_offset(7);
    let object = options.to_object().unwrap();
    let raw = object.as_ptr().cast::<frida_sys::FridaSessionOptions>();
    // SAFETY: a live FridaSessionOptions, and its getters.
    unsafe {
        assert_eq!(
            Realm::from_raw(frida_sys::frida_session_options_get_realm(raw)),
            Realm::Emulated
        );
        assert_eq!(
            frida_sys::frida_session_options_get_persist_timeout(raw),
            1234
        );
        assert_eq!(
            text(frida_sys::frida_session_options_get_emulated_agent_path(
                raw
            ))
            .as_deref(),
            Some("/tmp/agent.so")
        );
        assert_eq!(frida_sys::frida_session_options_get_exit_monitor(raw), 0);
        assert_ne!(
            frida_sys::frida_session_options_get_thread_suspend_monitor(raw),
            0
        );
    }
}

#[test]
fn fields_left_alone_keep_frida_cores_defaults() {
    let default = SessionOptions::default();
    assert!(default.exit_monitor, "the GIR's default");
    assert_eq!(default.persist_timeout, Duration::ZERO);
    assert_eq!(default.realm, None);
    let object = default.to_object().unwrap();
    // SAFETY: a live FridaSessionOptions.
    let realm = unsafe { frida_sys::frida_session_options_get_realm(object.as_ptr().cast()) };
    assert_eq!(
        Realm::from_raw(realm),
        Realm::Native,
        "frida-core's own default"
    );

    let remote = RemoteDeviceOptions::new();
    assert_eq!(remote.keepalive_interval, None, "-1 in the GIR: disabled");
    let object = remote
        .keepalive_interval(Some(Duration::from_secs(42)))
        .to_object()
        .unwrap();
    // SAFETY: a live FridaRemoteDeviceOptions.
    let interval = unsafe {
        frida_sys::frida_remote_device_options_get_keepalive_interval(object.as_ptr().cast())
    };
    assert_eq!(interval, 42);
    let object = RemoteDeviceOptions::new().to_object().unwrap();
    // SAFETY: as above.
    let interval = unsafe {
        frida_sys::frida_remote_device_options_get_keepalive_interval(object.as_ptr().cast())
    };
    assert_eq!(interval, -1);
}

#[test]
fn spawn_options_carry_arrays_environments_and_aux() {
    let options = SpawnOptions::new()
        .argv(["/bin/echo", "hello", "wörld", ""])
        .env([("A", "1"), ("EMPTY", "")])
        .envp(Vec::<(String, String)>::new())
        .cwd("/tmp")
        .stdio(Stdio::Pipe)
        .aux("flag", Variant::Boolean(true));
    let object = options.to_object().unwrap();
    let raw = object.as_ptr().cast::<frida_sys::FridaSpawnOptions>();
    let mut len = 0;
    // SAFETY: a live FridaSpawnOptions; the arrays are transfer none.
    unsafe {
        let argv = marshal::string_array(
            frida_sys::frida_spawn_options_get_argv(raw, &mut len),
            len,
            false,
        );
        assert_eq!(
            argv,
            Some(vec![
                "/bin/echo".into(),
                "hello".into(),
                "wörld".into(),
                String::new()
            ])
        );
        let env = marshal::string_array(
            frida_sys::frida_spawn_options_get_env(raw, &mut len),
            len,
            false,
        );
        assert_eq!(env, Some(vec!["A=1".into(), "EMPTY=".into()]));
        let envp = marshal::string_array(
            frida_sys::frida_spawn_options_get_envp(raw, &mut len),
            len,
            false,
        );
        assert_eq!(envp, Some(vec![]));
        assert_eq!(
            text(frida_sys::frida_spawn_options_get_cwd(raw)).as_deref(),
            Some("/tmp")
        );
        assert_eq!(
            Stdio::from_raw(frida_sys::frida_spawn_options_get_stdio(raw)),
            Stdio::Pipe
        );
        let aux = marshal::vardict(frida_sys::frida_spawn_options_get_aux(raw), false).unwrap();
        assert_eq!(aux.get("flag"), Some(&Variant::Boolean(true)));
    }
    // Unset arrays stay NULL.
    let object = SpawnOptions::new().to_object().unwrap();
    // SAFETY: as above.
    let argv = unsafe { frida_sys::frida_spawn_options_get_argv(object.as_ptr().cast(), &mut len) };
    assert!(argv.is_null());
}

#[test]
fn bytes_and_variant_dictionaries_survive_the_trip() {
    let blob = [0u8, 1, 2, 255, b'a', 0];
    let object = ScriptOptions::new()
        .name("probe")
        .snapshot(blob)
        .runtime(ScriptRuntime::Qjs)
        .to_object()
        .unwrap();
    let raw = object.as_ptr().cast::<frida_sys::FridaScriptOptions>();
    // SAFETY: a live FridaScriptOptions; the bytes are transfer none.
    unsafe {
        assert_eq!(
            marshal::bytes(frida_sys::frida_script_options_get_snapshot(raw), false).as_deref(),
            Some(&blob[..])
        );
        assert_eq!(
            text(frida_sys::frida_script_options_get_name(raw)).as_deref(),
            Some("probe")
        );
    }

    let mut inner = HashMap::new();
    inner.insert("nested".to_string(), Variant::Int64(-7));
    let mut options = SpawnOptions::new();
    options
        .aux
        .insert("map".into(), Variant::Map(inner.clone()));
    options
        .aux
        .insert("maps".into(), Variant::MapList(vec![inner, HashMap::new()]));
    options.aux.insert(
        "list".into(),
        Variant::StringList(vec!["a".into(), "b".into()]),
    );
    options.aux.insert("count".into(), Variant::Int64(1 << 40));
    let object = options.to_object().unwrap();
    // SAFETY: a live FridaSpawnOptions; the table is transfer none.
    let aux = unsafe {
        marshal::vardict(
            frida_sys::frida_spawn_options_get_aux(object.as_ptr().cast()),
            false,
        )
    };
    assert_eq!(aux.as_ref(), Some(&options.aux));
}

#[test]
fn collections_are_added_in_order() {
    let object = ProcessQueryOptions::new()
        .select_pid(7)
        .select_pid(4_000_000_000)
        .to_object()
        .unwrap();
    // SAFETY: a live FridaProcessQueryOptions.
    assert_ne!(
        unsafe { frida_sys::frida_process_query_options_has_selected_pids(object.as_ptr().cast()) },
        0
    );
    let object = ApplicationQueryOptions::new().to_object().unwrap();
    // SAFETY: a live FridaApplicationQueryOptions.
    assert_eq!(
        unsafe {
            frida_sys::frida_application_query_options_has_selected_identifiers(
                object.as_ptr().cast(),
            )
        },
        0
    );
}

#[test]
fn a_value_holds_its_handles_and_the_object_takes_its_own_reference() {
    let relay = Relay::new("192.0.2.1:3478", "user", "pass", RelayKind::TurnTcp).unwrap();
    let relay_object = relay.as_object().clone();
    let before = ref_count(&relay_object);
    let options = PeerOptions::new().add_relay(&relay);
    assert_eq!(options.relays, std::slice::from_ref(&relay));
    let object = options.to_object().unwrap();
    assert!(
        ref_count(&relay_object) > before,
        "the frida-core object keeps its own reference"
    );
    drop(object);
    drop(options);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while ref_count(&relay_object) != before && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(ref_count(&relay_object), before, "and gives it back");
}

#[test]
fn abstract_configs_are_enums_of_their_kinds() {
    let transport: BareboneTransportConfig = BareboneSocketTransportConfig::new()
        .path("/tmp/agent.sock")
        .into();
    let object = transport.to_object().unwrap();
    assert_eq!(object.type_name(), "FridaBareboneSocketTransportConfig");

    let allocator = BarebonePhysicalAllocatorConfig::new();
    let object = crate::gir::BareboneAllocatorConfig::from(allocator)
        .to_object()
        .unwrap();
    assert_eq!(object.type_name(), "FridaBarebonePhysicalAllocatorConfig");

    let image = BareboneLinuxKernelConfig::new().add_symbol("start_kernel", 0xffff_ffff_8100_0000);
    assert_eq!(
        image.symbols,
        [("start_kernel".to_string(), 0xffff_ffff_8100_0000)]
    );
    // An image config without its kernel is not usable, and check says so.
    let error = crate::gir::BareboneImageConfig::from(image)
        .check()
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotSupported, "{error}");
}

#[test]
fn endpoint_parameters_go_through_the_constructor() {
    let service = StaticAuthenticationService::new("secret").unwrap();
    let params = EndpointParameters::new(27042)
        .address("127.0.0.1")
        .auth_service(service.as_ref())
        .asset_root("/srv/www");
    let object = params.to_object().unwrap();
    let raw = object.as_ptr().cast::<frida_sys::FridaEndpointParameters>();
    // SAFETY: a live FridaEndpointParameters.
    unsafe {
        assert_eq!(frida_sys::frida_endpoint_parameters_get_port(raw), 27042);
        assert_eq!(
            text(frida_sys::frida_endpoint_parameters_get_address(raw)).as_deref(),
            Some("127.0.0.1")
        );
        assert!(!frida_sys::frida_endpoint_parameters_get_auth_service(raw).is_null());
    }
    // SAFETY: as above.
    let back = unsafe { EndpointParameters::from_object(raw, "test") }.unwrap();
    assert_eq!(back, params, "it converts back to the same value");
}

#[test]
fn a_nul_byte_is_an_invalid_argument_not_a_panic() {
    let error = marshal::cstring("a\0b").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    assert!(std::error::Error::source(&error).is_some());

    let error = SpawnOptions::new().cwd("/t\0mp").to_object().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    let error = SpawnOptions::new()
        .argv(["ok", "n\0t"])
        .to_object()
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    let error = Relay::new("a\0", "", "", RelayKind::TurnUdp).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);
}

#[test]
fn an_environment_name_with_an_equals_sign_is_an_invalid_argument() {
    for name in ["A=B", ""] {
        let error = SpawnOptions::new()
            .env([(name, "x")])
            .to_object()
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidArgument, "{name:?}");
    }
    assert_eq!(
        marshal::env_pairs(vec!["A=1=2".into(), "BARE".into()]),
        [
            ("A".to_string(), "1=2".to_string()),
            ("BARE".to_string(), String::new())
        ]
    );
}

#[test]
fn an_unsupported_variant_is_an_invalid_argument() {
    let error = SpawnOptions::new()
        .aux("x", Variant::Unsupported("(ii)".into()))
        .to_object()
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    // Inside a map, too, and nothing leaks on the way out.
    let mut map = HashMap::new();
    map.insert("ok".to_string(), Variant::Int64(1));
    map.insert("bad".to_string(), Variant::Unsupported("q".into()));
    assert_eq!(
        marshal::to_gvariant(&Variant::Map(map)).unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
}

#[test]
fn durations_that_do_not_fit_are_invalid_arguments() {
    assert_eq!(marshal::timeout_ms(None).unwrap(), -1);
    assert_eq!(marshal::timeout_ms(Some(Duration::ZERO)).unwrap(), 0);
    assert_eq!(
        marshal::timeout_ms(Some(Duration::from_millis(1500))).unwrap(),
        1500
    );
    assert_eq!(
        marshal::timeout_ms(Some(Duration::from_secs(u64::MAX)))
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidArgument
    );
    let error = SessionOptions::new()
        .persist_timeout(Duration::from_secs(u64::from(u32::MAX) + 1))
        .to_object()
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    let error = ProcessMatchOptions::new()
        .timeout(Some(Duration::from_secs(u64::MAX)))
        .to_object()
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);
}

#[test]
fn a_length_that_does_not_fit_is_an_invalid_argument() {
    assert_eq!(
        marshal::length(usize::MAX).unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
    assert_eq!(marshal::length(3).unwrap(), 3);
}

#[cfg(unix)]
#[test]
fn a_path_that_is_not_utf8_is_an_invalid_argument() {
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    let path = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/\xff"));
    assert_eq!(
        marshal::path(path).unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
    assert_eq!(
        crate::gir::File::for_path(path).unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
}

#[test]
fn a_null_frida_core_promised_against_is_unexpected_not_a_panic() {
    let error = marshal::non_null(None::<()>, "frida_thing_get").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unexpected);
    assert!(error.message().contains("frida_thing_get"));
    // SAFETY: a null list, which the conversion must refuse.
    let error = unsafe {
        crate::gir::generated::device_list_to_vec(std::ptr::null_mut(), false, "frida_x")
    }
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unexpected);
}

#[test]
fn watch_options_carry_their_parents_fields() {
    let options = WatchOptions::new()
        .project_root("/src")
        .add_external("left-pad");
    let object = options.to_object().unwrap();
    // SAFETY: a live FridaCompilerOptions (WatchOptions' parent).
    let root = unsafe {
        text(frida_sys::frida_compiler_options_get_project_root(
            object.as_ptr().cast(),
        ))
    };
    assert_eq!(root.as_deref(), Some("/src"));
}

#[test]
fn a_call_argument_is_a_handle_with_its_values() {
    let argument = BareboneCallArgument::new(BareboneCallArgumentRole::Literal, 0xfeed).unwrap();
    assert_eq!(argument.value(), 0xfeed);
    assert_eq!(argument.role(), BareboneCallArgumentRole::Literal);
}
