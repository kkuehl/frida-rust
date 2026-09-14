//! End-to-end tests for [`Session`]/[`Script`] wiring: attach, create_script,
//! message pump, `Script::post` payloads, and RPC exports.
//!
//! Every test attaches the test process to itself (pid=0) and immediately
//! detaches — that's the standard frida-rust integration-test pattern and
//! keeps CI portable.

use frida::{DeviceManager, Frida, Message, ScriptHandler, ScriptOption};
use serde_json::{Value, json};
use std::sync::mpsc::{Sender, channel};
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });
static FRIDA_SERIAL: Mutex<()> = Mutex::new(());

fn serial_guard() -> MutexGuard<'static, ()> {
    FRIDA_SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

struct ChannelHandler {
    tx: Sender<(Message, Option<Vec<u8>>)>,
}

impl ScriptHandler for ChannelHandler {
    fn on_message(&mut self, message: Message, data: Option<Vec<u8>>) {
        let _ = self.tx.send((message, data));
    }
}

#[test]
fn session_attach_creates_and_detaches_cleanly() {
    let _serial = serial_guard();
    let dm = DeviceManager::obtain(&FRIDA);
    let device = dm.get_local_device().expect("local device");
    let session = device.attach(0).expect("attach to self");

    assert!(
        !session.is_detached(),
        "freshly-attached session must not be detached"
    );

    session.detach().expect("detach");
    // After detach the session should observably flip. frida-core turns this
    // over asynchronously, so poll briefly.
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline && !session.is_detached() {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        session.is_detached(),
        "session should report detached after Session::detach"
    );
}

#[test]
fn script_load_send_and_receive_roundtrip() {
    let _serial = serial_guard();
    let dm = DeviceManager::obtain(&FRIDA);
    let device = dm.get_local_device().expect("local device");
    let session = device.attach(0).expect("attach to self");

    // Script listens on `recv()` and echoes back through `send()`. This
    // exercises: create_script, handle_message wiring, load, post, drain.
    let source = r#"
        recv('ping', function (msg) {
            send({ echo: msg.payload });
        });
    "#;

    let mut opts = ScriptOption::new();
    let mut script = session
        .create_script(source, &mut opts)
        .expect("create_script");

    let (tx, rx) = channel::<(Message, Option<Vec<u8>>)>();
    script
        .handle_message(ChannelHandler { tx })
        .expect("handle_message");
    script.load().expect("load");

    let request = json!({ "type": "ping", "payload": "hi from rust" }).to_string();
    script.post(&request, None).expect("post");

    // Wait for the echo — 3s is generous even on the slowest CI runner.
    let (msg, _data) = rx
        .recv_timeout(Duration::from_secs(3))
        .expect("script must respond within 3s");

    match msg {
        Message::Send(s) => {
            let echo = s.payload.get("echo").expect("echo key present in payload");
            assert_eq!(
                echo,
                &Value::String("hi from rust".to_string()),
                "script must echo the payload verbatim"
            );
        }
        other => panic!("expected Message::Send, got {other:?}"),
    }

    script.unload().expect("unload");
    session.detach().expect("detach");
}

#[test]
fn script_console_log_surfaces_as_message_log() {
    let _serial = serial_guard();
    let dm = DeviceManager::obtain(&FRIDA);
    let device = dm.get_local_device().expect("local device");
    let session = device.attach(0).expect("attach to self");

    let source = r#"console.log('hello-from-console');"#;

    let mut opts = ScriptOption::new();
    let mut script = session.create_script(source, &mut opts).expect("script");

    let (tx, rx) = channel::<(Message, Option<Vec<u8>>)>();
    script
        .handle_message(ChannelHandler { tx })
        .expect("handle_message");
    script.load().expect("load");

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_log = false;
    while Instant::now() < deadline {
        if let Ok((Message::Log(log), _)) = rx.recv_timeout(Duration::from_millis(100))
            && log.payload.contains("hello-from-console")
        {
            saw_log = true;
            break;
        }
    }
    assert!(
        saw_log,
        "console.log('hello-from-console') should surface as Message::Log"
    );

    script.unload().expect("unload");
    session.detach().expect("detach");
}

#[test]
fn script_rpc_exports_are_callable() {
    let _serial = serial_guard();
    let dm = DeviceManager::obtain(&FRIDA);
    let device = dm.get_local_device().expect("local device");
    let session = device.attach(0).expect("attach to self");

    let source = r#"
        rpc.exports = {
            add: function (a, b) { return a + b; },
            greet: function (name) { return 'hello ' + name; },
        };
    "#;

    let mut opts = ScriptOption::new();
    let mut script = session.create_script(source, &mut opts).expect("script");
    script
        .handle_message(NoopHandler)
        .expect("handle_message");
    script.load().expect("load");

    let mut exports = script.list_exports().expect("list_exports");
    exports.sort();
    assert_eq!(
        exports,
        vec!["add".to_string(), "greet".to_string()],
        "list_exports must return every rpc.exports key"
    );

    let sum = script
        .exports
        .call("add", Some(json!([2, 3])))
        .expect("rpc call add");
    assert_eq!(
        sum,
        Some(Value::Number(5.into())),
        "rpc `add` must return the sum"
    );

    let hi = script
        .exports
        .call("greet", Some(json!(["world"])))
        .expect("rpc call greet");
    assert_eq!(
        hi,
        Some(Value::String("hello world".to_string())),
        "rpc `greet` must return the concatenated string"
    );

    script.unload().expect("unload");
    session.detach().expect("detach");
}

#[test]
fn script_post_carries_binary_data_payload() {
    // frida allows `Script::post` to attach a binary blob that JS receives
    // via the recv() second argument. This is the primary out-of-band data
    // channel — regressions here silently break hooks that stream payloads.
    let _serial = serial_guard();
    let dm = DeviceManager::obtain(&FRIDA);
    let device = dm.get_local_device().expect("local device");
    let session = device.attach(0).expect("attach to self");

    let source = r#"
        recv('withdata', function (msg, data) {
            send({ size: data ? data.byteLength : 0 });
        });
    "#;

    let mut opts = ScriptOption::new();
    let mut script = session.create_script(source, &mut opts).expect("script");

    let (tx, rx) = channel::<(Message, Option<Vec<u8>>)>();
    script
        .handle_message(ChannelHandler { tx })
        .expect("handle_message");
    script.load().expect("load");

    let msg = json!({ "type": "withdata" }).to_string();
    let payload = vec![0u8, 1, 2, 3, 4, 5, 6, 7];
    script.post(&msg, Some(&payload)).expect("post with data");

    let (reply, _) = rx
        .recv_timeout(Duration::from_secs(3))
        .expect("script response");
    match reply {
        Message::Send(s) => {
            let size = s.payload.get("size").and_then(Value::as_u64);
            assert_eq!(size, Some(8), "script must see 8 bytes of payload");
        }
        other => panic!("expected Message::Send, got {other:?}"),
    }

    script.unload().expect("unload");
    session.detach().expect("detach");
}

struct NoopHandler;

impl ScriptHandler for NoopHandler {
    fn on_message(&mut self, _message: Message, _data: Option<Vec<u8>>) {}
}
