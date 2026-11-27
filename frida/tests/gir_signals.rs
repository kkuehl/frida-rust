/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Tests of `frida::gir`'s signals, script messages and RPC, attaching to this test's own
//! process (pid 0) on the local device. No other device is needed.

// The helpers of these tests fail the test by panicking, as the tests themselves may
// (clippy.toml allows that in a test, but not in a helper outside one).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use frida::{
    Cancellable, DeviceManager, ErrorKind, FileMonitor, LogLevel, Message, Owned, Process, Script,
    Session, SessionDetachReason, SignalHandler,
};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Attaching to this process from two tests at once is not something to test by accident.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

const WAIT: Duration = Duration::from_secs(10);

/// Counts how many times it is dropped: what a handler captures.
struct DropProbe(Arc<AtomicUsize>);

impl Drop for DropProbe {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The device manager every test attaches through, as a program has one for its whole
/// life. On Android each manager that attaches to its own process loads another copy of
/// frida's agent, whose thread-local storage keys are never returned, and the process
/// runs out of them after a dozen.
static MANAGER: LazyLock<Owned<DeviceManager>> =
    LazyLock::new(|| DeviceManager::new().expect("a device manager"));

struct Attached {
    session: Owned<Session>,
}

impl Attached {
    fn new() -> Self {
        let device = MANAGER.get_local_device().expect("the local device");
        let session = device
            .attach(0, None, None)
            .expect("attach to this process");
        Self { session }
    }

    fn script(&self, source: &str) -> Owned<Script> {
        self.session
            .create_script(source, None, None)
            .expect("create the script")
    }

    fn close(self) {
        if !self.session.is_detached() {
            self.session.detach(None).expect("detach");
        } else {
            drop(self.session.keep());
        }
    }
}

/// Connects a handler that forwards every parsed message to a channel.
/// A parsed message and its binary data, as a test receives them.
type Received = (Message, Option<Vec<u8>>);

fn messages(script: &Script) -> (SignalHandler, Receiver<Received>) {
    let (sender, receiver) = channel();
    let handler = script.on_message(move |message, data| {
        let _ = sender.send((message, data.map(<[u8]>::to_vec)));
    });
    (handler, receiver)
}

#[test]
fn the_types_signals_hand_out_can_cross_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Session>();
    assert_send_sync::<Owned<Session>>();
    assert_send_sync::<Script>();
    assert_send_sync::<Owned<Script>>();
    assert_send_sync::<Process>();
    assert_send_sync::<SignalHandler>();
}

#[test]
fn sent_messages_arrive_typed_with_their_payload() {
    let _serial = serial();
    let attached = Attached::new();
    let script = attached.script(
        r#"
        send({ greeting: "hello", n: 42 });
        send("with data", new Uint8Array([0, 1, 2, 255]).buffer);
        console.warn("careful");
        "#,
    );
    let (handler, receiver) = messages(&script);
    script.load(None).expect("load");

    let (first, data) = receiver.recv_timeout(WAIT).expect("the first message");
    match first {
        Message::Send(send) => assert_eq!(send.payload, json!({"greeting": "hello", "n": 42})),
        other => panic!("expected a send, got {other:?}"),
    }
    assert_eq!(data, None, "the first send has no binary payload");

    let (second, data) = receiver.recv_timeout(WAIT).expect("the second message");
    match second {
        Message::Send(send) => assert_eq!(send.payload, json!("with data")),
        other => panic!("expected a send, got {other:?}"),
    }
    assert_eq!(data.as_deref(), Some(&[0u8, 1, 2, 255][..]));

    let (third, _) = receiver.recv_timeout(WAIT).expect("the log message");
    match third {
        Message::Log(log) => {
            assert_eq!(log.level, LogLevel::Warning);
            assert_eq!(log.payload, "careful");
        }
        other => panic!("expected a log, got {other:?}"),
    }

    assert!(handler.disconnect());
    script.unload(None).expect("unload");
    attached.close();
}

#[test]
fn an_uncaught_exception_arrives_as_a_typed_error() {
    let _serial = serial();
    let attached = Attached::new();
    let script = attached.script("setTimeout(() => { throw new Error('it broke'); }, 0);");
    let (_handler, receiver) = messages(&script);
    script.load(None).expect("load");

    let (message, data) = receiver.recv_timeout(WAIT).expect("the error message");
    match message {
        Message::Error(error) => {
            assert!(error.description.contains("it broke"), "{error:?}");
            assert!(error.stack.is_some(), "{error:?}");
        }
        other => panic!("expected an error, got {other:?}"),
    }
    assert_eq!(data, None);
    script.unload(None).expect("unload");
    attached.close();
}

#[test]
fn a_posted_message_comes_back() {
    let _serial = serial();
    let attached = Attached::new();
    let script = attached.script(
        r#"
        function onMessage(message, data) {
            send({ echo: message, size: data === null ? -1 : data.byteLength }, data);
            recv(onMessage);
        }
        recv(onMessage);
        "#,
    );
    let (_handler, receiver) = messages(&script);
    script.load(None).expect("load");

    script
        .post_json(&json!({"n": 1, "text": "a\u{0}b"}), None)
        .unwrap();
    let (message, data) = receiver.recv_timeout(WAIT).expect("the echo");
    match message {
        Message::Send(send) => {
            assert_eq!(
                send.payload,
                json!({"echo": {"n": 1, "text": "a\u{0}b"}, "size": -1})
            )
        }
        other => panic!("expected a send, got {other:?}"),
    }
    assert_eq!(data, None);

    script.post(r#"{"n":2}"#, Some(&[9, 8, 7])).unwrap();
    // A NUL byte in the text cannot reach C: an error, not a panic.
    let error = script.post("{\"n\":\u{0}}", None).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    let (message, data) = receiver.recv_timeout(WAIT).expect("the echo with data");
    match message {
        Message::Send(send) => assert_eq!(send.payload, json!({"echo": {"n": 2}, "size": 3})),
        other => panic!("expected a send, got {other:?}"),
    }
    assert_eq!(data.as_deref(), Some(&[9u8, 8, 7][..]));

    script.unload(None).expect("unload");
    attached.close();
}

#[test]
fn detaching_emits_detached_with_its_reason() {
    let _serial = serial();
    let attached = Attached::new();
    let (sender, receiver) = channel();
    let _handler = attached.session.connect_detached(move |reason, crash| {
        let _ = sender.send((reason, crash.is_some()));
    });
    attached.session.handle().detach(None).expect("detach");
    let (reason, crashed) = receiver.recv_timeout(WAIT).expect("the detached signal");
    assert_eq!(reason, SessionDetachReason::ApplicationRequested);
    assert!(!crashed);
    assert!(
        receiver.recv_timeout(Duration::from_millis(200)).is_err(),
        "detached is emitted once"
    );
    attached.close();
}

#[test]
fn disconnecting_stops_deliveries_and_frees_the_closure_once() {
    let _serial = serial();
    let attached = Attached::new();
    let script = attached.script(
        r#"
        function onMessage(message) { send(message); recv(onMessage); }
        recv(onMessage);
        "#,
    );
    let drops = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let probe = DropProbe(drops.clone());
    let counted = calls.clone();
    let handler = script.connect_message(move |_, _| {
        let _keep = &probe;
        counted.fetch_add(1, Ordering::SeqCst);
    });
    // A second handler, never disconnected, tells when a message has been delivered.
    let (_witness, receiver) = messages(&script);
    script.load(None).expect("load");

    script.post_json(&json!(1), None).unwrap();
    receiver.recv_timeout(WAIT).expect("the first echo");
    wait_for("the first delivery", || calls.load(Ordering::SeqCst) == 1);
    assert_eq!(drops.load(Ordering::SeqCst), 0, "not freed while connected");

    assert!(handler.disconnect(), "it was connected");
    wait_for("the closure to be freed", || {
        drops.load(Ordering::SeqCst) == 1
    });

    script.post_json(&json!(2), None).unwrap();
    receiver.recv_timeout(WAIT).expect("the second echo");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "no delivery after disconnect"
    );

    script.unload(None).expect("unload");
    attached.close();
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(drops.load(Ordering::SeqCst), 1, "freed exactly once");
}

#[test]
fn a_closure_left_connected_is_freed_once_when_its_object_goes() {
    let drops = Arc::new(AtomicUsize::new(0));
    let monitor = FileMonitor::new(&std::env::temp_dir()).unwrap().keep();
    let probe = DropProbe(drops.clone());
    let handler = monitor.connect_change(move |_, _, _| {
        let _keep = &probe;
    });
    assert!(handler.is_connected());
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(drops.load(Ordering::SeqCst), 0, "alive while the object is");

    // The guard outlives the object: what it would disconnect is gone with it.
    drop(monitor);
    wait_for("the closure to be freed with its object", || {
        drops.load(Ordering::SeqCst) == 1
    });
    assert!(!handler.is_connected());
    assert!(!handler.disconnect(), "nothing left to disconnect");
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(drops.load(Ordering::SeqCst), 1, "freed exactly once");
}

#[test]
fn a_script_handler_left_connected_is_freed_once_when_the_script_goes() {
    let _serial = serial();
    let attached = Attached::new();
    let script = attached.script("send('hi');");
    let drops = Arc::new(AtomicUsize::new(0));
    let probe = DropProbe(drops.clone());
    let (sender, receiver) = channel();
    // Kept, the handler stays connected without its guard.
    script
        .connect_message(move |json, _| {
            let _keep = &probe;
            let _ = sender.send(json.to_string());
        })
        .keep();
    script.load(None).expect("load");
    receiver.recv_timeout(WAIT).expect("the message");
    assert_eq!(drops.load(Ordering::SeqCst), 0);

    script.unload(None).expect("unload");
    attached.close();
    wait_for("the closure to be freed with the script", || {
        drops.load(Ordering::SeqCst) == 1
    });
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(drops.load(Ordering::SeqCst), 1, "freed exactly once");
}

#[test]
fn a_handler_that_panics_does_not_take_the_process_down() {
    let _serial = serial();
    let attached = Attached::new();
    let script = attached.script(
        r#"
        function onMessage(message) { send(message); recv(onMessage); }
        recv(onMessage);
        "#,
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let panicking = script.connect_message(move |_, _| {
        counted.fetch_add(1, Ordering::SeqCst);
        panic!("from a signal handler");
    });
    let (_witness, receiver) = messages(&script);
    script.load(None).expect("load");

    script.post_json(&json!("first"), None).unwrap();
    receiver.recv_timeout(WAIT).expect("the first echo");
    wait_for("the panic", || panicking.has_panicked());

    // The process, frida-core's thread and the other handler carry on; the one that
    // panicked is not run again.
    script.post_json(&json!("second"), None).unwrap();
    let (message, _) = receiver.recv_timeout(WAIT).expect("the second echo");
    assert!(matches!(message, Message::Send(ref s) if s.payload == json!("second")));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(panicking.disconnect());

    script.unload(None).expect("unload");
    attached.close();
}

const RPC_SCRIPT: &str = r#"
rpc.exports = {
    add(a, b) { return a + b; },
    greet(name) { return { hello: name }; },
    nothing() {},
    fail() { throw new Error('export failed'); },
    later(x) { return new Promise(resolve => setTimeout(() => resolve(x * 2), 10)); },
    bytes() { return new Uint8Array([4, 5, 6]).buffer; },
    never() { return new Promise(() => {}); },
};
"#;

#[test]
fn rpc_lists_exports_and_calls_them() {
    let _serial = serial();
    let attached = Attached::new();
    let script = attached.script(RPC_SCRIPT);
    let (_handler, receiver) = messages(&script);
    script.load(None).expect("load");

    let mut exports = script.list_exports(None).expect("list exports");
    exports.sort();
    assert_eq!(
        exports,
        ["add", "bytes", "fail", "greet", "later", "never", "nothing"]
    );

    assert_eq!(
        script
            .call_export("add", &[json!(2), json!(40)], None)
            .expect("add"),
        json!(42)
    );
    assert_eq!(
        script
            .call_export("greet", &[json!("wörld")], None)
            .expect("greet"),
        json!({"hello": "wörld"})
    );
    assert_eq!(
        script.call_export("nothing", &[], None).expect("nothing"),
        Value::Null
    );
    assert_eq!(
        script
            .call_export("later", &[json!(21)], None)
            .expect("later"),
        json!(42)
    );
    let (_, data) = script
        .call_export_with_data("bytes", &[], None)
        .expect("bytes");
    assert_eq!(data.as_deref(), Some(&[4u8, 5, 6][..]));

    // Calls from several threads at once each get their own reply.
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let script: Script = script.handle().clone();
            std::thread::spawn(move || script.call_export("add", &[json!(i), json!(1000)], None))
        })
        .collect();
    for (i, handle) in handles.into_iter().enumerate() {
        assert_eq!(
            handle.join().unwrap().expect("add from a thread"),
            json!(i + 1000)
        );
    }

    assert!(
        receiver.try_recv().is_err(),
        "RPC replies are not handed to on_message"
    );
    script.unload(None).expect("unload");
    attached.close();
}

#[test]
fn an_export_that_throws_is_an_error() {
    let _serial = serial();
    let attached = Attached::new();
    let script = attached.script(RPC_SCRIPT);
    script.load(None).expect("load");

    let error = script.call_export("fail", &[], None).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Rpc);
    assert_eq!(error.message(), "export failed");
    assert!(
        error.stack().is_some_and(|stack| stack.contains("fail")),
        "{error:?}"
    );
    let error = script.call_export("missing", &[], None).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Rpc);
    assert!(error.message().contains("missing"), "{error}");
    // The script is still usable.
    assert_eq!(
        script
            .call_export("add", &[json!(1), json!(2)], None)
            .unwrap(),
        json!(3)
    );
    script.unload(None).expect("unload");
    attached.close();
}

fn assert_destroyed(result: Result<Value, frida::Error>) {
    match result {
        Err(error) => assert_eq!(error.kind(), ErrorKind::InvalidOperation, "{error}"),
        Ok(value) => panic!("expected an InvalidOperation error, got {value}"),
    }
}

#[test]
fn a_call_that_can_never_be_answered_is_an_error_not_a_hang() {
    let _serial = serial();
    let attached = Attached::new();
    let script = attached.script(RPC_SCRIPT);
    script.load(None).expect("load");

    // Waiting when the script is unloaded.
    let waiting = {
        let script: Script = script.handle().clone();
        std::thread::spawn(move || script.call_export("never", &[], None))
    };
    std::thread::sleep(Duration::from_millis(300));
    assert!(!waiting.is_finished(), "the call waits for a reply");
    script.handle().unload(None).expect("unload");
    let deadline = Instant::now() + WAIT;
    while !waiting.is_finished() {
        assert!(
            Instant::now() < deadline,
            "the call still waits after the unload"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_destroyed(waiting.join().unwrap());

    // Made after the unload.
    assert_destroyed(script.call_export("add", &[json!(1), json!(2)], None));
    assert!(script.list_exports(None).is_err());

    // A script that was never used for RPC, destroyed when its session detaches.
    let other = attached.script(RPC_SCRIPT);
    other.load(None).expect("load");
    attached.session.handle().detach(None).expect("detach");
    wait_for("the script to be destroyed", || other.is_destroyed());
    assert_destroyed(other.call_export("add", &[json!(1), json!(2)], None));
    attached.close();
}

#[test]
fn a_cancelled_call_stops_waiting() {
    let _serial = serial();
    let attached = Attached::new();
    let script = attached.script(RPC_SCRIPT);
    script.load(None).expect("load");

    let cancellable = Cancellable::new().unwrap();
    let waiting = {
        let script: Script = script.handle().clone();
        let cancellable = cancellable.clone();
        std::thread::spawn(move || script.call_export("never", &[], Some(&cancellable)))
    };
    std::thread::sleep(Duration::from_millis(200));
    assert!(!waiting.is_finished());
    cancellable.cancel();
    let error = waiting.join().unwrap().unwrap_err();
    assert!(error.is_cancelled(), "{error:?}");
    // Already cancelled: fails at once.
    let error = script
        .call_export("add", &[json!(1), json!(2)], Some(&cancellable))
        .unwrap_err();
    assert!(error.is_cancelled(), "{error:?}");
    // And the script still answers other calls.
    assert_eq!(
        script
            .call_export("add", &[json!(1), json!(2)], None)
            .unwrap(),
        json!(3)
    );
    script.unload(None).expect("unload");
    attached.close();
}

#[test]
fn an_rpc_call_from_a_signal_handler_is_refused() {
    let _serial = serial();
    let attached = Attached::new();
    let script = attached.script(&format!("{RPC_SCRIPT}\nrecv(() => send('go'));"));
    let (sender, receiver) = channel();
    let inner: Script = script.handle().clone();
    let handler = script.connect_message(move |_, _| {
        let _ = sender.send(inner.call_export("add", &[json!(1), json!(2)], None));
    });
    script.load(None).expect("load");
    script.post_json(&json!(null), None).unwrap();
    let error = receiver
        .recv_timeout(WAIT)
        .expect("the handler ran")
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidOperation, "{error}");
    // The handler holds a handle to the script: disconnect it to break the cycle.
    assert!(handler.disconnect());
    script.unload(None).expect("unload");
    attached.close();
}

#[test]
fn processes_are_listed_with_the_scope_asked_for() {
    let _serial = serial();
    let manager = DeviceManager::new().unwrap();
    let device = manager.get_local_device().expect("the local device");
    // On Android frida-core lists processes through a helper inside the calling process,
    // which leaves that process out, so there the process to find is the one that started
    // this test.
    #[cfg(target_os = "android")]
    let known = std::os::unix::process::parent_id();
    #[cfg(not(target_os = "android"))]
    let known = std::process::id();
    let minimal = device
        .enumerate_processes_with_scope(frida::Scope::Minimal, None)
        .expect("processes");
    let full = device
        .enumerate_processes_with_scope(frida::Scope::Full, None)
        .expect("processes with parameters");
    let find = |list: &[Process]| list.iter().find(|p| p.pid() == known).cloned();
    assert!(
        find(&minimal)
            .expect("a process known to be running")
            .parameters()
            .is_empty()
    );
    assert!(
        !find(&full)
            .expect("a process known to be running")
            .parameters()
            .is_empty(),
        "Scope::Full fills the parameters"
    );
    device
        .enumerate_applications_with_scope(frida::Scope::Minimal, None)
        .expect("applications");
    assert_eq!(device.device_type().to_string(), "local");
    manager.close(None).expect("close the manager");
}

const ECHO_SCRIPT: &str = r#"
function onMessage(message) { send(message); recv(onMessage); }
recv(onMessage);
"#;

#[test]
fn dropping_the_guard_disconnects_the_handler() {
    let _serial = serial();
    let attached = Attached::new();
    let script = attached.script(ECHO_SCRIPT);
    let drops = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let probe = DropProbe(drops.clone());
    let counted = calls.clone();
    let guard = script.connect_message(move |_, _| {
        let _keep = &probe;
        counted.fetch_add(1, Ordering::SeqCst);
    });
    let (_witness, receiver) = messages(&script);
    script.load(None).expect("load");
    script.post_json(&json!(1), None).unwrap();
    receiver.recv_timeout(WAIT).expect("the first echo");
    wait_for("the first delivery", || calls.load(Ordering::SeqCst) == 1);

    drop(guard);
    wait_for("the closure to be freed", || {
        drops.load(Ordering::SeqCst) == 1
    });
    script.post_json(&json!(2), None).unwrap();
    receiver.recv_timeout(WAIT).expect("the second echo");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "no delivery after the drop"
    );
    script.unload(None).expect("unload");
    attached.close();
}

#[test]
fn a_handler_may_drop_its_own_guard() {
    let _serial = serial();
    let attached = Attached::new();
    let script = attached.script(ECHO_SCRIPT);
    let slot: Arc<Mutex<Option<SignalHandler>>> = Arc::new(Mutex::new(None));
    let calls = Arc::new(AtomicUsize::new(0));
    let (inner_slot, counted) = (slot.clone(), calls.clone());
    let guard = script.connect_message(move |_, _| {
        counted.fetch_add(1, Ordering::SeqCst);
        // Disconnects from inside its own emission, on frida-core's thread.
        drop(inner_slot.lock().unwrap().take());
    });
    *slot.lock().unwrap() = Some(guard);
    let (_witness, receiver) = messages(&script);
    script.load(None).expect("load");
    for n in 0..3 {
        script.post_json(&json!(n), None).unwrap();
        receiver.recv_timeout(WAIT).expect("an echo");
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "delivered once, then disconnected"
    );
    assert!(slot.lock().unwrap().is_none());
    script.unload(None).expect("unload");
    attached.close();
}

#[test]
fn dropping_an_owner_inside_a_signal_handler_neither_blocks_nor_deadlocks() {
    let _serial = serial();
    let attached = Attached::new();
    let speaker = attached.script(ECHO_SCRIPT);
    let victim = attached.script("1;");
    victim.load(None).expect("load the victim");
    let victim_handle: Script = victim.handle().clone();
    let held = Mutex::new(Some(victim));
    let (sender, receiver) = channel();
    let _guard = speaker.connect_message(move |_, _| {
        // On frida-core's thread: a blocking unload here would run a nested main loop
        // under this handler; dropping the owner queues it instead, and returns at once.
        let started = Instant::now();
        drop(held.lock().unwrap().take());
        let _ = sender.send(started.elapsed());
    });
    speaker.load(None).expect("load");
    speaker.post_json(&json!("go"), None).unwrap();
    let took = receiver.recv_timeout(WAIT).expect("the handler returned");
    assert!(
        took < Duration::from_millis(100),
        "the drop waited for {took:?}"
    );
    wait_for("the victim to be unloaded", || victim_handle.is_destroyed());
    speaker.unload(None).expect("unload");
    attached.close();
}

#[test]
fn an_owner_dropped_while_unwinding_still_releases() {
    let _serial = serial();
    let attached = Attached::new();
    let script = attached.script("1;");
    script.load(None).expect("load");
    let handle: Script = script.handle().clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _owner = script;
        panic!("while the owner is alive");
    }));
    assert!(result.is_err());
    wait_for("the script to be unloaded", || handle.is_destroyed());
    attached.close();
}
