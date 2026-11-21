//! The script message and RPC plumbing: who receives a message, which call a
//! reply belongs to, and what a call does when no reply can come.
//!
//! Each test attaches to its own process (pid 0). A test that would hang runs
//! its work on a thread of its own and fails when that thread does not finish
//! in time, so a regression shows as a failure instead of a stuck test run.

use frida::{DeviceManager, Error, Frida, Message, ScriptHandler, ScriptOption};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });
static FRIDA_SERIAL: Mutex<()> = Mutex::new(());

fn serial_guard() -> MutexGuard<'static, ()> {
    FRIDA_SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

/// Runs `work` on a thread of its own and returns what it returns, failing the
/// test when it has not finished within `secs` seconds.
fn within<T: Send + 'static>(secs: u64, work: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let _ = tx.send(work());
    });
    match rx.recv_timeout(Duration::from_secs(secs)) {
        Ok(value) => value,
        Err(RecvTimeoutError::Timeout) => panic!("did not finish within {secs}s: it hangs"),
        Err(RecvTimeoutError::Disconnected) => panic!("the work panicked"),
    }
}

/// Installs a handler on a script before it is loaded.
type Install = Box<dyn FnOnce(&mut frida::Script)>;

/// Attaches to this process, creates and loads `source`, and gives the script
/// to `work`. `handler` is installed before the script is loaded, if given.
fn with_script<T>(
    source: &str,
    handler: Option<Install>,
    work: impl FnOnce(&mut frida::Script) -> T,
) -> T {
    let dm = DeviceManager::obtain(&FRIDA);
    let device = dm.get_local_device().expect("local device");
    let session = device.attach(0).expect("attach to self");
    let mut opts = ScriptOption::new();
    let mut script = session.create_script(source, &mut opts).expect("script");
    if let Some(install) = handler {
        install(&mut script);
    }
    script.load().expect("load");
    let result = work(&mut script);
    drop(script);
    let _ = session.detach();
    result
}

struct NoopHandler;

impl ScriptHandler for NoopHandler {
    fn on_message(&mut self, _message: Message, _data: Option<Vec<u8>>) {}
}

struct CountingHandler {
    count: Arc<AtomicUsize>,
}

impl ScriptHandler for CountingHandler {
    fn on_message(&mut self, message: Message, _data: Option<Vec<u8>>) {
        if matches!(message, Message::Send(_)) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }
}

fn wait_for(deadline: Duration, done: impl Fn() -> bool) {
    let until = Instant::now() + deadline;
    while Instant::now() < until && !done() {
        std::thread::sleep(Duration::from_millis(10));
    }
}

const ADD_AND_GREET: &str = r#"
    rpc.exports = {
        add: function (a, b) { return a + b; },
        greet: function (name) { return 'hello ' + name; },
    };
"#;

#[test]
fn rpc_works_without_a_message_handler() {
    let _serial = serial_guard();
    let sum = within(20, || {
        with_script(ADD_AND_GREET, None, |script| {
            script.exports.call("add", Some(json!([2, 3]))).ok()
        })
    });
    assert_eq!(sum, Some(Some(json!(5))));
}

#[test]
fn a_second_handle_message_does_not_deliver_messages_twice() {
    let _serial = serial_guard();
    let count = Arc::new(AtomicUsize::new(0));
    let first = Arc::new(AtomicUsize::new(0));
    let (count_c, first_c) = (count.clone(), first.clone());
    within(20, move || {
        with_script(
            "recv('go', function () { send('once'); });",
            Some(Box::new(move |script| {
                script
                    .handle_message(CountingHandler { count: first_c })
                    .unwrap();
                script
                    .handle_message(CountingHandler { count: count_c })
                    .unwrap();
            })),
            |script| {
                script.post(r#"{"type":"go"}"#, None).unwrap();
                std::thread::sleep(Duration::from_millis(500));
            },
        )
    });
    assert_eq!(count.load(Ordering::SeqCst), 1, "delivered once, not twice");
    assert_eq!(
        first.load(Ordering::SeqCst),
        0,
        "the replaced handler is gone"
    );
}

#[test]
fn a_second_handle_message_does_not_mix_up_rpc_replies() {
    let _serial = serial_guard();
    let (sum, hi) = within(20, || {
        with_script(
            ADD_AND_GREET,
            Some(Box::new(|script| {
                script.handle_message(NoopHandler).unwrap();
                script.handle_message(NoopHandler).unwrap();
            })),
            |script| {
                let sum = script.exports.call("add", Some(json!([2, 3]))).ok();
                let hi = script.exports.call("greet", Some(json!(["you"]))).ok();
                (sum, hi)
            },
        )
    });
    assert_eq!(sum, Some(Some(json!(5))));
    assert_eq!(hi, Some(Some(json!("hello you"))));
}

#[test]
fn a_reply_for_another_request_is_not_taken_as_this_calls() {
    let _serial = serial_guard();
    // The script sends something shaped like a reply for a request that was
    // never made, before any call is made.
    let source = format!("{ADD_AND_GREET}\nsend(['frida:rpc', 424242, 'ok', 'not yours']);");
    let sum = within(20, move || {
        with_script(
            &source,
            Some(Box::new(|script| {
                script.handle_message(NoopHandler).unwrap()
            })),
            |script| {
                std::thread::sleep(Duration::from_millis(300));
                script.exports.call("add", Some(json!([2, 3]))).ok()
            },
        )
    });
    assert_eq!(sum, Some(Some(json!(5))));
}

#[test]
fn a_call_after_unload_fails_instead_of_waiting_for_ever() {
    let _serial = serial_guard();
    let result = within(20, || {
        with_script(
            ADD_AND_GREET,
            Some(Box::new(|script| {
                script.handle_message(NoopHandler).unwrap()
            })),
            |script| {
                script.unload().expect("unload");
                let call = script.exports.call("add", Some(json!([2, 3])));
                let list = script.list_exports();
                (format!("{call:?}"), format!("{list:?}"))
            },
        )
    });
    assert!(result.0.starts_with("Err("), "call: {}", result.0);
    assert!(result.1.starts_with("Err("), "list_exports: {}", result.1);
}

#[test]
fn a_call_pending_when_the_session_detaches_fails() {
    let _serial = serial_guard();
    let result = within(20, || {
        let dm = DeviceManager::obtain(&FRIDA);
        let device = dm.get_local_device().expect("local device");
        let session = device.attach(0).expect("attach to self");
        let mut opts = ScriptOption::new();
        // `never` never settles, so its reply can only be the script going away.
        let mut script = session
            .create_script(
                "rpc.exports = { never: function () { return new Promise(function () {}); } };",
                &mut opts,
            )
            .expect("script");
        script.load().expect("load");
        let session_ptr = &session as *const frida::Session as usize;
        let detacher = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            // SAFETY: the session is alive until this thread is joined below.
            let session = unsafe { &*(session_ptr as *const frida::Session) };
            let _ = session.detach();
        });
        let call = script.exports.call("never", None);
        detacher.join().unwrap();
        format!("{call:?}")
    });
    assert!(result.starts_with("Err("), "call: {result}");
}

#[test]
fn a_function_name_is_escaped_into_the_request() {
    let _serial = serial_guard();
    let (weird, missing) = within(20, || {
        with_script(
            r#"rpc.exports = { 'we"ird\\name': function () { return 42; } };"#,
            Some(Box::new(|script| {
                script.handle_message(NoopHandler).unwrap()
            })),
            |script| {
                let weird = script.exports.call(r#"we"ird\name"#, None).ok();
                let missing = script.exports.call(r#"no"such"#, None);
                (weird, format!("{missing:?}"))
            },
        )
    });
    assert_eq!(weird, Some(Some(json!(42))));
    assert!(missing.contains("RpcJsError"), "missing method: {missing}");
}

#[test]
fn a_failing_list_is_an_error_not_an_empty_list() {
    let _serial = serial_guard();
    // gumjs itself never answers `list` with an error: when listing throws it
    // sends no reply. The script stands in for an agent that does answer, by
    // replying to the request itself as it is parsed, before listing throws.
    let listed = within(20, || {
        with_script(
            r#"rpc.exports = new Proxy({}, {
                ownKeys: function () { throw new Error('no listing'); },
            });
            const realParse = JSON.parse;
            JSON.parse = function (text, reviver) {
                const value = realParse(text, reviver);
                if (Array.isArray(value) && value[0] === 'frida:rpc' && value[2] === 'list')
                    send(['frida:rpc', value[1], 'error', 'listing refused']);
                return value;
            };"#,
            Some(Box::new(|script| {
                script.handle_message(NoopHandler).unwrap()
            })),
            |script| format!("{:?}", script.list_exports()),
        )
    });
    assert!(
        listed.contains("RpcJsError") && listed.contains("listing refused"),
        "list_exports: {listed}"
    );
}

#[test]
fn arguments_that_are_not_an_array_are_the_scripts_error() {
    // Pins the verdict that this entry is not a defect: gumjs spreads the
    // arguments inside its `try`, so a non-array is answered with an error.
    let _serial = serial_guard();
    let result = within(20, || {
        with_script(
            ADD_AND_GREET,
            Some(Box::new(|script| {
                script.handle_message(NoopHandler).unwrap()
            })),
            |script| format!("{:?}", script.exports.call("add", Some(json!(5)))),
        )
    });
    assert!(result.contains("RpcJsError"), "call: {result}");
}

struct DropFlagHandler {
    count: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
    seen: Vec<u64>,
}

impl ScriptHandler for DropFlagHandler {
    fn on_message(&mut self, _message: Message, _data: Option<Vec<u8>>) {
        assert!(
            !self.dropped.load(Ordering::SeqCst),
            "a dropped handler was called"
        );
        self.seen.push(0);
        self.count.fetch_add(1, Ordering::SeqCst);
    }
}

impl Drop for DropFlagHandler {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[test]
fn a_message_after_the_script_is_dropped_does_not_reach_the_freed_handler() {
    let _serial = serial_guard();
    let count = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let (count_c, dropped_c) = (count.clone(), dropped.clone());
    within(20, move || {
        let dm = DeviceManager::obtain(&FRIDA);
        let device = dm.get_local_device().expect("local device");
        let session = device.attach(0).expect("attach to self");
        let mut opts = ScriptOption::new();
        let mut script = session
            .create_script(
                "setTimeout(function () { for (var i = 0; i < 50; i++) send(i); }, 300);",
                &mut opts,
            )
            .expect("script");
        script
            .handle_message(DropFlagHandler {
                count: count_c,
                dropped: dropped_c,
                seen: Vec::new(),
            })
            .unwrap();
        script.load().expect("load");
        // The session keeps the script running after this.
        drop(script);
        std::thread::sleep(Duration::from_millis(1000));
        let _ = session.detach();
    });
    assert!(dropped.load(Ordering::SeqCst), "the handler was dropped");
    assert_eq!(count.load(Ordering::SeqCst), 0, "no message after the drop");
}

#[test]
fn swapped_exports_cannot_outlive_their_script() {
    let _serial = serial_guard();
    let result = within(20, || {
        let dm = DeviceManager::obtain(&FRIDA);
        let device = dm.get_local_device().expect("local device");
        let session = device.attach(0).expect("attach to self");
        let mut opts = ScriptOption::new();
        let mut first = session
            .create_script(ADD_AND_GREET, &mut opts)
            .expect("script");
        let mut second = session
            .create_script(ADD_AND_GREET, &mut opts)
            .expect("script");
        first.handle_message(NoopHandler).unwrap();
        second.handle_message(NoopHandler).unwrap();
        first.load().expect("load");
        second.load().expect("load");
        std::mem::swap(&mut first.exports, &mut second.exports);
        // The session lets go of a script once it is unloaded, so dropping
        // it drops the last reference frida itself holds.
        second.unload().expect("unload");
        drop(second);
        std::thread::sleep(Duration::from_millis(200));
        let call = first.exports.call("add", Some(json!([2, 3])));
        let result = format!("{call:?}");
        drop(first);
        let _ = session.detach();
        result
    });
    assert!(result.starts_with("Err("), "call: {result}");
}

struct BusyHandler {
    seen: Vec<Value>,
    total: Arc<AtomicUsize>,
}

impl ScriptHandler for BusyHandler {
    fn on_message(&mut self, message: Message, _data: Option<Vec<u8>>) {
        if let Message::Send(send) = message {
            self.seen.push(send.payload);
            if self.seen.len() > 64 {
                self.seen.clear();
            }
            self.total.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// A stress loop rather than a proof: the handler is replaced, and RPC calls
/// are made, while frida's thread delivers a stream of messages to it.
#[test]
fn replacing_the_handler_while_messages_arrive() {
    let _serial = serial_guard();
    let total = Arc::new(AtomicUsize::new(0));
    let total_c = total.clone();
    let sums = within(120, move || {
        with_script(
            &format!(
                "{ADD_AND_GREET}\nrecv('go', function () {{ for (var i = 0; i < 20000; i++) send({{ i: i, pad: 'x'.repeat(64) }}); }});"
            ),
            None,
            |script| {
                script
                    .handle_message(BusyHandler {
                        seen: Vec::new(),
                        total: total_c.clone(),
                    })
                    .unwrap();
                script.post(r#"{"type":"go"}"#, None).unwrap();
                let mut sums = Vec::new();
                for round in 0..3000 {
                    script
                        .handle_message(BusyHandler {
                            seen: Vec::with_capacity(8),
                            total: total_c.clone(),
                        })
                        .unwrap();
                    if round % 100 == 0 {
                        sums.push(script.exports.call("add", Some(json!([round, 1]))).ok());
                    }
                }
                wait_for(Duration::from_secs(20), || {
                    total_c.load(Ordering::SeqCst) >= 20000
                });
                sums
            },
        )
    });
    for (n, sum) in sums.iter().enumerate() {
        assert_eq!(sum, &Some(Some(json!(n * 100 + 1))), "call {n}");
    }
    assert_eq!(
        total.load(Ordering::SeqCst),
        20000,
        "every message delivered once"
    );
}

#[test]
fn errors_say_what_failed() {
    // Not a defect of its own: pins that a destroyed script's error is the
    // RPC error variant, which callers already match on.
    let _serial = serial_guard();
    let err = within(20, || {
        with_script(ADD_AND_GREET, None, |script| {
            script.unload().expect("unload");
            match script.exports.call("add", None) {
                Err(Error::RpcJsError { message }) => message,
                other => format!("unexpected: {other:?}"),
            }
        })
    });
    assert!(err.contains("destroyed"), "{err}");
}
