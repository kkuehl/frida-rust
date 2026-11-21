//! A panic in a caller's callback must not unwind into frida's C frames, which
//! aborts the process. Each test makes one callback panic and then checks that
//! the process is still running and the next callback still arrives.

use frida::{
    DeviceManager, Frida, LanguageServer, LanguageServerHandler, Message, ScriptHandler,
    ScriptOption,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::Duration;

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });
static FRIDA_SERIAL: Mutex<()> = Mutex::new(());

fn serial_guard() -> MutexGuard<'static, ()> {
    FRIDA_SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

struct PanicsOnFirst {
    calls: usize,
    tx: Sender<String>,
}

impl ScriptHandler for PanicsOnFirst {
    fn on_message(&mut self, message: Message, _data: Option<Vec<u8>>) {
        self.calls += 1;
        if self.calls == 1 {
            panic!("the handler panics on purpose");
        }
        let _ = self.tx.send(format!("{message:?}"));
    }
}

#[test]
fn a_panic_in_a_script_handler_does_not_abort() {
    let _serial = serial_guard();
    let dm = DeviceManager::obtain(&FRIDA);
    let device = dm.get_local_device().expect("local device");
    let session = device.attach(0).expect("attach to self");
    let mut opts = ScriptOption::new();
    let mut script = session
        .create_script("send('first'); send('second');", &mut opts)
        .expect("script");
    let (tx, rx) = channel();
    script
        .handle_message(PanicsOnFirst { calls: 0, tx })
        .unwrap();
    script.load().expect("load");
    let second = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the message after the panic");
    assert!(second.contains("second"), "{second}");
    drop(script);
    let _ = session.detach();
}

#[test]
fn a_panic_in_a_scheduled_closure_does_not_abort() {
    let _serial = serial_guard();
    let frida = &*FRIDA;
    frida.schedule_on_main(|| panic!("the closure panics on purpose"));
    let (tx, rx) = channel();
    frida.schedule_on_main(move || {
        let _ = tx.send(());
    });
    rx.recv_timeout(Duration::from_secs(5))
        .expect("the closure after the panic ran");
}

struct LspPanicsOnFirst {
    calls: Arc<AtomicUsize>,
    tx: Sender<String>,
}

impl LanguageServerHandler for LspPanicsOnFirst {
    fn on_message(&mut self, json: &str) {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            panic!("the handler panics on purpose");
        }
        let _ = self.tx.send(json.to_string());
    }
}

#[test]
fn a_panic_in_a_language_server_handler_does_not_abort() {
    let _serial = serial_guard();
    let _f = &*FRIDA;
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("entry.ts"), "export const x: number = 1;\n").unwrap();
    let mut server =
        LanguageServer::new(dir.path().to_str().expect("utf-8 path")).expect("language server");
    let calls = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = channel();
    server
        .handle_message(LspPanicsOnFirst {
            calls: calls.clone(),
            tx,
        })
        .unwrap();
    server.start().expect("start");
    let root = format!("file://{}", dir.path().display());
    for id in 1..=2 {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": { "processId": null, "rootUri": root, "capabilities": {} },
        });
        server.post(&request.to_string()).expect("post");
    }
    let reply = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("a message after the panic");
    assert!(!reply.is_empty());
    assert!(calls.load(Ordering::SeqCst) >= 2);
}
