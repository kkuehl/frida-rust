/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! RPC with a script's `rpc.exports`, over its message channel, the way frida-python and
//! frida-node do it.
//!
//! A request is a message posted to the script, `["frida:rpc", id, "call", name, args]` or
//! `["frida:rpc", id, "list"]`. The script answers with `send()`:
//! `["frida:rpc", id, "ok", value]`, with binary data beside it when the export returned
//! an `ArrayBuffer`, or `["frida:rpc", id, "error", message, name, stack, ...]`.
//!
//! Each script gets one [`RpcState`], made on its first request and kept on the
//! script object itself, so that every handle to the script shares it. It connects a
//! `message` handler that takes the replies, and a `destroyed` handler that fails every
//! request still waiting: a reply cannot come from a script that has been unloaded. Both
//! handlers, and the state, are freed when the script is finalized.

use std::collections::HashMap;
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};

use serde_json::Value;

use crate::gir::{Cancellable, Error, ErrorKind, Message, ObjectType, Script};

/// A reply: the value and the binary data beside it, or the error.
pub(crate) type Reply = Result<(Value, Option<Vec<u8>>), Error>;

/// The key the state is kept under on the script object.
const KEY: &std::ffi::CStr = c"frida-rust-rpc-state";

/// Serializes looking the state up and attaching it, so that a script gets one.
static ATTACH: Mutex<()> = Mutex::new(());

pub(crate) struct RpcState {
    inner: Mutex<Inner>,
}

struct Inner {
    next_id: u64,
    pending: HashMap<u64, Sender<Reply>>,
    destroyed: bool,
}

/// Whether `message` is a reply to an RPC request, which the RPC machinery takes.
pub(crate) fn is_reply(message: &Message) -> bool {
    matches!(message, Message::Send(send)
        if send.payload.get(0).and_then(Value::as_str) == Some("frida:rpc"))
}

fn destroyed_error() -> Error {
    Error::invalid_operation("Script is destroyed")
}

/// A reply this cannot make sense of.
pub(crate) fn unexpected_reply() -> Error {
    Error::new(
        ErrorKind::Protocol,
        "the script sent an RPC reply that does not follow the protocol",
    )
}

unsafe extern "C" fn release_state(data: frida_sys::gpointer) {
    // SAFETY: the count `of` gave the script object, given back once, by GLib.
    drop(unsafe { Arc::from_raw(data.cast::<RpcState>()) });
}

impl RpcState {
    /// The script's state, made and connected on first use.
    fn of(script: &Script) -> Arc<RpcState> {
        let _attach = ATTACH
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let object = script.as_object().as_ptr();
        // SAFETY: a live object; the data under KEY is only ever an RpcState this set.
        let existing = unsafe { frida_sys::g_object_get_data(object, KEY.as_ptr()) };
        if !existing.is_null() {
            let existing = existing.cast::<RpcState>().cast_const();
            // SAFETY: the script holds one count of its own, which this does not take over.
            unsafe { Arc::increment_strong_count(existing) };
            // SAFETY: the count just taken.
            return unsafe { Arc::from_raw(existing) };
        }
        let state = Arc::new(RpcState {
            inner: Mutex::new(Inner {
                next_id: 1,
                pending: HashMap::new(),
                destroyed: false,
            }),
        });
        let on_reply = state.clone();
        // Kept connected for the life of the script.
        script
            .connect_message(move |json, data| on_reply.take_reply(json, data))
            .keep();
        let on_destroyed = state.clone();
        script
            .connect_destroyed(move || on_destroyed.fail_all())
            .keep();
        // SAFETY: the script takes one count of the state, given back by release_state when
        // it is finalized.
        unsafe {
            frida_sys::g_object_set_data_full(
                object,
                KEY.as_ptr(),
                Arc::into_raw(state.clone()).cast_mut().cast(),
                Some(release_state),
            )
        };
        state
    }

    /// Hands a reply to the request waiting for it. Anything else is not for us.
    fn take_reply(&self, json: &str, data: Option<&[u8]>) {
        // Cheap test first: every message passes through here.
        if !json.contains("frida:rpc") {
            return;
        }
        let Message::Send(send) = Message::from_json(json) else {
            return;
        };
        let Some(items) = send.payload.as_array() else {
            return;
        };
        if items.first().and_then(Value::as_str) != Some("frida:rpc") {
            return;
        }
        let Some(id) = items.get(1).and_then(Value::as_u64) else {
            return;
        };
        let reply = match items.get(2).and_then(Value::as_str) {
            Some("ok") => Ok((
                items.get(3).cloned().unwrap_or(Value::Null),
                data.map(<[u8]>::to_vec),
            )),
            Some("error") => Err(Error::rpc(
                items
                    .get(3)
                    .and_then(Value::as_str)
                    .unwrap_or("the export failed, and gave no message")
                    .to_string(),
                items.get(5).and_then(Value::as_str).map(str::to_string),
            )),
            _ => Err(unexpected_reply()),
        };
        self.finish(id, reply);
    }

    /// Ends the request `id`, if it is still waiting, with `reply`.
    fn finish(&self, id: u64, reply: Reply) {
        let sender = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .remove(&id);
        if let Some(sender) = sender {
            let _ = sender.send(reply);
        }
    }

    /// Fails every request waiting, and any later one: the script is gone.
    fn fail_all(&self) {
        let pending: Vec<_> = {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            inner.destroyed = true;
            inner.pending.drain().map(|(_, sender)| sender).collect()
        };
        for sender in pending {
            let _ = sender.send(Err(destroyed_error()));
        }
    }
}

/// Takes the request `id` off the waiting list when the call returns, however it returns.
struct PendingGuard<'a>(&'a RpcState, u64);

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.0
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .remove(&self.1);
    }
}

/// What a cancellable's `cancelled` handler needs: which request to end.
struct CancelTarget {
    state: Arc<RpcState>,
    id: u64,
}

unsafe extern "C" fn on_cancelled(
    _cancellable: *mut frida_sys::GCancellable,
    data: frida_sys::gpointer,
) {
    // SAFETY: the target `request` connected, alive until free_cancel_target.
    let target = unsafe { &*data.cast::<CancelTarget>() };
    target.state.finish(target.id, Err(Error::cancelled()));
}

unsafe extern "C" fn free_cancel_target(data: frida_sys::gpointer) {
    // SAFETY: the box `request` made, freed once, by GIO.
    drop(unsafe { Box::from_raw(data.cast::<CancelTarget>()) });
}

/// Posts the request `operation` (what follows the id) to `script` and waits for the reply.
pub(crate) fn request(
    script: &Script,
    operation: Vec<Value>,
    cancellable: Option<&Cancellable>,
) -> Reply {
    // Waiting here would wait for ever: the reply is delivered on this very thread.
    if crate::gir::runtime::on_frida_thread() {
        return Err(Error::invalid_operation(
            "an RPC call cannot wait on frida-core's thread, which delivers the reply",
        ));
    }
    let state = RpcState::of(script);
    let (sender, receiver) = channel();
    let id = {
        let mut inner = state
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // The `destroyed` handler sets the flag; a script destroyed before the state was
        // attached never ran it, so ask the script too.
        if inner.destroyed || script.is_destroyed() {
            return Err(destroyed_error());
        }
        let id = inner.next_id;
        inner.next_id += 1;
        inner.pending.insert(id, sender);
        id
    };
    let _pending = PendingGuard(&state, id);

    // Connected after the request is listed, so that a cancellable cancelled already,
    // whose handler runs at once, finds it.
    let cancel_handler = cancellable.map(|cancellable| {
        let target = Box::into_raw(Box::new(CancelTarget {
            state: state.clone(),
            id,
        }));
        let callback: unsafe extern "C" fn(*mut frida_sys::GCancellable, frida_sys::gpointer) =
            on_cancelled;
        // SAFETY: a live cancellable; GIO owns the target from here, and frees it with
        // free_cancel_target. The callback's type is the `cancelled` signal's.
        let handler = unsafe {
            frida_sys::g_cancellable_connect(
                cancellable.as_raw(),
                Some(std::mem::transmute::<
                    unsafe extern "C" fn(*mut frida_sys::GCancellable, frida_sys::gpointer),
                    unsafe extern "C" fn(),
                >(callback)),
                target.cast(),
                Some(free_cancel_target),
            )
        };
        (cancellable, handler)
    });

    let mut message = vec![Value::from("frida:rpc"), Value::from(id)];
    message.extend(operation);
    // The sender stays listed until a reply, the script's destruction or a cancellation
    // takes it; if the state itself goes, so does the sender. Posting cannot fail on a
    // NUL byte, as serde_json escapes it.
    let reply = match script.post(&Value::Array(message).to_string(), None) {
        Ok(()) => receiver.recv().unwrap_or_else(|_| Err(destroyed_error())),
        Err(error) => Err(error),
    };

    if let Some((cancellable, handler)) = cancel_handler {
        // SAFETY: the handler connected above. This waits for a `cancelled` handler running
        // on another thread, and frees the target.
        unsafe { frida_sys::g_cancellable_disconnect(cancellable.as_raw(), handler) };
    }
    reply
}
