/*
 * Copyright © 2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use frida_sys::{
    _FridaScript, _GBytes, _GClosure, FridaScriptOptions, g_bytes_get_data, g_bytes_new,
    g_bytes_unref, gpointer, gsize, gulong,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex, MutexGuard};
use std::{cell::RefCell, marker::PhantomData, rc::Rc};
use std::{
    ffi::{CStr, CString, c_char, c_void},
    ptr::null_mut,
};

use crate::{Error, Result};

/// Represents a Frida message
#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "lowercase")]
pub enum Message {
    /// Message of type "send"
    Send(MessageSend),
    /// Message of type "log"
    Log(MessageLog),
    /// Message of type "error"
    Error(MessageError),
    /// Any other type of message.
    Other(Value),
}

/// Send Message.
#[derive(Deserialize, Debug)]
pub struct MessageSend {
    /// Payload of a Send Message.
    pub payload: Value,
}

/// Log Message.
#[derive(Deserialize, Debug)]
pub struct MessageLog {
    /// Log Level.
    pub level: MessageLogLevel,
    /// Payload of a Message Log.
    pub payload: String,
}

/// Error message.
/// This message is sent when a JavaScript runtime error occurs, such as a misspelled word.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MessageError {
    /// Error description.
    pub description: String,
    /// Stack trace string.
    pub stack: String,
    /// Script file name that failed.
    pub file_name: String,
    /// Line number with the error.
    pub line_number: usize,
    /// Column number with the error.
    pub column_number: usize,
}

/// Represents a Message Log Level Types.
/// Used by `MessageLog._level`
#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum MessageLogLevel {
    /// Indicates an informal message.
    Info,
    /// Represents a debugging message.
    Debug,
    /// Signifies a warning message.
    Warning,
    /// Represents an error message.
    Error,
}

/// Represents a script signal handler.
pub trait ScriptHandler {
    /// Handler called when a message is shared from JavaScript to Rust.
    fn on_message(&mut self, message: Message, data: Option<Vec<u8>>);
}

/// The caller's handler, as the inbox keeps it.
///
/// It is called on frida's thread, and may be dropped there, but
/// [`Script::handle_message`] does not require it to be `Send`. Everything
/// the crate itself shares between the threads is behind a lock; what the
/// handler holds is the caller's to keep safe to use from frida's thread.
struct UserHandler(Box<dyn ScriptHandler>);

// SAFETY: not proven; see `UserHandler`. The inbox only ever reaches the
// handler through its mutex, so the crate makes no unsynchronised access.
unsafe impl Send for UserHandler {}

/// What frida's thread and the caller's share about one script: the
/// caller's handler, and the RPC calls waiting for a reply.
///
/// The signal connections own one reference each, given back when GLib
/// destroys the closure, so the inbox outlives every callback.
struct Inbox {
    handler: Mutex<Option<UserHandler>>,
    rpc: Mutex<RpcState>,
    next_id: AtomicUsize,
}

#[derive(Default)]
struct RpcState {
    /// The calls waiting, by request id.
    waiting: HashMap<usize, Sender<Value>>,
    /// Set once the script is destroyed: no reply can come after that.
    closed: bool,
}

impl Inbox {
    fn new() -> Self {
        Self {
            handler: Mutex::new(None),
            rpc: Mutex::new(RpcState::default()),
            next_id: AtomicUsize::new(1),
        }
    }

    fn rpc(&self) -> MutexGuard<'_, RpcState> {
        self.rpc
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn set_handler(&self, handler: Box<dyn ScriptHandler>) {
        let old = {
            let mut slot = self
                .handler
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            slot.replace(UserHandler(handler))
        };
        // The old handler is dropped outside the lock.
        drop(old);
    }

    /// Hands an RPC reply to the call waiting for it. A reply no call is
    /// waiting for is dropped.
    fn deliver_reply(&self, payload: Value) {
        let Some(id) = payload.get(1).and_then(Value::as_u64) else {
            return;
        };
        let waiter = self.rpc().waiting.remove(&(id as usize));
        if let Some(waiter) = waiter {
            let _ = waiter.send(payload);
        }
    }

    fn deliver(&self, message: Message, data: Option<Vec<u8>>) {
        let mut slot = self
            .handler
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(UserHandler(handler)) = slot.as_mut() {
            // A panic must not unwind into frida's C frames. The default hook
            // has reported it by the time it is caught here.
            let _ = catch_unwind(AssertUnwindSafe(|| handler.on_message(message, data)));
        }
    }

    /// No reply can come any more: wakes every waiting call with an error.
    fn close(&self) {
        let waiting = {
            let mut rpc = self.rpc();
            rpc.closed = true;
            std::mem::take(&mut rpc.waiting)
        };
        drop(waiting);
    }

    /// Posts an RPC request and waits for its reply, or for the script to be
    /// destroyed.
    fn request(&self, script: &ScriptRef, operation: &str, params: Vec<Value>) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut request = vec![json!("frida:rpc"), json!(id), json!(operation)];
        request.extend(params);
        let request =
            CString::new(Value::Array(request).to_string()).map_err(|_| Error::CStringFailed)?;

        let (tx, rx) = channel();
        {
            let mut rpc = self.rpc();
            if rpc.closed {
                return Err(destroyed());
            }
            rpc.waiting.insert(id, tx);
        }
        unsafe { frida_sys::frida_script_post(script.0, request.as_ptr(), null_mut()) };

        // Every sender is dropped when the script is destroyed, which ends
        // the wait.
        rx.recv().map_err(|_| destroyed())
    }
}

fn destroyed() -> Error {
    Error::RpcJsError {
        message: "Script is destroyed".to_string(),
    }
}

/// The reason an RPC reply gives for failing, or a generic one.
fn rpc_failure(payload: &Value) -> Error {
    let message = payload
        .get(3)
        .and_then(Value::as_str)
        .unwrap_or("RPC call failed. Result is not ok and no error message provided.")
        .to_string();
    Error::RpcJsError { message }
}

unsafe fn inbox_from<'i>(user_data: *mut c_void) -> &'i Inbox {
    // SAFETY: `user_data` is the reference the connection owns; GLib calls
    // the destroy notify that gives it back only after the last callback.
    unsafe { &*(user_data as *const Inbox) }
}

unsafe extern "C" fn on_script_message(
    _script: *mut _FridaScript,
    message: *const c_char,
    data: *mut _GBytes,
    user_data: *mut c_void,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        if message.is_null() {
            return;
        }
        let inbox = inbox_from(user_data);
        let text = CStr::from_ptr(message).to_string_lossy();

        let formatted_msg: Message = serde_json::from_str(&text).unwrap_or_else(|err| {
            Message::Other(json!({
                "error": err.to_string(),
                "data": text,
            }))
        });

        if let Message::Send(msg) = &formatted_msg
            && msg.payload.get(0).and_then(Value::as_str) == Some("frida:rpc")
        {
            let Message::Send(msg) = formatted_msg else {
                unreachable!()
            };
            inbox.deliver_reply(msg.payload);
            return;
        }

        // Retrieve extra message data, if any.
        let data_vec = if data.is_null() {
            None
        } else {
            let mut raw_data_size: gsize = 0;
            let raw_data = g_bytes_get_data(data, &mut raw_data_size) as *const u8;
            if raw_data_size == 0 || raw_data.is_null() {
                None
            } else {
                // Copy to a vector to avoid potential lifetime issues.
                Some(std::slice::from_raw_parts(raw_data, raw_data_size as usize).to_vec())
            }
        };

        inbox.deliver(formatted_msg, data_vec);
    }));
}

unsafe extern "C" fn on_script_destroyed(_script: *mut _FridaScript, user_data: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        unsafe { inbox_from(user_data) }.close()
    }));
}

unsafe extern "C" fn release_inbox(user_data: gpointer, _closure: *mut _GClosure) {
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Arc::from_raw(user_data as *const Inbox));
    }));
}

/// A reference to the `FridaScript`, given back when the last holder drops.
struct ScriptRef(*mut _FridaScript);

impl Drop for ScriptRef {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.0 as _) }
    }
}

/// Keeps [`Script`] and [`Exports`] neither `Send`, `Sync` nor unwind-safe,
/// as they were.
type NotThreadSafe = PhantomData<Rc<RefCell<()>>>;

/// Represents a Frida script.
pub struct Script<'a> {
    script: Rc<ScriptRef>,
    inbox: Arc<Inbox>,
    signal_ids: [gulong; 2],
    ///Exports of the script.
    pub exports: Exports<'a>,
    phantom: PhantomData<&'a _FridaScript>,
    not_thread_safe: NotThreadSafe,
}

/// This represents the exports of the script.
pub struct Exports<'a> {
    script: Rc<ScriptRef>,
    inbox: Arc<Inbox>,
    phantom: PhantomData<&'a _FridaScript>,
    not_thread_safe: NotThreadSafe,
}

unsafe fn connect(
    script: *mut _FridaScript,
    signal: &CStr,
    callback: *const c_void,
    inbox: &Arc<Inbox>,
) -> gulong {
    unsafe {
        let callback = std::mem::transmute::<*const c_void, unsafe extern "C" fn()>(callback);
        frida_sys::g_signal_connect_data(
            script as _,
            signal.as_ptr(),
            Some(callback),
            Arc::into_raw(inbox.clone()) as gpointer,
            Some(release_inbox),
            0,
        )
    }
}

impl<'a> Script<'a> {
    pub(crate) fn from_raw(script_ptr: *mut _FridaScript) -> Script<'a> {
        let script = Rc::new(ScriptRef(script_ptr));
        let inbox = Arc::new(Inbox::new());
        // Connected once, for the life of this `Script`: RPC replies arrive
        // whether or not a handler is ever installed, and a destroyed script
        // ends the calls waiting on it.
        let signal_ids = unsafe {
            [
                connect(
                    script_ptr,
                    c"message",
                    on_script_message as *const c_void,
                    &inbox,
                ),
                connect(
                    script_ptr,
                    c"destroyed",
                    on_script_destroyed as *const c_void,
                    &inbox,
                ),
            ]
        };
        if unsafe { frida_sys::frida_script_is_destroyed(script_ptr) } != 0 {
            inbox.close();
        }
        Script {
            script: script.clone(),
            inbox: inbox.clone(),
            signal_ids,
            phantom: PhantomData,
            not_thread_safe: PhantomData,
            exports: Exports {
                script,
                inbox,
                phantom: PhantomData,
                not_thread_safe: PhantomData,
            },
        }
    }

    /// Loads the script into the process.
    pub fn load(&self) -> Result<()> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        unsafe { frida_sys::frida_script_load_sync(self.script.0, null_mut(), &mut error) };

        if error.is_null() {
            Ok(())
        } else {
            unsafe { crate::take_gerror(error) };
            Err(Error::LoadingFailed)
        }
    }

    /// Unloads the script from the process.
    pub fn unload(&self) -> Result<()> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        unsafe { frida_sys::frida_script_unload_sync(self.script.0, null_mut(), &mut error) };

        if error.is_null() {
            Ok(())
        } else {
            unsafe { crate::take_gerror(error) };
            Err(Error::UnloadingFailed)
        }
    }

    /// Handles the `message` signal for the script and wraps into [`ScriptHandler`].
    ///
    /// A later call replaces the handler; each message reaches one handler,
    /// once. The handler is called on frida's thread, so whatever it shares
    /// with other threads must be safe to use from there. A panic in it is
    /// caught and reported, and the handler stays installed. It is dropped
    /// when it is replaced or when the [`Script`] is dropped.
    ///
    /// # Example
    ///
    /// ```
    /// use frida::ScriptHandler;
    ///
    /// struct Handler;
    ///
    /// impl ScriptHandler for Handler {
    ///     fn on_message(&mut self, message: frida::Message, data: Option<Vec<u8>>) {
    ///         println!("Message: {:?}", message);
    ///         println!("Data: {:?}", data);
    ///     }
    /// }
    /// ```
    pub fn handle_message<I: ScriptHandler + 'static>(&mut self, handler: I) -> Result<()> {
        self.inbox.set_handler(Box::new(handler));
        Ok(())
    }

    /// Post a JSON-encoded message to the script with optional binary data
    ///
    /// NOTE: `message` must be valid JSON otherwise the script will throw a SyntaxError
    pub fn post<S: AsRef<str>>(&self, message: S, data: Option<&[u8]>) -> Result<()> {
        let message = CString::new(message.as_ref()).map_err(|_| Error::CStringFailed)?;

        unsafe {
            let g_data = if let Some(data) = data {
                g_bytes_new(data.as_ptr() as _, data.len() as _)
            } else {
                std::ptr::null_mut()
            };
            frida_sys::frida_script_post(self.script.0, message.as_ptr() as _, g_data);
            g_bytes_unref(g_data);
        }

        Ok(())
    }

    /// List all the exported attributes from the script's rpc
    ///
    /// Fails if the script answers with an error, or is destroyed before it
    /// answers.
    pub fn list_exports(&mut self) -> Result<Vec<String>> {
        let payload = self.inbox.request(&self.script, "list", vec![])?;
        if payload.get(2).and_then(Value::as_str) != Some("ok") {
            return Err(rpc_failure(&payload));
        }
        let names = payload
            .get(3)
            .and_then(Value::as_array)
            .ok_or(Error::RpcUnexpectedMessage)?;
        Ok(names
            .iter()
            .map(|name| name.as_str().unwrap_or("").to_string())
            .collect())
    }
}

impl Exports<'_> {
    /// Run exported functions from a Frida script.
    ///
    /// `args` is the list of arguments, as a JSON array; `None` is none.
    /// Fails if the function throws, or if the script is destroyed before it
    /// answers. A call to a script that is not loaded waits until it is.
    pub fn call(&mut self, function_name: &str, args: Option<Value>) -> Result<Option<Value>> {
        let args = args.unwrap_or_else(|| Value::Array(vec![]));
        let payload = self
            .inbox
            .request(&self.script, "call", vec![json!(function_name), args])?;

        if payload.get(2).and_then(Value::as_str) != Some("ok") {
            return Err(rpc_failure(&payload));
        }
        match payload.get(3) {
            Some(Value::Null) => Ok(None),
            Some(returns) => Ok(Some(returns.clone())),
            None => Err(Error::RpcUnexpectedMessage),
        }
    }
}

impl Drop for Script<'_> {
    fn drop(&mut self) {
        // The handler stops here: no message reaches it after the `Script`
        // is gone, though the session may keep the script itself running.
        // GLib drops the connections' references to the inbox once no
        // callback is running.
        for id in self.signal_ids {
            unsafe { frida_sys::g_signal_handler_disconnect(self.script.0 as _, id) };
        }
        self.inbox.close();
        let handler = self
            .inbox
            .handler
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        drop(handler);
    }
}

/// The JavaScript runtime of Frida.
pub enum ScriptRuntime {
    /// Default Frida runtime.
    Default,
    /// QuickJS runtime.
    QJS,
    /// Google V8 runtime.
    V8,
}

impl From<ScriptRuntime> for frida_sys::FridaScriptRuntime {
    fn from(runtime: ScriptRuntime) -> Self {
        match runtime {
            ScriptRuntime::Default => frida_sys::FridaScriptRuntime_FRIDA_SCRIPT_RUNTIME_DEFAULT,
            ScriptRuntime::QJS => frida_sys::FridaScriptRuntime_FRIDA_SCRIPT_RUNTIME_QJS,
            ScriptRuntime::V8 => frida_sys::FridaScriptRuntime_FRIDA_SCRIPT_RUNTIME_V8,
        }
    }
}

/// Represents options passed to the Frida script registrar.
pub struct ScriptOption {
    ptr: *mut FridaScriptOptions,
}

impl ScriptOption {
    /// Create a new set of script options.
    pub fn new() -> Self {
        let ptr = unsafe { frida_sys::frida_script_options_new() };
        Self { ptr }
    }

    /// Get the name of the script, or `""` if it has none.
    ///
    /// The options own their name only until it is next set, so the name is
    /// copied out, once for each distinct name, and kept for the life of the
    /// process: that is what lets it be `'static`.
    pub fn get_name(&self) -> &'static str {
        let name = unsafe { frida_sys::frida_script_options_get_name(self.ptr) };
        if name.is_null() {
            return "";
        }
        let name = unsafe { CStr::from_ptr(name) };
        intern(name.to_str().unwrap_or_default())
    }

    /// Set the name of the script. A name is cut at a NUL in it, if any.
    pub fn set_name(self, name: &str) -> Self {
        let name = name.split('\0').next().unwrap_or_default();
        let name = CString::new(name).unwrap_or_default();
        unsafe { frida_sys::frida_script_options_set_name(self.ptr, name.as_ptr()) };
        self
    }

    /// Set the runtime of the script.
    pub fn set_runtime(self, runtime: ScriptRuntime) -> Self {
        unsafe { frida_sys::frida_script_options_set_runtime(self.ptr, runtime.into()) };
        self
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut FridaScriptOptions {
        self.ptr
    }
}

impl Default for ScriptOption {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ScriptOption {
    fn drop(&mut self) {
        unsafe {
            frida_sys::g_clear_object(
                &mut self.ptr as *mut *mut frida_sys::_FridaScriptOptions as _,
            )
        }
    }
}

/// The one `'static` copy of `name`, made the first time it is asked for.
fn intern(name: &str) -> &'static str {
    static NAMES: Mutex<BTreeSet<&'static str>> = Mutex::new(BTreeSet::new());
    let mut names = NAMES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(known) = names.get(name) {
        return known;
    }
    let name: &'static str = Box::leak(name.into());
    names.insert(name);
    name
}
