/*
 * Copyright © 2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use frida_sys::{
    _FridaSession, _FridaSessionOptions, g_bytes_get_data, g_bytes_new, g_bytes_unref, gsize,
};
use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::ptr::null_mut;

use crate::script::{Script, ScriptOption};
use crate::{Error, Result};

/// Which realm (gum) a session's scripts run in. Values match `FridaRealm`.
#[repr(u32)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum Realm {
    /// The native realm.
    Native = 0,
    /// The emulated realm (e.g. Android's native bridge under the
    /// x86_64 emulator).
    Emulated = 1,
}

/// Where an exception is delivered while a script runs. Values match
/// `FridaExceptor`.
#[repr(u32)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum Exceptor {
    /// Deliver the exception to the script (default).
    Full = 0,
    /// Invoke only the configured exception handler.
    HandlerOnly = 1,
    /// Ignore the exception entirely.
    Off = 2,
}

/// Options for [`Device::attach`](crate::Device::attach) and
/// [`Device::attach_with_options`](crate::Device::attach_with_options).
///
/// Among these, [`gadget_path`](SessionOptions::gadget_path) is what selects a
/// custom Gadget when attaching by injection on jailed iOS and non-rooted
/// Android (Frida 17.27+ attaches to running debuggable apps over JDWP).
pub struct SessionOptions<'a> {
    pub(crate) options_ptr: *mut _FridaSessionOptions,
    phantom: PhantomData<&'a _FridaSessionOptions>,
}

impl SessionOptions<'_> {
    pub(crate) fn from_raw(options_ptr: *mut _FridaSessionOptions) -> Self {
        Self {
            options_ptr,
            phantom: PhantomData,
        }
    }

    /// Create an empty SessionOptions instance.
    pub fn new() -> Self {
        Self::from_raw(unsafe { frida_sys::frida_session_options_new() })
    }

    /// Which [`Realm`] scripts created on the session run in.
    pub fn realm(self, realm: Realm) -> Self {
        unsafe { frida_sys::frida_session_options_set_realm(self.options_ptr, realm as _) }
        self
    }

    /// How long, in milliseconds, a script keeps running after the session
    /// is detached (see `frida-session-options-set-persist-timeout`).
    pub fn persist_timeout(self, timeout: u32) -> Self {
        unsafe { frida_sys::frida_session_options_set_persist_timeout(self.options_ptr, timeout) }
        self
    }

    /// Path to the emulated (native-bridge) agent to load.
    pub fn emulated_agent_path<S: AsRef<CStr>>(self, path: S) -> Self {
        unsafe {
            frida_sys::frida_session_options_set_emulated_agent_path(
                self.options_ptr,
                path.as_ref().as_ptr() as *mut _,
            );
        }
        self
    }

    /// Path to the Gadget to inject when attaching by injection on jailed
    /// iOS and non-rooted Android. Frida 17.27+.
    pub fn gadget_path<S: AsRef<CStr>>(self, path: S) -> Self {
        unsafe {
            frida_sys::frida_session_options_set_gadget_path(
                self.options_ptr,
                path.as_ref().as_ptr() as *mut _,
            );
        }
        self
    }

    /// Where exceptions are delivered while scripts run.
    pub fn exceptor(self, exceptor: Exceptor) -> Self {
        unsafe { frida_sys::frida_session_options_set_exceptor(self.options_ptr, exceptor as _) }
        self
    }

    /// Whether the UnwindBroker is enabled (default is platform-dependent).
    pub fn unwind_broker(self, enable: bool) -> Self {
        unsafe { frida_sys::frida_session_options_set_unwind_broker(self.options_ptr, enable as _) }
        self
    }

    /// Whether the ExitMonitor is enabled.
    pub fn exit_monitor(self, enable: bool) -> Self {
        unsafe { frida_sys::frida_session_options_set_exit_monitor(self.options_ptr, enable as _) }
        self
    }

    /// Whether the ThreadSuspendMonitor is enabled.
    pub fn thread_suspend_monitor(self, enable: bool) -> Self {
        unsafe {
            frida_sys::frida_session_options_set_thread_suspend_monitor(
                self.options_ptr,
                enable as _,
            )
        }
        self
    }
}

impl Default for SessionOptions<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SessionOptions<'_> {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.options_ptr as _) }
    }
}

/// Represents a Frida session.
pub struct Session<'a> {
    session_ptr: *mut _FridaSession,
    phantom: PhantomData<&'a _FridaSession>,
}

impl<'a> Session<'a> {
    pub(crate) fn from_raw(session_ptr: *mut _FridaSession) -> Session<'a> {
        Session {
            session_ptr,
            phantom: PhantomData,
        }
    }

    /// Returns if the session is detached or not.
    pub fn is_detached(&self) -> bool {
        unsafe { frida_sys::frida_session_is_detached(self.session_ptr) == 1 }
    }

    /// Creates a [`Script`] attached to current session.
    pub fn create_script<'b>(
        &'a self,
        source: &str,
        option: &mut ScriptOption,
    ) -> Result<Script<'b>>
    where
        'a: 'b,
    {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        match CString::new(source) {
            Ok(source) => {
                let script = unsafe {
                    frida_sys::frida_session_create_script_sync(
                        self.session_ptr,
                        source.as_ptr(),
                        option.as_mut_ptr(),
                        null_mut(),
                        &mut error,
                    )
                };
                if error.is_null() {
                    Ok(Script::from_raw(script))
                } else {
                    Err(Error::ScriptCreationError)
                }
            }
            Err(_) => Err(Error::CStringFailed),
        }
    }

    /// Creates a [`Script`] from a pre-compiled bytecode blob produced by
    /// `frida_session_compile_script_sync` (or e.g. `session.compileScript`
    /// in the Node binding).
    ///
    /// Note: bytecode is runtime-specific. A blob produced with the QJS
    /// runtime won't load under V8 and vice-versa — make sure the bytecode
    /// was compiled with the same `ScriptRuntime` you pass here.
    pub fn create_script_from_bytes<'b>(
        &'a self,
        bytes: &[u8],
        option: &mut ScriptOption,
    ) -> Result<Script<'b>>
    where
        'a: 'b,
    {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        let script = unsafe {
            let g = g_bytes_new(bytes.as_ptr() as _, bytes.len() as _);
            let s = frida_sys::frida_session_create_script_from_bytes_sync(
                self.session_ptr,
                g,
                option.as_mut_ptr(),
                null_mut(),
                &mut error,
            );
            g_bytes_unref(g);
            s
        };
        if error.is_null() {
            Ok(Script::from_raw(script))
        } else {
            Err(Error::ScriptCreationError)
        }
    }

    /// Compile JS source to V8/QJS bytecode. Runtime is taken from `option`
    /// (default = QJS as of frida 16.x). The returned bytes can later be
    /// loaded with [`create_script_from_bytes`](Self::create_script_from_bytes).
    pub fn compile_script(&self, source: &str, option: &mut ScriptOption) -> Result<Vec<u8>> {
        let source_c = CString::new(source).map_err(|_| Error::CStringFailed)?;
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        unsafe {
            let g = frida_sys::frida_session_compile_script_sync(
                self.session_ptr,
                source_c.as_ptr(),
                option.as_mut_ptr(),
                null_mut(),
                &mut error,
            );
            if !error.is_null() {
                return Err(Error::ScriptCreationError);
            }
            let mut len: gsize = 0;
            let raw = g_bytes_get_data(g, &mut len) as *const u8;
            let out = if raw.is_null() || len == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(raw, len as usize).to_vec()
            };
            g_bytes_unref(g);
            Ok(out)
        }
    }

    /// Detaches the current session.
    pub fn detach(&self) -> Result<()> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        unsafe {
            frida_sys::frida_session_detach_sync(self.session_ptr, std::ptr::null_mut(), &mut error)
        }

        if error.is_null() {
            Ok(())
        } else {
            Err(Error::SessionDetachError)
        }
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.session_ptr as _) }
    }
}
