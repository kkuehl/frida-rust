/*
 * Copyright © 2026 Frida-rust contributors
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Bindings to `Frida.LanguageServer`, added in Frida 17.18.0.
//!
//! The language server speaks the Language Server Protocol for a TypeScript
//! or JavaScript project, powered by the same TypeScript 7.0 compiler as
//! [`Compiler`](crate::Compiler) and sharing its parse cache.

use frida_sys::{_FridaLanguageServer, GError, _GClosure, gpointer};
use std::ffi::{CStr, CString, c_char, c_void};
use std::marker::PhantomData;

use crate::{Error, Result};

/// Trait implemented by consumers who want to receive server-to-client
/// LSP messages.
pub trait LanguageServerHandler {
    /// Invoked with each JSON-RPC message from the server.
    fn on_message(&mut self, json: &str);
}

struct HandlerBox {
    handler: Box<dyn LanguageServerHandler>,
}

unsafe extern "C" fn call_on_message(
    _server: *mut _FridaLanguageServer,
    json: *const c_char,
    user_data: *mut c_void,
) {
    unsafe {
        if json.is_null() || user_data.is_null() {
            return;
        }
        let boxed = &mut *(user_data as *mut HandlerBox);
        let text = CStr::from_ptr(json).to_string_lossy();
        boxed.handler.on_message(&text);
    }
}

unsafe extern "C" fn destroy_handler(user_data: gpointer, _closure: *mut _GClosure) {
    unsafe {
        drop(Box::from_raw(user_data as *mut HandlerBox));
    }
}

/// Speaks the Language Server Protocol for a TypeScript or JavaScript project.
///
/// Wraps `Frida.LanguageServer`, introduced in Frida 17.18.0.
pub struct LanguageServer<'a> {
    ptr: *mut _FridaLanguageServer,
    phantom: PhantomData<&'a _FridaLanguageServer>,
}

impl<'a> LanguageServer<'a> {
    /// Create a language server rooted at the given directory.
    pub fn new(project_root: &str) -> Result<Self> {
        let cs = CString::new(project_root).map_err(|_| Error::CStringFailed)?;
        let ptr = unsafe { frida_sys::frida_language_server_new(cs.as_ptr()) };
        Ok(Self {
            ptr,
            phantom: PhantomData,
        })
    }

    /// Start the server so that messages can be posted to it.
    pub fn start(&self) -> Result<()> {
        let mut error: *mut GError = std::ptr::null_mut();
        unsafe {
            frida_sys::frida_language_server_start_sync(
                self.ptr,
                std::ptr::null_mut(),
                &mut error,
            )
        };

        if !error.is_null() {
            let message = unsafe { CStr::from_ptr((*error).message) }
                .to_string_lossy()
                .into_owned();
            let code = unsafe { (*error).code };
            unsafe { frida_sys::g_error_free(error) };
            return Err(Error::LanguageServerFailed { code, message });
        }
        Ok(())
    }

    /// Send the LSP shutdown+exit messages and then stop the server.
    pub fn stop(&self) {
        unsafe { frida_sys::frida_language_server_stop(self.ptr) };
    }

    /// Post a JSON-RPC message to the server.
    pub fn post(&self, json: &str) -> Result<()> {
        let cs = CString::new(json).map_err(|_| Error::CStringFailed)?;
        let mut error: *mut GError = std::ptr::null_mut();
        unsafe { frida_sys::frida_language_server_post(self.ptr, cs.as_ptr(), &mut error) };

        if !error.is_null() {
            let message = unsafe { CStr::from_ptr((*error).message) }
                .to_string_lossy()
                .into_owned();
            let code = unsafe { (*error).code };
            unsafe { frida_sys::g_error_free(error) };
            return Err(Error::LanguageServerFailed { code, message });
        }
        Ok(())
    }

    /// Register a handler for messages emitted by the server.
    ///
    /// The handler is owned for the lifetime of the language server; the
    /// underlying GLib signal machinery drops it when the server itself is
    /// dropped.
    pub fn handle_message<H: LanguageServerHandler + 'static>(&mut self, handler: H) -> Result<()> {
        let message = CString::new("message").map_err(|_| Error::CStringFailed)?;
        let boxed = Box::into_raw(Box::new(HandlerBox {
            handler: Box::new(handler),
        }));

        unsafe {
            let cb = Some(std::mem::transmute::<
                *mut c_void,
                unsafe extern "C" fn(),
            >(call_on_message as *mut c_void));
            frida_sys::g_signal_connect_data(
                self.ptr as _,
                message.as_ptr(),
                cb,
                boxed as *mut c_void,
                Some(destroy_handler),
                0,
            );
        }
        Ok(())
    }

    /// Access the raw pointer for advanced signal wiring.
    pub fn as_raw(&self) -> *mut _FridaLanguageServer {
        self.ptr
    }
}

impl Drop for LanguageServer<'_> {
    fn drop(&mut self) {
        unsafe {
            self.stop();
            frida_sys::frida_unref(self.ptr as _);
        }
    }
}
