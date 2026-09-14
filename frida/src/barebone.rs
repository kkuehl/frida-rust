/*
 * Copyright © 2026 Frida-rust contributors
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Bindings to the Barebone backend added in Frida 17.18.0.
//!
//! Barebone talks to a target over a debug transport (GDB stub, JTAG/SWD, or a
//! Frida kernel module). Its default configuration is normally loaded from the
//! JSON file pointed to by `FRIDA_BAREBONE_CONFIG`; the wrappers in this module
//! expose the object-level C API for callers that want to add their own device
//! at runtime.

use frida_sys::{_FridaBareboneConfig, _FridaBareboneDeviceOptions};
use std::ffi::CString;

/// Runtime configuration for a Barebone device.
///
/// The default constructor produces an "all defaults" configuration; more
/// sophisticated setups should populate the nested config objects via the
/// `frida_barebone_config_*` C API (available on [`Self::raw_ptr`]).
pub struct BareboneConfig {
    ptr: *mut _FridaBareboneConfig,
}

impl BareboneConfig {
    /// Create a configuration with defaults for every setting.
    pub fn new() -> Self {
        Self {
            ptr: unsafe { frida_sys::frida_barebone_config_new() },
        }
    }

    /// Access the raw pointer for advanced configuration.
    pub fn raw_ptr(&self) -> *mut _FridaBareboneConfig {
        self.ptr
    }
}

impl Default for BareboneConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BareboneConfig {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.ptr as _) }
    }
}

/// Options that control how a Barebone device presents itself.
pub struct BareboneDeviceOptions {
    pub(crate) ptr: *mut _FridaBareboneDeviceOptions,
}

impl BareboneDeviceOptions {
    /// Create an empty options object; the backend chooses defaults.
    pub fn new() -> Self {
        Self {
            ptr: unsafe { frida_sys::frida_barebone_device_options_new() },
        }
    }

    /// Set a stable device id; if left unset, one is auto-generated.
    pub fn id(self, id: &str) -> Self {
        if let Ok(cs) = CString::new(id) {
            unsafe { frida_sys::frida_barebone_device_options_set_id(self.ptr, cs.as_ptr()) };
        }
        self
    }

    /// Set the display name; if left unset, the backend's own name is used.
    pub fn name(self, name: &str) -> Self {
        if let Ok(cs) = CString::new(name) {
            unsafe { frida_sys::frida_barebone_device_options_set_name(self.ptr, cs.as_ptr()) };
        }
        self
    }
}

impl Default for BareboneDeviceOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BareboneDeviceOptions {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.ptr as _) }
    }
}
