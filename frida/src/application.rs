/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use crate::variant::Variant;
use frida_sys::_FridaApplication;
use std::collections::HashMap;
use std::ffi::CStr;
use std::marker::PhantomData;
use std::os::raw::c_void;

/// An installed or running application on the device.
///
/// Returned by [`crate::Device::enumerate_applications`]; every field except
/// `parameters` is populated with [`crate::Scope::Minimal`] (the default). With
/// [`crate::Scope::Full`], `parameters` is populated too — the same
/// host-dependent key set frida-core attaches to processes.
pub struct Application<'a> {
    application_ptr: *mut _FridaApplication,
    phantom: PhantomData<&'a _FridaApplication>,
}

impl<'a> Application<'a> {
    pub(crate) fn from_raw(application_ptr: *mut _FridaApplication) -> Application<'a> {
        Application {
            application_ptr,
            phantom: PhantomData,
        }
    }

    /// The application's identifier (its bundle id/package name).
    pub fn get_identifier(&self) -> &str {
        let id = unsafe {
            CStr::from_ptr(frida_sys::frida_application_get_identifier(self.application_ptr) as _)
        };
        id.to_str().unwrap_or_default()
    }

    /// The application's display name.
    pub fn get_name(&self) -> &str {
        let name = unsafe {
            CStr::from_ptr(frida_sys::frida_application_get_name(self.application_ptr) as _)
        };
        name.to_str().unwrap_or_default()
    }

    /// The process ID the application is currently running under, or `0` when
    /// it is not running.
    pub fn get_pid(&self) -> u32 {
        unsafe { frida_sys::frida_application_get_pid(self.application_ptr) }
    }

    /// Extended parameters attached to this application by frida-core.
    ///
    /// Only populated when enumerated with [`crate::Scope::Full`]; the default
    /// [`crate::Scope::Minimal`] returns an empty map.
    pub fn get_parameters(&self) -> HashMap<String, Variant> {
        let mut out = HashMap::new();
        unsafe {
            let hash = frida_sys::frida_application_get_parameters(self.application_ptr);
            if hash.is_null() {
                return out;
            }
            let mut iter: frida_sys::GHashTableIter = std::mem::MaybeUninit::zeroed().assume_init();
            frida_sys::g_hash_table_iter_init(&mut iter, hash);
            let mut key: *mut c_void = std::ptr::null_mut();
            let mut value: *mut c_void = std::ptr::null_mut();
            while frida_sys::g_hash_table_iter_next(&mut iter, &mut key, &mut value) != 0 {
                let k = CStr::from_ptr(key.cast()).to_string_lossy().into_owned();
                let v = Variant::from_ptr(value.cast());
                out.insert(k, v);
            }
        }
        out
    }
}

impl Drop for Application<'_> {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.application_ptr as _) }
    }
}
