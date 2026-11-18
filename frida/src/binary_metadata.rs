/*
 * Copyright © 2026 tktkinc
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use frida_sys::{_FridaBinaryMetadata, g_strfreev};
use std::ffi::{CStr, CString};
use std::marker::PhantomData;

use crate::{Error, Result};

/// The name, version and architectures a Frida binary (Gadget, frida-server,
/// frida-inject, …) embeds, readable without loading it (Frida 17.27+).
///
/// `from_file` reads it back from a PE, Mach-O (including universal) or ELF
/// file, the same payload `BinaryMetadata.from_file()` exposes in the Python
/// and Node bindings.
pub struct BinaryMetadata<'a> {
    metadata_ptr: *mut _FridaBinaryMetadata,
    phantom: PhantomData<&'a _FridaBinaryMetadata>,
}

impl<'a> BinaryMetadata<'a> {
    /// Read the embedded metadata from the binary at `path` without loading
    /// it. Fails if the file is missing, malformed, or carries no metadata.
    pub fn from_file<S: AsRef<CStr>>(path: S) -> Result<BinaryMetadata<'a>> {
        let path = CString::new(path.as_ref().to_bytes()).map_err(|_| Error::CStringFailed)?;
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        let metadata_ptr =
            unsafe { frida_sys::frida_binary_metadata_from_file(path.as_ptr(), &mut error) };
        if error.is_null() {
            Ok(BinaryMetadata {
                metadata_ptr,
                phantom: PhantomData,
            })
        } else {
            let (code, message) = unsafe { crate::take_gerror(error) };
            Err(Error::BinaryMetadataFailed { code, message })
        }
    }

    /// The binary's name (e.g. `frida-gadget`).
    pub fn name(&self) -> Option<&str> {
        unsafe { CStr::from_ptr(frida_sys::frida_binary_metadata_get_name(self.metadata_ptr)) }
            .to_str()
            .ok()
    }

    /// The binary's version (e.g. `17.27.1`).
    pub fn version(&self) -> Option<&str> {
        unsafe {
            CStr::from_ptr(frida_sys::frida_binary_metadata_get_version(
                self.metadata_ptr,
            ))
        }
        .to_str()
        .ok()
    }

    /// The architectures the binary carries (e.g. `["arm64", "x86_64"]`).
    pub fn architectures(&self) -> Vec<String> {
        let mut len: frida_sys::gint = 0;
        let ptr = unsafe {
            frida_sys::frida_binary_metadata_get_architectures(self.metadata_ptr, &mut len)
        };
        if ptr.is_null() || len <= 0 {
            return Vec::new();
        }
        let archs = (0..len)
            .map(|i| {
                unsafe { CStr::from_ptr(*ptr.add(i as usize)) }
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        unsafe { g_strfreev(ptr) };
        archs
    }
}

impl Drop for BinaryMetadata<'_> {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.metadata_ptr as _) }
    }
}
