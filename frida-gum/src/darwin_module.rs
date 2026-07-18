/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Darwin/Mach-O module inspection — enumerate sections, symbols, exports, imports, binds, rebases.
//!
//! Added in Frida 17.16.0. Only available on macOS (Darwin module API not available on iOS/tvOS/watchOS).

#![cfg(target_os = "macos")]

use {
    core::ffi::c_void,
    cstr_core::CString,
    frida_gum_sys as gum_sys,
    frida_gum_sys::gpointer,
};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::ffi::CStr;

#[cfg(not(feature = "std"))]
use core::ffi::CStr;

/// Darwin module segment details.
#[derive(Clone, Debug)]
pub struct DarwinSegment {
    pub name: String,
    pub vm_address: u64,
    pub vm_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub protection: u32,
}

impl DarwinSegment {
    unsafe fn from_raw(details: *const gum_sys::GumDarwinSegment) -> Self {
        unsafe {
            Self {
                name: CStr::from_ptr((*details).name.as_ptr())
                    .to_string_lossy()
                    .into_owned(),
                vm_address: (*details).vm_address,
                vm_size: (*details).vm_size,
                file_offset: (*details).file_offset,
                file_size: (*details).file_size,
                protection: (*details).protection,
            }
        }
    }
}

/// Darwin section details.
#[derive(Clone, Debug)]
pub struct DarwinSectionDetails {
    pub segment_name: String,
    pub section_name: String,
    pub vm_address: u64,
    pub size: u64,
}

impl DarwinSectionDetails {
    unsafe fn from_raw(details: *const gum_sys::GumDarwinSectionDetails) -> Self {
        unsafe {
            Self {
                segment_name: CStr::from_ptr((*details).segment_name)
                    .to_string_lossy()
                    .into_owned(),
                section_name: CStr::from_ptr((*details).section_name)
                    .to_string_lossy()
                    .into_owned(),
                vm_address: (*details).vm_address,
                size: (*details).size,
            }
        }
    }
}

/// Darwin symbol details.
#[derive(Clone, Debug)]
pub struct DarwinSymbolDetails {
    pub name: String,
    pub address: u64,
}

impl DarwinSymbolDetails {
    unsafe fn from_raw(details: *const gum_sys::GumDarwinSymbolDetails) -> Self {
        unsafe {
            Self {
                name: CStr::from_ptr((*details).name)
                    .to_string_lossy()
                    .into_owned(),
                address: (*details).address,
            }
        }
    }
}

/// Darwin export details.
#[derive(Clone, Debug)]
pub struct DarwinExportDetails {
    pub name: String,
    pub flags: u64,
    pub offset: u64,
}

impl DarwinExportDetails {
    unsafe fn from_raw(details: *const gum_sys::GumDarwinExportDetails) -> Self {
        unsafe {
            Self {
                name: CStr::from_ptr((*details).name)
                    .to_string_lossy()
                    .into_owned(),
                flags: (*details).flags,
                offset: (*details).offset,
            }
        }
    }
}

/// Darwin bind details.
#[derive(Clone, Debug)]
pub struct DarwinBindDetails {
    pub segment_index: u16,
    pub offset: u64,
    pub type_: u8,
    pub library_ordinal: i16,
    pub symbol_name: String,
    pub symbol_flags: i8,
    pub addend: i64,
}

impl DarwinBindDetails {
    unsafe fn from_raw(details: *const gum_sys::GumDarwinBindDetails) -> Self {
        unsafe {
            Self {
                segment_index: (*details).segment as u16,
                offset: (*details).offset,
                type_: (*details).type_,
                library_ordinal: (*details).library_ordinal,
                symbol_name: CStr::from_ptr((*details).symbol_name)
                    .to_string_lossy()
                    .into_owned(),
                symbol_flags: (*details).symbol_flags,
                addend: (*details).addend,
            }
        }
    }
}

extern "C" fn enumerate_sections_callout(
    details: *const gum_sys::GumDarwinSectionDetails,
    user_data: *mut c_void,
) -> gum_sys::gboolean {
    let mut f = unsafe { Box::from_raw(user_data as *mut Box<dyn FnMut(DarwinSectionDetails) -> bool>) };
    let r = unsafe { f(DarwinSectionDetails::from_raw(details)) };
    Box::leak(f);
    r as gum_sys::gboolean
}

extern "C" fn enumerate_symbols_callout(
    details: *const gum_sys::GumDarwinSymbolDetails,
    user_data: *mut c_void,
) -> gum_sys::gboolean {
    let mut f = unsafe { Box::from_raw(user_data as *mut Box<dyn FnMut(DarwinSymbolDetails) -> bool>) };
    let r = unsafe { f(DarwinSymbolDetails::from_raw(details)) };
    Box::leak(f);
    r as gum_sys::gboolean
}

extern "C" fn enumerate_exports_callout(
    details: *const gum_sys::GumDarwinExportDetails,
    user_data: *mut c_void,
) -> gum_sys::gboolean {
    let mut f = unsafe { Box::from_raw(user_data as *mut Box<dyn FnMut(DarwinExportDetails) -> bool>) };
    let r = unsafe { f(DarwinExportDetails::from_raw(details)) };
    Box::leak(f);
    r as gum_sys::gboolean
}

extern "C" fn enumerate_binds_callout(
    details: *const gum_sys::GumDarwinBindDetails,
    user_data: *mut c_void,
) -> gum_sys::gboolean {
    let mut f = unsafe { Box::from_raw(user_data as *mut Box<dyn FnMut(DarwinBindDetails) -> bool>) };
    let r = unsafe { f(DarwinBindDetails::from_raw(details)) };
    Box::leak(f);
    r as gum_sys::gboolean
}

/// A Darwin (Mach-O) module loaded by Frida.
pub struct DarwinModule {
    inner: *mut gum_sys::GumDarwinModule,
}

impl DarwinModule {
    /// Open a Mach-O file from disk.
    ///
    /// Returns `None` if the file cannot be opened or parsed.
    pub fn from_file(path: &str) -> Option<Self> {
        let path = CString::new(path).ok()?;
        let mut error: *mut gum_sys::GError = core::ptr::null_mut();
        let ptr = unsafe { gum_sys::gum_darwin_module_new_from_file(path.as_ptr(), &mut error) };
        if ptr.is_null() {
            None
        } else {
            Some(Self { inner: ptr })
        }
    }

    /// Open a Mach-O module already mapped into memory at `base_address`.
    pub fn from_memory(name: &str, base_address: u64) -> Option<Self> {
        let name = CString::new(name).ok()?;
        let mut error: *mut gum_sys::GError = core::ptr::null_mut();
        let ptr = unsafe {
            gum_sys::gum_darwin_module_new_from_memory(name.as_ptr(), base_address, &mut error)
        };
        if ptr.is_null() {
            None
        } else {
            Some(Self { inner: ptr })
        }
    }

    // NOTE: Accessor functions (get_name, get_uuid, get_pointer_size, get_base_address,
    // get_preferred_address) do not exist in Frida 17.16.1. These need to be implemented
    // by accessing the underlying module image properties or waiting for upstream Frida
    // to expose these APIs.

    /// Enumerate segments in this module.
    pub fn segments(&self) -> Vec<DarwinSegment> {
        let mut result = Vec::new();
        unsafe {
            let n_segments = (*self.inner).segments.len;
            let segments = (*self.inner).segments.data as *const gum_sys::GumDarwinSegment;
            for i in 0..n_segments {
                result.push(DarwinSegment::from_raw(segments.add(i as usize)));
            }
        }
        result
    }

    /// Enumerate sections in this module.
    pub fn enumerate_sections<F>(&self, mut callback: F)
    where
        F: FnMut(DarwinSectionDetails) -> bool,
    {
        let callback: Box<dyn FnMut(DarwinSectionDetails) -> bool> = Box::new(&mut callback);
        let callback = Box::into_raw(Box::new(callback));
        unsafe {
            gum_sys::gum_darwin_module_enumerate_sections(
                self.inner,
                Some(enumerate_sections_callout),
                callback as gpointer,
            );
            drop(Box::from_raw(callback));
        }
    }

    /// Enumerate symbols in this module.
    pub fn enumerate_symbols<F>(&self, mut callback: F)
    where
        F: FnMut(DarwinSymbolDetails) -> bool,
    {
        let callback: Box<dyn FnMut(DarwinSymbolDetails) -> bool> = Box::new(&mut callback);
        let callback = Box::into_raw(Box::new(callback));
        unsafe {
            gum_sys::gum_darwin_module_enumerate_symbols(
                self.inner,
                Some(enumerate_symbols_callout),
                callback as gpointer,
            );
            drop(Box::from_raw(callback));
        }
    }

    /// Enumerate exports from this module.
    pub fn enumerate_exports<F>(&self, mut callback: F)
    where
        F: FnMut(DarwinExportDetails) -> bool,
    {
        let callback: Box<dyn FnMut(DarwinExportDetails) -> bool> = Box::new(&mut callback);
        let callback = Box::into_raw(Box::new(callback));
        unsafe {
            gum_sys::gum_darwin_module_enumerate_exports(
                self.inner,
                Some(enumerate_exports_callout),
                callback as gpointer,
            );
            drop(Box::from_raw(callback));
        }
    }

    /// Enumerate bind entries (external symbol references).
    pub fn enumerate_binds<F>(&self, mut callback: F)
    where
        F: FnMut(DarwinBindDetails) -> bool,
    {
        let callback: Box<dyn FnMut(DarwinBindDetails) -> bool> = Box::new(&mut callback);
        let callback = Box::into_raw(Box::new(callback));
        unsafe {
            gum_sys::gum_darwin_module_enumerate_binds(
                self.inner,
                Some(enumerate_binds_callout),
                callback as gpointer,
            );
            drop(Box::from_raw(callback));
        }
    }

    /// Collect all sections into a Vec.
    pub fn sections(&self) -> Vec<DarwinSectionDetails> {
        let mut result = Vec::new();
        self.enumerate_sections(|section| {
            result.push(section);
            true
        });
        result
    }

    /// Collect all symbols into a Vec.
    pub fn symbols(&self) -> Vec<DarwinSymbolDetails> {
        let mut result = Vec::new();
        self.enumerate_symbols(|symbol| {
            result.push(symbol);
            true
        });
        result
    }

    /// Collect all exports into a Vec.
    pub fn exports(&self) -> Vec<DarwinExportDetails> {
        let mut result = Vec::new();
        self.enumerate_exports(|export| {
            result.push(export);
            true
        });
        result
    }

    /// Collect all binds into a Vec.
    pub fn binds(&self) -> Vec<DarwinBindDetails> {
        let mut result = Vec::new();
        self.enumerate_binds(|bind| {
            result.push(bind);
            true
        });
        result
    }
}

impl Drop for DarwinModule {
    fn drop(&mut self) {
        unsafe { gum_sys::g_object_unref(self.inner as *mut c_void) };
    }
}
