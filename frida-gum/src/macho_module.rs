/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Mach-O module inspection: enumerate segments, sections, symbols, exports and binds.
//!
//! Added in Frida 17.16.0 as the Darwin module API, which Frida 17.25 renamed to Mach-O and made
//! portable, so it reads Mach-O files on every platform Frida supports. [`Gum`](crate::Gum) must
//! have been obtained before a module is created.

use {
    crate::{
        enumeration::{Sink, collected, details_callout, string_at},
        glib_compat,
    },
    core::{ffi::c_void, ptr},
    cstr_core::CString,
    frida_gum_sys as gum_sys,
    frida_gum_sys::{gchar, gpointer},
};

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

/// The text in a fixed-size name field, which is NUL-terminated.
fn name_in(field: &[gchar]) -> String {
    // SAFETY: gum copies these names with `g_strlcpy`, which always terminates them.
    unsafe { string_at(field.as_ptr()) }.unwrap_or_default()
}

/// Mach-O segment details.
#[derive(Clone, Debug)]
pub struct MachoSegment {
    pub name: String,
    pub vm_address: u64,
    pub vm_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub protection: u32,
}

impl MachoSegment {
    unsafe fn from_raw(details: *const gum_sys::GumMachoSegment) -> Self {
        let details = unsafe { &*details };
        Self {
            name: name_in(&details.name),
            vm_address: details.vm_address,
            vm_size: details.vm_size,
            file_offset: details.file_offset,
            file_size: details.file_size,
            protection: details.protection as u32,
        }
    }
}

/// Mach-O section details.
#[derive(Clone, Debug)]
pub struct MachoSectionDetails {
    pub segment_name: String,
    pub section_name: String,
    pub vm_address: u64,
    pub size: u64,
}

impl MachoSectionDetails {
    unsafe fn from_raw(details: *const gum_sys::GumMachoSectionDetails) -> Self {
        let details = unsafe { &*details };
        Self {
            segment_name: name_in(&details.segment_name),
            section_name: name_in(&details.section_name),
            vm_address: details.vm_address,
            size: details.size,
        }
    }
}

/// Mach-O symbol details.
#[derive(Clone, Debug)]
pub struct MachoSymbolDetails {
    pub name: String,
    pub address: u64,
}

impl MachoSymbolDetails {
    unsafe fn from_raw(details: *const gum_sys::GumMachoSymbolDetails) -> Self {
        let details = unsafe { &*details };
        Self {
            name: unsafe { string_at(details.name) }.unwrap_or_default(),
            address: details.address,
        }
    }
}

/// Mach-O export details.
#[derive(Clone, Debug)]
pub struct MachoExportDetails {
    pub name: String,
    pub flags: u64,
    /// Offset of the symbol from the start of the image, or of its stub for an export with a
    /// resolver. Zero for a re-export, which has no place in this image.
    pub offset: u64,
}

impl MachoExportDetails {
    unsafe fn from_raw(details: *const gum_sys::GumMachoExportDetails) -> Self {
        let details = unsafe { &*details };
        let reexport = gum_sys::_GumMachoExportSymbolFlags_GUM_MACHO_EXPORT_REEXPORT as u64;
        let is_reexport = (details.flags & reexport) != 0;
        Self {
            name: unsafe { string_at(details.name) }.unwrap_or_default(),
            flags: details.flags,
            offset: if is_reexport {
                0
            } else {
                // SAFETY: an export that is not a re-export has an offset or a stub written
                // here, and the two share their place in the union.
                unsafe { details.__bindgen_anon_1.__bindgen_anon_1.offset }
            },
        }
    }
}

/// Mach-O bind details.
#[derive(Clone, Debug)]
pub struct MachoBindDetails {
    /// Index of the segment the bind is in, as [`MachoModule::segments`] orders them.
    pub segment_index: u16,
    pub offset: u64,
    pub type_: u8,
    pub library_ordinal: i16,
    pub symbol_name: String,
    pub symbol_flags: i8,
    pub addend: i64,
}

impl MachoBindDetails {
    /// # Safety
    ///
    /// `first_segment` must be the module's first segment, or null.
    unsafe fn from_raw(
        details: *const gum_sys::GumMachoBindDetails,
        first_segment: *const gum_sys::GumMachoSegment,
    ) -> Self {
        let details = unsafe { &*details };
        let segment_index = if details.segment.is_null() || first_segment.is_null() {
            0
        } else {
            // SAFETY: a bind's segment is an element of the array `first_segment` starts.
            unsafe { details.segment.offset_from(first_segment) as u16 }
        };
        Self {
            segment_index,
            offset: details.offset,
            type_: details.type_,
            library_ordinal: details.library_ordinal as i16,
            symbol_name: unsafe { string_at(details.symbol_name) }.unwrap_or_default(),
            symbol_flags: details.symbol_flags as i8,
            addend: details.addend,
        }
    }
}

/// The task whose memory holds an image mapped into this process.
#[cfg(target_vendor = "apple")]
fn current_task() -> gum_sys::GumDarwinPort {
    unsafe extern "C" {
        static mach_task_self_: gum_sys::GumDarwinPort;
    }
    // SAFETY: the system sets this before any of the process's code runs and never writes it
    // again. It is what the C macro `mach_task_self()` reads.
    unsafe { mach_task_self_ }
}

/// The task whose memory holds an image mapped into this process. Only Darwin has tasks; elsewhere
/// gum reads this process's memory whatever the task.
#[cfg(not(target_vendor = "apple"))]
fn current_task() -> gum_sys::GumDarwinPort {
    0
}

/// A Mach-O module parsed by Frida.
pub struct MachoModule {
    inner: *mut gum_sys::GumMachoModule,
}

impl MachoModule {
    /// Open a Mach-O file from disk. From a universal binary, the first slice for a CPU Frida
    /// supports is taken.
    ///
    /// Returns `None` if the file cannot be opened or parsed.
    pub fn from_file(path: &str) -> Option<Self> {
        let path = CString::new(path).ok()?;
        let mut error: *mut gum_sys::GError = ptr::null_mut();
        let inner = unsafe {
            gum_sys::gum_macho_module_new_from_file(
                path.as_ptr().cast(),
                gum_sys::GumCpuType_GUM_CPU_INVALID,
                gum_sys::_GumPtrauthSupport_GUM_PTRAUTH_INVALID as _,
                gum_sys::GumMachoModuleFlags_GUM_MACHO_MODULE_FLAGS_NONE,
                &mut error,
            )
        };
        unsafe { Self::from_new(inner, error) }
    }

    /// Parse a Mach-O file held in `bytes`, which are copied. From a universal binary, the first
    /// slice for a CPU Frida supports is taken.
    ///
    /// Returns `None` if the bytes cannot be parsed.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut error: *mut gum_sys::GError = ptr::null_mut();
        unsafe {
            let blob = glib_compat::g_bytes_new(bytes.as_ptr().cast(), bytes.len() as _);
            let inner = gum_sys::gum_macho_module_new_from_blob(
                blob,
                gum_sys::GumCpuType_GUM_CPU_INVALID,
                gum_sys::_GumPtrauthSupport_GUM_PTRAUTH_INVALID as _,
                gum_sys::GumMachoModuleFlags_GUM_MACHO_MODULE_FLAGS_NONE,
                &mut error,
            );
            // The module holds its own reference to the blob.
            glib_compat::g_bytes_unref(blob);
            Self::from_new(inner, error)
        }
    }

    /// Open a Mach-O module already mapped into this process at `base_address`.
    ///
    /// `base_address` must be the base of a mapped Mach-O image: the image is read on first use,
    /// not here, and Gum reads it in place without checking that the memory is mapped. Returns
    /// `None` for a null `base_address` or a `name` with a NUL in it.
    pub fn from_memory(name: &str, base_address: u64) -> Option<Self> {
        if base_address == 0 {
            // Gum asserts on it.
            return None;
        }
        let name = CString::new(name).ok()?;
        let mut error: *mut gum_sys::GError = ptr::null_mut();
        let inner = unsafe {
            gum_sys::gum_macho_module_new_from_memory(
                name.as_ptr().cast(),
                current_task(),
                base_address,
                gum_sys::GumMachoModuleFlags_GUM_MACHO_MODULE_FLAGS_NONE,
                &mut error,
            )
        };
        unsafe { Self::from_new(inner, error) }
    }

    /// Takes ownership of what a constructor returned, freeing the error it may have set.
    unsafe fn from_new(
        inner: *mut gum_sys::GumMachoModule,
        error: *mut gum_sys::GError,
    ) -> Option<Self> {
        if !error.is_null() {
            unsafe { glib_compat::g_error_free(error) };
        }
        if inner.is_null() {
            None
        } else {
            Some(Self { inner })
        }
    }

    /// The module's first segment, or null if its image cannot be read.
    fn first_segment(&self) -> *const gum_sys::GumMachoSegment {
        unsafe { gum_sys::gum_macho_module_get_nth_segment(self.inner, 0) }
    }

    /// Enumerate segments in this module.
    pub fn segments(&self) -> Vec<MachoSegment> {
        let mut result = Vec::new();
        loop {
            let segment =
                unsafe { gum_sys::gum_macho_module_get_nth_segment(self.inner, result.len() as _) };
            if segment.is_null() {
                return result;
            }
            result.push(unsafe { MachoSegment::from_raw(segment) });
        }
    }

    /// Enumerate sections in this module.
    pub fn enumerate_sections<F>(&self, mut callback: F)
    where
        F: FnMut(MachoSectionDetails) -> bool,
    {
        let mut sink = |details| callback(unsafe { MachoSectionDetails::from_raw(details) });
        let mut sink: Sink<'_, *const gum_sys::GumMachoSectionDetails> = &mut sink;
        unsafe {
            gum_sys::gum_macho_module_enumerate_sections(
                self.inner,
                Some(details_callout::<gum_sys::GumMachoSectionDetails>),
                &mut sink as *mut _ as gpointer,
            );
        }
    }

    /// Enumerate symbols in this module.
    pub fn enumerate_symbols<F>(&self, mut callback: F)
    where
        F: FnMut(MachoSymbolDetails) -> bool,
    {
        let mut sink = |details| callback(unsafe { MachoSymbolDetails::from_raw(details) });
        let mut sink: Sink<'_, *const gum_sys::GumMachoSymbolDetails> = &mut sink;
        unsafe {
            gum_sys::gum_macho_module_enumerate_symbols(
                self.inner,
                Some(details_callout::<gum_sys::GumMachoSymbolDetails>),
                &mut sink as *mut _ as gpointer,
            );
        }
    }

    /// Enumerate exports from this module.
    pub fn enumerate_exports<F>(&self, mut callback: F)
    where
        F: FnMut(MachoExportDetails) -> bool,
    {
        let mut sink = |details| callback(unsafe { MachoExportDetails::from_raw(details) });
        let mut sink: Sink<'_, *const gum_sys::GumMachoExportDetails> = &mut sink;
        unsafe {
            gum_sys::gum_macho_module_enumerate_exports(
                self.inner,
                Some(details_callout::<gum_sys::GumMachoExportDetails>),
                &mut sink as *mut _ as gpointer,
            );
        }
    }

    /// Enumerate bind entries (external symbol references).
    pub fn enumerate_binds<F>(&self, mut callback: F)
    where
        F: FnMut(MachoBindDetails) -> bool,
    {
        let first_segment = self.first_segment();
        let mut sink =
            |details| callback(unsafe { MachoBindDetails::from_raw(details, first_segment) });
        let mut sink: Sink<'_, *const gum_sys::GumMachoBindDetails> = &mut sink;
        unsafe {
            gum_sys::gum_macho_module_enumerate_binds(
                self.inner,
                Some(details_callout::<gum_sys::GumMachoBindDetails>),
                &mut sink as *mut _ as gpointer,
            );
        }
    }

    /// Collect all sections into a Vec.
    pub fn sections(&self) -> Vec<MachoSectionDetails> {
        collected(|sink| self.enumerate_sections(sink))
    }

    /// Collect all symbols into a Vec.
    pub fn symbols(&self) -> Vec<MachoSymbolDetails> {
        collected(|sink| self.enumerate_symbols(sink))
    }

    /// Collect all exports into a Vec.
    pub fn exports(&self) -> Vec<MachoExportDetails> {
        collected(|sink| self.enumerate_exports(sink))
    }

    /// Collect all binds into a Vec.
    pub fn binds(&self) -> Vec<MachoBindDetails> {
        collected(|sink| self.enumerate_binds(sink))
    }
}

impl Drop for MachoModule {
    fn drop(&mut self) {
        unsafe { gum_sys::g_object_unref(self.inner as *mut c_void) };
    }
}

/// The name [`MachoModule`] had before Frida 17.25.
#[deprecated(note = "renamed to `MachoModule`")]
pub type DarwinModule = MachoModule;

/// The name [`MachoSegment`] had before Frida 17.25.
#[deprecated(note = "renamed to `MachoSegment`")]
pub type DarwinSegment = MachoSegment;

/// The name [`MachoSectionDetails`] had before Frida 17.25.
#[deprecated(note = "renamed to `MachoSectionDetails`")]
pub type DarwinSectionDetails = MachoSectionDetails;

/// The name [`MachoSymbolDetails`] had before Frida 17.25.
#[deprecated(note = "renamed to `MachoSymbolDetails`")]
pub type DarwinSymbolDetails = MachoSymbolDetails;

/// The name [`MachoExportDetails`] had before Frida 17.25.
#[deprecated(note = "renamed to `MachoExportDetails`")]
pub type DarwinExportDetails = MachoExportDetails;

/// The name [`MachoBindDetails`] had before Frida 17.25.
#[deprecated(note = "renamed to `MachoBindDetails`")]
pub type DarwinBindDetails = MachoBindDetails;
