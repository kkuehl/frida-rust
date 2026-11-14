/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Mapping a module into a process without the system's loader: the module's image is laid out
//! in memory, relocated and bound to what it imports, and the loader never hears of it.
//!
//! The module is in the platform's own format: PE on Windows, Mach-O on Darwin, ELF elsewhere.
//!
//! Added in Frida 17.20.

use {
    crate::{
        ExportDetails, ExportType, MemoryRange, NativeModuleResolver, ProcessMemory,
        enumeration::{collected, enumerate_details, string_at},
        glib_compat,
    },
    core::{ffi::c_void, ptr},
    cstr_core::CString,
    frida_gum_sys as gum_sys,
};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// A module to map into a process, and once mapped, where it is.
pub struct Mapper {
    inner: *mut gum_sys::GumMapper,
}

impl Mapper {
    /// Reads the module at `path`, whose dependencies `resolver` is to find.
    ///
    /// Returns `None` if the file cannot be read or is not a module.
    pub fn from_file(path: &str, resolver: &NativeModuleResolver) -> Option<Self> {
        let path = CString::new(path).ok()?;
        let mut error: *mut gum_sys::GError = ptr::null_mut();
        let inner = unsafe {
            gum_sys::gum_mapper_new_from_file(path.as_ptr().cast(), resolver.as_raw(), &mut error)
        };
        unsafe { Self::from_new(inner, error) }
    }

    /// Reads the module held in `bytes`, which are copied, and calls it `name`.
    ///
    /// Returns `None` if the bytes are not a module.
    pub fn from_bytes(name: &str, bytes: &[u8], resolver: &NativeModuleResolver) -> Option<Self> {
        let name = CString::new(name).ok()?;
        let mut error: *mut gum_sys::GError = ptr::null_mut();
        unsafe {
            let blob = glib_compat::g_bytes_new(bytes.as_ptr().cast(), bytes.len() as _);
            // Takes over the reference to the blob.
            let inner = gum_sys::gum_mapper_new_take_blob(
                name.as_ptr().cast(),
                blob,
                resolver.as_raw(),
                &mut error,
            );
            Self::from_new(inner, error)
        }
    }

    /// Takes ownership of what a constructor returned, freeing the error it may have set.
    unsafe fn from_new(
        inner: *mut gum_sys::GumMapper,
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

    /// Chooses the process to map the module into. Without this it is this process.
    pub fn set_target(&self, target: &ProcessMemory) {
        unsafe { gum_sys::gum_mapper_set_target(self.inner, target.as_raw()) };
    }

    /// Adds a `key=value` string to those the module's initializers are passed on Darwin, where
    /// the kernel passes a program such strings after its environment. Does nothing elsewhere.
    pub fn add_apple_parameter(&self, key: &str, value: &str) {
        let (Ok(key), Ok(value)) = (CString::new(key), CString::new(value)) else {
            return;
        };
        unsafe {
            gum_sys::gum_mapper_add_apple_parameter(
                self.inner,
                key.as_ptr().cast(),
                value.as_ptr().cast(),
            );
        }
    }

    /// Maps the module into the target, with `extra_size` bytes of memory after it for the
    /// caller's use, and returns the address of that memory. Returns `None`, with nothing left
    /// mapped, if memory cannot be had or something the module imports cannot be found.
    ///
    /// None of the module's code is run: its initializers run when the function at
    /// [`Mapper::constructor`] is called in the target. The module stays mapped when the
    /// `Mapper` is dropped; only [`Mapper::unmap`] takes it out.
    ///
    /// The modules it depends on are loaded into this process to be found, and on Windows a
    /// module that has thread-local storage may have the creation of threads in the target
    /// hooked to set that up.
    pub fn map(&self, extra_size: usize) -> Option<u64> {
        let mut extra_address: gum_sys::GumAddress = 0;
        let mut error: *mut gum_sys::GError = ptr::null_mut();
        let mapped = unsafe {
            gum_sys::gum_mapper_map(self.inner, extra_size as _, &mut extra_address, &mut error)
        };
        if !error.is_null() {
            unsafe { glib_compat::g_error_free(error) };
        }
        (mapped != 0).then_some(extra_address)
    }

    /// Takes the mapped module, and the extra memory after it, out of the target.
    ///
    /// # Safety
    ///
    /// The module must be mapped, its destructor must have been called if its constructor was,
    /// and nothing may use its code, its data or the extra memory afterwards.
    pub unsafe fn unmap(&self) {
        unsafe { gum_sys::gum_mapper_unmap(self.inner) };
    }

    /// Where the module, with the extra memory after it, is mapped. Empty before it is.
    pub fn range(&self) -> MemoryRange {
        MemoryRange::from_raw(unsafe { gum_sys::gum_mapper_get_range(self.inner) })
    }

    /// The address in the target of a function, taking and returning nothing, that runs the
    /// mapped module's initializers. Meaningless before the module is mapped.
    pub fn constructor(&self) -> u64 {
        unsafe { gum_sys::gum_mapper_constructor(self.inner) }
    }

    /// The address in the target of a function, taking and returning nothing, that runs the
    /// mapped module's finalizers. Meaningless before the module is mapped.
    pub fn destructor(&self) -> u64 {
        unsafe { gum_sys::gum_mapper_destructor(self.inner) }
    }

    /// The address in the target of the mapped module's export `symbol`, or of what it forwards
    /// to. `None` if the module has no such export.
    pub fn resolve(&self, symbol: &str) -> Option<u64> {
        let symbol = CString::new(symbol).ok()?;
        let address = unsafe { gum_sys::gum_mapper_resolve(self.inner, symbol.as_ptr().cast()) };
        (address != 0).then_some(address)
    }

    /// The mapped module's exports, each with its address in the target.
    pub fn enumerate_exports(&self) -> Vec<ExportDetails> {
        collected(|sink| {
            enumerate_details(
                |details: *const gum_sys::GumExportDetails| {
                    let details = unsafe { &*details };
                    sink(ExportDetails {
                        typ: if details.type_ == gum_sys::GumExportType_GUM_EXPORT_VARIABLE {
                            ExportType::Variable
                        } else {
                            ExportType::Function
                        },
                        name: unsafe { string_at(details.name) }.unwrap_or_default(),
                        address: details.address as usize,
                    })
                },
                |func, data| unsafe {
                    gum_sys::gum_mapper_enumerate_exports(self.inner, Some(func), data)
                },
            )
        })
    }
}

impl Drop for Mapper {
    fn drop(&mut self) {
        unsafe { gum_sys::g_object_unref(self.inner as *mut c_void) };
    }
}
