/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Kernel-mode memory operations and module enumeration.
//!
//! Provides APIs for interacting with kernel memory on supported platforms.
//! Availability can be checked with [`Kernel::api_is_available`].

use {
    crate::{MemoryRange, NativePointer, PageProtection, glib_compat::g_free},
    core::ffi::c_void,
    frida_gum_sys as gum_sys,
};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::ffi::CStr;

#[cfg(not(feature = "std"))]
use core::ffi::CStr;

/// Details about a kernel module.
#[derive(Clone, Debug)]
pub struct KernelModuleDetails {
    pub name: String,
    pub range: MemoryRange,
    pub path: String,
}

impl KernelModuleDetails {
    unsafe fn from_raw(details: *const gum_sys::GumKernelModuleDetails) -> Self {
        unsafe {
            let range_ptr = (*details).range;
            let range = MemoryRange::new(
                NativePointer((*range_ptr).base_address as *mut c_void),
                (*range_ptr).size as usize,
            );
            Self {
                name: CStr::from_ptr((*details).name)
                    .to_string_lossy()
                    .into_owned(),
                range,
                path: CStr::from_ptr((*details).path)
                    .to_string_lossy()
                    .into_owned(),
            }
        }
    }
}

extern "C" fn enumerate_modules_callout(
    details: *const gum_sys::GumKernelModuleDetails,
    user_data: *mut c_void,
) -> gum_sys::gboolean {
    let mut f =
        unsafe { Box::from_raw(user_data as *mut Box<dyn FnMut(KernelModuleDetails) -> bool>) };
    let r = unsafe { f(KernelModuleDetails::from_raw(details)) };
    Box::leak(f);
    r as gum_sys::gboolean
}

extern "C" fn enumerate_ranges_callout(
    details: *const gum_sys::_GumRangeDetails,
    user_data: *mut c_void,
) -> gum_sys::gboolean {
    let mut f = unsafe { Box::from_raw(user_data as *mut Box<dyn FnMut(MemoryRange) -> bool>) };
    let range = unsafe {
        let range_ptr = (*details).range;
        MemoryRange::new(
            NativePointer((*range_ptr).base_address as *mut c_void),
            (*range_ptr).size as usize,
        )
    };
    let r = f(range);
    Box::leak(f);
    r as gum_sys::gboolean
}

extern "C" fn enumerate_module_ranges_callout(
    details: *const gum_sys::GumKernelModuleRangeDetails,
    user_data: *mut c_void,
) -> gum_sys::gboolean {
    let mut f = unsafe { Box::from_raw(user_data as *mut Box<dyn FnMut(MemoryRange) -> bool>) };
    let range = unsafe {
        MemoryRange::new(
            NativePointer((*details).address as *mut c_void),
            (*details).size as usize,
        )
    };
    let r = f(range);
    Box::leak(f);
    r as gum_sys::gboolean
}

extern "C" fn scan_callout(
    address: gum_sys::GumAddress,
    size: gum_sys::gsize,
    user_data: *mut c_void,
) -> gum_sys::gboolean {
    let mut f =
        unsafe { Box::from_raw(user_data as *mut Box<dyn FnMut(NativePointer, usize) -> bool>) };
    let r = f(NativePointer(address as *mut c_void), size as usize);
    Box::leak(f);
    r as gum_sys::gboolean
}

/// Static interface to Frida's kernel memory operations.
pub struct Kernel;

impl Kernel {
    /// Check if kernel API is available on this platform.
    ///
    /// Returns `false` on platforms without kernel API support or
    /// when running without sufficient privileges.
    pub fn api_is_available() -> bool {
        unsafe { gum_sys::gum_kernel_api_is_available() != 0 }
    }

    /// Get the kernel page size.
    pub fn query_page_size() -> u32 {
        unsafe { gum_sys::gum_kernel_query_page_size() }
    }

    /// Allocate kernel pages.
    ///
    /// # Safety
    ///
    /// This allocates memory in kernel space. Improper use can crash the system.
    pub unsafe fn alloc_n_pages(n_pages: u32) -> NativePointer {
        let addr = unsafe { gum_sys::gum_kernel_alloc_n_pages(n_pages) };
        NativePointer(addr as *mut c_void)
    }

    /// Free kernel pages previously allocated with [`Kernel::alloc_n_pages`].
    ///
    /// # Safety
    ///
    /// The address must have been returned by [`Kernel::alloc_n_pages`]
    /// and must not have been freed already.
    pub unsafe fn free_pages(mem: NativePointer) {
        unsafe { gum_sys::gum_kernel_free_pages(mem.0 as gum_sys::GumAddress) };
    }

    /// Try to change protection on kernel memory.
    ///
    /// # Safety
    ///
    /// Modifying kernel memory protection can destabilize the system.
    pub unsafe fn try_mprotect(
        address: NativePointer,
        size: usize,
        protection: PageProtection,
    ) -> bool {
        unsafe {
            gum_sys::gum_kernel_try_mprotect(
                address.0 as gum_sys::GumAddress,
                size as gum_sys::gsize,
                protection as u32,
            ) != 0
        }
    }

    /// Read from kernel memory.
    ///
    /// Returns the bytes read, or `None` on failure.
    ///
    /// # Safety
    ///
    /// The address must point to valid kernel memory.
    pub unsafe fn read(address: NativePointer, len: usize) -> Option<Vec<u8>> {
        let mut n_read = 0usize;
        let ptr = unsafe {
            gum_sys::gum_kernel_read(
                address.0 as gum_sys::GumAddress,
                len as gum_sys::gsize,
                &mut n_read as *mut usize as *mut gum_sys::gsize,
            )
        };
        if ptr.is_null() {
            None
        } else {
            let mut buf = Vec::with_capacity(n_read);
            unsafe {
                core::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), n_read);
                buf.set_len(n_read);
                g_free(ptr as gum_sys::gpointer);
            }
            Some(buf)
        }
    }

    /// Write to kernel memory.
    ///
    /// # Safety
    ///
    /// The address must point to valid writable kernel memory.
    pub unsafe fn write(address: NativePointer, bytes: &[u8]) -> bool {
        unsafe {
            gum_sys::gum_kernel_write(
                address.0 as gum_sys::GumAddress,
                bytes.as_ptr(),
                bytes.len() as gum_sys::gsize,
            ) != 0
        }
    }

    /// Scan kernel memory for a pattern.
    ///
    /// Calls `callback` for each match with the address and size.
    ///
    /// # Safety
    ///
    /// The range must be valid kernel memory.
    pub unsafe fn scan<F>(
        range: &MemoryRange,
        pattern: &crate::memory_range::MatchPattern,
        mut callback: F,
    ) where
        F: FnMut(NativePointer, usize) -> bool,
    {
        let gum_range = gum_sys::GumMemoryRange {
            base_address: range.base_address().0 as gum_sys::GumAddress,
            size: range.size() as gum_sys::gsize,
        };

        let callback: Box<dyn FnMut(NativePointer, usize) -> bool> = Box::new(&mut callback);
        let callback = Box::into_raw(Box::new(callback));

        unsafe {
            gum_sys::gum_kernel_scan(
                &gum_range,
                pattern.internal,
                Some(scan_callout),
                callback as *mut c_void,
            );
            drop(Box::from_raw(callback));
        }
    }

    /// Enumerate kernel memory ranges matching the given protection.
    pub fn enumerate_ranges<F>(protection: PageProtection, mut callback: F)
    where
        F: FnMut(MemoryRange) -> bool,
    {
        let callback: Box<dyn FnMut(MemoryRange) -> bool> = Box::new(&mut callback);
        let callback = Box::into_raw(Box::new(callback));
        unsafe {
            gum_sys::gum_kernel_enumerate_ranges(
                protection as u32,
                Some(enumerate_ranges_callout),
                callback as *mut c_void,
            );
            drop(Box::from_raw(callback));
        }
    }

    /// Enumerate kernel memory ranges belonging to a specific module.
    pub fn enumerate_module_ranges<F>(
        module_name: &str,
        protection: PageProtection,
        mut callback: F,
    ) where
        F: FnMut(MemoryRange) -> bool,
    {
        use cstr_core::CString;
        let module_cstr = match CString::new(module_name) {
            Ok(s) => s,
            Err(_) => return,
        };

        let callback: Box<dyn FnMut(MemoryRange) -> bool> = Box::new(&mut callback);
        let callback = Box::into_raw(Box::new(callback));
        unsafe {
            gum_sys::gum_kernel_enumerate_module_ranges(
                module_cstr.as_ptr(),
                protection as u32,
                Some(enumerate_module_ranges_callout),
                callback as *mut c_void,
            );
            drop(Box::from_raw(callback));
        }
    }

    /// Enumerate loaded kernel modules.
    pub fn enumerate_modules<F>(mut callback: F)
    where
        F: FnMut(KernelModuleDetails) -> bool,
    {
        let callback: Box<dyn FnMut(KernelModuleDetails) -> bool> = Box::new(&mut callback);
        let callback = Box::into_raw(Box::new(callback));
        unsafe {
            gum_sys::gum_kernel_enumerate_modules(
                Some(enumerate_modules_callout),
                callback as *mut c_void,
            );
            drop(Box::from_raw(callback));
        }
    }

    /// Find the kernel base address.
    ///
    /// Returns 0 if not found.
    pub fn find_base_address() -> u64 {
        unsafe { gum_sys::gum_kernel_find_base_address() }
    }

    /// Set the kernel base address manually.
    ///
    /// Useful when automatic detection doesn't work.
    pub fn set_base_address(base: u64) {
        unsafe { gum_sys::gum_kernel_set_base_address(base) };
    }

    /// Collect all kernel modules into a Vec.
    pub fn modules() -> Vec<KernelModuleDetails> {
        let mut result = Vec::new();
        Self::enumerate_modules(|module| {
            result.push(module);
            true
        });
        result
    }

    /// Collect all kernel ranges with the given protection into a Vec.
    pub fn ranges(protection: PageProtection) -> Vec<MemoryRange> {
        let mut result = Vec::new();
        Self::enumerate_ranges(protection, |range| {
            result.push(range);
            true
        });
        result
    }
}
