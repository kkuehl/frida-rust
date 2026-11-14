/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! The memory of a process, this one or another: allocate, read, write and protect it through
//! one interface. It is what a [`Mapper`](crate::Mapper) maps a module into.

use {
    crate::{Gum, PageProtection},
    core::ffi::c_void,
    frida_gum_sys as gum_sys,
};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

/// The memory of a process.
pub struct ProcessMemory {
    inner: *mut gum_sys::GumNativeProcessMemory,
}

impl ProcessMemory {
    /// The memory of this process.
    pub fn local(_gum: &Gum) -> Self {
        Self {
            inner: unsafe { gum_sys::gum_native_process_memory_new_local() },
        }
    }

    /// The memory of the process `pid`, reached through `handle`: on Windows a process handle
    /// with access to the process's memory, on Darwin its task port. On Linux the process is
    /// reached by `pid` alone, and only to read and write.
    ///
    /// # Safety
    ///
    /// `handle` must be such a handle for `pid`, and must stay open for as long as the returned
    /// value, and any [`Mapper`](crate::Mapper) it was made the target of, is used. It is not
    /// closed.
    pub unsafe fn remote(_gum: &Gum, pid: u32, handle: *mut c_void) -> Self {
        Self {
            inner: unsafe { gum_sys::gum_native_process_memory_new_remote(pid, handle) },
        }
    }

    pub(crate) fn as_raw(&self) -> *mut gum_sys::GumProcessMemory {
        self.inner.cast()
    }

    /// The handle the process is reached through. Null for this process.
    pub fn handle(&self) -> *mut c_void {
        unsafe { gum_sys::gum_native_process_memory_get_handle(self.inner) }
    }

    /// The ID of the process.
    pub fn pid(&self) -> u32 {
        unsafe { gum_sys::gum_process_memory_get_pid(self.as_raw()) }
    }

    /// Allocates `size` bytes of readable and writable memory at a multiple of `alignment`,
    /// which must be a power of two. Returns its address, or `None` if there is none to be had.
    pub fn alloc(&self, size: usize, alignment: usize) -> Option<u64> {
        let address =
            unsafe { gum_sys::gum_process_memory_alloc(self.as_raw(), size as _, alignment as _) };
        (address != 0).then_some(address)
    }

    /// Like [`ProcessMemory::alloc`], but no further than `max_distance` from `near_address`.
    pub fn alloc_near(
        &self,
        near_address: u64,
        max_distance: usize,
        size: usize,
        alignment: usize,
    ) -> Option<u64> {
        let address = unsafe {
            gum_sys::gum_process_memory_alloc_near(
                self.as_raw(),
                near_address,
                max_distance as _,
                size as _,
                alignment as _,
            )
        };
        (address != 0).then_some(address)
    }

    /// Frees memory that [`ProcessMemory::alloc`] or [`ProcessMemory::alloc_near`] returned.
    ///
    /// # Safety
    ///
    /// `address` and `size` must be those of such an allocation that has not been freed, and
    /// nothing may use it afterwards.
    pub unsafe fn free(&self, address: u64, size: usize) {
        unsafe { gum_sys::gum_process_memory_free(self.as_raw(), address, size as _) };
    }

    /// Reads `size` bytes at `address`. Returns `None` if not all of them could be read.
    ///
    /// # Safety
    ///
    /// In this process the bytes are read in place, so all of them must be readable. In another
    /// process an unreadable address is an error that is reported.
    pub unsafe fn read(&self, address: u64, size: usize) -> Option<Vec<u8>> {
        let mut buffer = vec![0u8; size];
        let read = unsafe {
            gum_sys::gum_process_memory_read(
                self.as_raw(),
                address,
                buffer.as_mut_ptr().cast(),
                size as _,
            )
        };
        (read != 0).then_some(buffer)
    }

    /// Writes `data` at `address`. Returns whether all of it was written.
    ///
    /// # Safety
    ///
    /// In this process the bytes are written in place, so the memory must be writable, and
    /// nothing else may rely on what was there. The latter holds in another process too.
    pub unsafe fn write(&self, address: u64, data: &[u8]) -> bool {
        unsafe {
            gum_sys::gum_process_memory_write(
                self.as_raw(),
                address,
                data.as_ptr().cast(),
                data.len() as _,
            ) != 0
        }
    }

    /// Fills the start of the `size` bytes at `address` with `data` and gives them all the
    /// protection `protection`. Returns whether it did.
    ///
    /// # Safety
    ///
    /// The `size` bytes at `address` must be whole pages that the caller allocated and that
    /// nothing else uses, and `data` must be no longer than them.
    pub unsafe fn map(
        &self,
        address: u64,
        size: usize,
        data: &[u8],
        protection: PageProtection,
    ) -> bool {
        unsafe {
            gum_sys::gum_process_memory_map(
                self.as_raw(),
                address,
                size as _,
                data.as_ptr().cast(),
                data.len() as _,
                protection as u32,
            ) != 0
        }
    }

    /// Changes the protection of the `size` bytes at `address`. Returns whether it did.
    ///
    /// # Safety
    ///
    /// The pages must be mapped, and nothing may be using them in a way the new protection
    /// forbids.
    pub unsafe fn protect(&self, address: u64, size: usize, protection: PageProtection) -> bool {
        unsafe {
            gum_sys::gum_process_memory_protect(
                self.as_raw(),
                address,
                size as _,
                protection as u32,
            ) != 0
        }
    }

    /// Makes the `size` bytes at `address`, into which code has been written, executable.
    /// Returns whether it did.
    ///
    /// # Safety
    ///
    /// The pages must be mapped, and nothing may still be writing to them.
    pub unsafe fn mark_code(&self, address: u64, size: usize) -> bool {
        unsafe { gum_sys::gum_process_memory_mark_code(self.as_raw(), address, size as _) != 0 }
    }
}

impl Drop for ProcessMemory {
    fn drop(&mut self) {
        unsafe { gum_sys::g_object_unref(self.inner as *mut c_void) };
    }
}
