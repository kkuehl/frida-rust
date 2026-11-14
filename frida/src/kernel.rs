/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Kernels as they are on disk, to hand to a Barebone session: a Linux kernel's image or its
//! `System.map`, either of which tells what the kernel names, and an XNU kernelcache.
//!
//! [`Frida`](crate::Frida) must have been obtained before any of these is created.

use frida_sys::{_FridaLinuxKernelSymbols, _FridaXnuKernelcache, GBytes, GError};
use std::ffi::CString;
use std::ops::Deref;

use crate::error::take_gerror;
use crate::{Error, Result};

/// A new `GBytes` holding a copy of `bytes`, for the caller to unref.
fn blob_of(bytes: &[u8]) -> *mut GBytes {
    unsafe { frida_sys::g_bytes_new(bytes.as_ptr().cast(), bytes.len() as _) }
}

/// What a constructor that reads a kernel returned: the object, or the error it set.
unsafe fn kernel_or_error<T>(object: *mut T, error: *mut GError) -> Result<*mut T> {
    if !error.is_null() {
        let (code, message) = unsafe { take_gerror(error) };
        return Err(Error::KernelReadFailed { code, message });
    }
    if object.is_null() {
        return Err(Error::KernelReadFailed {
            code: 0,
            message: "nothing was returned".into(),
        });
    }
    Ok(object)
}

/// What a Linux kernel names, and the address each name was linked for: a
/// [`LinuxKernelImage`] or a [`LinuxSystemMap`].
pub struct LinuxKernelSymbols {
    ptr: *mut _FridaLinuxKernelSymbols,
}

impl LinuxKernelSymbols {
    /// Takes over the caller's reference to `ptr`.
    pub(crate) unsafe fn from_owned(ptr: *mut _FridaLinuxKernelSymbols) -> Self {
        Self { ptr }
    }

    /// Whether the kernel names `name`.
    pub fn has_symbol(&self, name: &str) -> bool {
        let Ok(name) = CString::new(name) else {
            return false;
        };
        unsafe { frida_sys::frida_linux_kernel_symbols_has_symbol(self.ptr, name.as_ptr()) != 0 }
    }

    /// The address `name` was linked for, or `None` if the kernel does not name it.
    pub fn try_find_symbol(&self, name: &str) -> Option<u64> {
        let name = CString::new(name).ok()?;
        let mut address = 0;
        let found = unsafe {
            frida_sys::frida_linux_kernel_symbols_try_find_symbol(
                self.ptr,
                name.as_ptr(),
                &mut address,
            )
        };
        (found != 0).then_some(address)
    }

    /// Access the raw pointer.
    pub fn raw_ptr(&self) -> *mut _FridaLinuxKernelSymbols {
        self.ptr
    }
}

impl Drop for LinuxKernelSymbols {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.ptr as _) }
    }
}

/// A Linux kernel image: a raw one, a gzip-compressed one, or a bzImage whose payload is packed
/// with LZ4. Its symbols come from the kallsyms tables embedded in it.
pub struct LinuxKernelImage(LinuxKernelSymbols);

impl LinuxKernelImage {
    /// Finds the kallsyms tables in the kernel image held in `bytes`, which are copied.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut error: *mut GError = std::ptr::null_mut();
        unsafe {
            let blob = blob_of(bytes);
            let image = frida_sys::frida_linux_kernel_image_from_blob(blob, &mut error);
            frida_sys::g_bytes_unref(blob);
            Ok(Self(LinuxKernelSymbols::from_owned(
                kernel_or_error(image, error)?.cast(),
            )))
        }
    }

    /// Reads the kernel image at `path`.
    pub fn open(path: &str) -> Result<Self> {
        let path = CString::new(path).map_err(|_| Error::CStringFailed)?;
        let mut error: *mut GError = std::ptr::null_mut();
        unsafe {
            let image = frida_sys::frida_linux_kernel_image_open(path.as_ptr(), &mut error);
            Ok(Self(LinuxKernelSymbols::from_owned(
                kernel_or_error(image, error)?.cast(),
            )))
        }
    }
}

impl Deref for LinuxKernelImage {
    type Target = LinuxKernelSymbols;

    fn deref(&self) -> &LinuxKernelSymbols {
        &self.0
    }
}

/// The `System.map` a kernel build leaves beside its image: a line per symbol, each an address,
/// a one-letter type, and a name.
pub struct LinuxSystemMap(LinuxKernelSymbols);

impl LinuxSystemMap {
    /// Reads the `System.map` whose text is `bytes`, which are copied.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Frida splits the text at the line ending of the system it was built on, so on
        // Windows a map whose lines end in a bare LF, as every kernel build's do, is one long
        // line. Lines ending in CR LF are split either way, as the CR is trimmed off the name.
        let mut text = Vec::with_capacity(bytes.len() + bytes.len() / 16 + 1);
        for (i, &byte) in bytes.iter().enumerate() {
            if byte == b'\n' && (i == 0 || bytes[i - 1] != b'\r') {
                text.push(b'\r');
            }
            text.push(byte);
        }
        // Frida reads the text as a C string, up to a NUL that the bytes need not end with.
        text.push(0);
        let mut error: *mut GError = std::ptr::null_mut();
        unsafe {
            let blob = blob_of(&text);
            let map = frida_sys::frida_linux_system_map_from_blob(blob, &mut error);
            frida_sys::g_bytes_unref(blob);
            Ok(Self(LinuxKernelSymbols::from_owned(
                kernel_or_error(map, error)?.cast(),
            )))
        }
    }

    /// Reads the `System.map` at `path`.
    ///
    /// The file is read here and given to [`LinuxSystemMap::from_bytes`], not to
    /// `frida_linux_system_map_open`, which on Windows does not split a map whose lines end in
    /// a bare LF.
    pub fn open(path: &str) -> Result<Self> {
        if path.contains('\0') {
            return Err(Error::CStringFailed);
        }
        let bytes = std::fs::read(path).map_err(|error| Error::KernelReadFailed {
            code: error.raw_os_error().unwrap_or(0),
            message: error.to_string(),
        })?;
        Self::from_bytes(&bytes)
    }
}

impl Deref for LinuxSystemMap {
    type Target = LinuxKernelSymbols;

    fn deref(&self) -> &LinuxKernelSymbols {
        &self.0
    }
}

/// An XNU kernelcache, held as it arrived: a Barebone session takes it apart itself.
pub struct XnuKernelcache {
    ptr: *mut _FridaXnuKernelcache,
}

impl XnuKernelcache {
    /// Takes over the caller's reference to `ptr`.
    pub(crate) unsafe fn from_owned(ptr: *mut _FridaXnuKernelcache) -> Self {
        Self { ptr }
    }

    /// Takes the kernelcache held in `bytes`, which are copied. They are not looked at until a
    /// session uses them.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        unsafe {
            let blob = blob_of(bytes);
            let kernelcache = frida_sys::frida_xnu_kernelcache_from_blob(blob);
            frida_sys::g_bytes_unref(blob);
            Self { ptr: kernelcache }
        }
    }

    /// Reads the kernelcache at `path`.
    pub fn open(path: &str) -> Result<Self> {
        let path = CString::new(path).map_err(|_| Error::CStringFailed)?;
        let mut error: *mut GError = std::ptr::null_mut();
        unsafe {
            let kernelcache = frida_sys::frida_xnu_kernelcache_open(path.as_ptr(), &mut error);
            Ok(Self {
                ptr: kernel_or_error(kernelcache, error)?,
            })
        }
    }

    /// Access the raw pointer.
    pub fn raw_ptr(&self) -> *mut _FridaXnuKernelcache {
        self.ptr
    }
}

impl Drop for XnuKernelcache {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.ptr as _) }
    }
}
