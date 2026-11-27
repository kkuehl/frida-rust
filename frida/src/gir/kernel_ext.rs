/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Written by hand on top of the generated [`LinuxSystemMap`]: frida-core's own
//! `from_blob` reads the blob as a C string, past its end unless it ends in a NUL
//! (`linux-kernel-image.vala:96`), and splits it at the line ending of the system it was
//! built on, so on Windows a map whose lines end in a bare LF, as every kernel build's
//! do, is one long line.

use std::path::Path;

use crate::gir::runtime::Lease;
use crate::gir::{Error, LinuxSystemMap, ObjectType, marshal};

impl LinuxSystemMap {
    /// The `System.map` whose text is `blob`, which is copied.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidArgument`](crate::gir::ErrorKind::InvalidArgument) if the text
    /// names no symbols, and
    /// [`ErrorKind::InvalidOperation`](crate::gir::ErrorKind::InvalidOperation) once
    /// frida-core has been deinitialized.
    pub fn from_blob(blob: &[u8]) -> Result<Self, Error> {
        let _lease = Lease::new()?;
        // A CR before each bare LF: lines ending in CR LF are split on every system, as the
        // CR is trimmed off the name. Then the NUL frida-core reads up to.
        let mut text = Vec::with_capacity(blob.len() + blob.len() / 16 + 1);
        let mut previous = None;
        for &byte in blob {
            if byte == b'\n' && previous != Some(b'\r') {
                text.push(b'\r');
            }
            text.push(byte);
            previous = Some(byte);
        }
        text.push(0);
        let text = marshal::BytesIn::new(&text)?;
        let mut raw_error: *mut frida_sys::GError = std::ptr::null_mut();
        // SAFETY: frida-core is initialized; a GBytes that ends in a NUL.
        let raw = unsafe {
            frida_sys::frida_linux_system_map_from_blob(text.as_ptr(), &raw mut raw_error)
        };
        // SAFETY: NULL, or a new instance whose reference this takes.
        let map = unsafe { Self::from_glib_full(raw.cast()) };
        // SAFETY: the error the call set, if any, which this now owns.
        if let Some(error) = unsafe { marshal::take_error(raw_error) } {
            return Err(error);
        }
        marshal::non_null(map, "frida_linux_system_map_from_blob")
    }

    /// The `System.map` at `path`, read here and given to
    /// [`from_blob`](Self::from_blob).
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidArgument`](crate::gir::ErrorKind::InvalidArgument), with the
    /// I/O error as its source, if the file cannot be read; and those of
    /// [`from_blob`](Self::from_blob).
    pub fn open(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read(path).map_err(|error| {
            Error::with_source(
                crate::gir::ErrorKind::InvalidArgument,
                format!("cannot read {}: {error}", path.display()),
                error,
            )
        })?;
        Self::from_blob(&text)
    }
}
