/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! [`Inject`]: what a [`Device`] and an [`Injector`] have in common, for code that injects
//! a library with either.

use std::path::Path;

use crate::gir::{Cancellable, Device, Error, Injector};

/// Injects a library into a process: a [`Device`], or an [`Injector`].
///
/// Each returns the injection's id, which the device's or injector's `uninjected` signal
/// names when the library unloads.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), frida::Error> {
/// use frida::{DeviceManager, Inject, Injector};
/// use std::path::Path;
///
/// fn inject(into: &impl Inject, pid: u32) -> Result<u32, frida::Error> {
///     into.inject_library_file(pid, Path::new("/tmp/agent.so"), "agent_main", "", None)
/// }
///
/// let manager = DeviceManager::new()?;
/// inject(&manager.get_local_device()?, 1234)?;
/// inject(&*Injector::new()?, 1234)?;
/// # Ok(())
/// # }
/// ```
pub trait Inject {
    /// Injects the library at `path`, and calls `entrypoint` in it with `data`.
    ///
    /// # Errors
    ///
    /// frida-core's, such as for a process that is gone, and
    /// [`ErrorKind::InvalidArgument`](crate::gir::ErrorKind::InvalidArgument) for a
    /// string or path that cannot be passed to C.
    fn inject_library_file(
        &self,
        pid: u32,
        path: &Path,
        entrypoint: &str,
        data: &str,
        cancellable: Option<&Cancellable>,
    ) -> Result<u32, Error>;

    /// Injects the library in `blob`, and calls `entrypoint` in it with `data`.
    ///
    /// # Errors
    ///
    /// As [`inject_library_file`](Self::inject_library_file).
    fn inject_library_blob(
        &self,
        pid: u32,
        blob: &[u8],
        entrypoint: &str,
        data: &str,
        cancellable: Option<&Cancellable>,
    ) -> Result<u32, Error>;
}

/// The path is one on the device, which may run another system: it is passed as text.
impl Inject for Device {
    fn inject_library_file(
        &self,
        pid: u32,
        path: &Path,
        entrypoint: &str,
        data: &str,
        cancellable: Option<&Cancellable>,
    ) -> Result<u32, Error> {
        let Some(path) = path.to_str() else {
            return Err(Error::invalid_argument(format!(
                "the path {} is not UTF-8, which frida-core needs",
                path.display()
            )));
        };
        Device::inject_library_file(self, pid, path, entrypoint, data, cancellable)
    }

    fn inject_library_blob(
        &self,
        pid: u32,
        blob: &[u8],
        entrypoint: &str,
        data: &str,
        cancellable: Option<&Cancellable>,
    ) -> Result<u32, Error> {
        Device::inject_library_blob(self, pid, blob, entrypoint, data, cancellable)
    }
}

impl Inject for Injector {
    fn inject_library_file(
        &self,
        pid: u32,
        path: &Path,
        entrypoint: &str,
        data: &str,
        cancellable: Option<&Cancellable>,
    ) -> Result<u32, Error> {
        Injector::inject_library_file(self, pid, path, entrypoint, data, cancellable)
    }

    fn inject_library_blob(
        &self,
        pid: u32,
        blob: &[u8],
        entrypoint: &str,
        data: &str,
        cancellable: Option<&Cancellable>,
    ) -> Result<u32, Error> {
        Injector::inject_library_blob(self, pid, blob, entrypoint, data, cancellable)
    }
}
