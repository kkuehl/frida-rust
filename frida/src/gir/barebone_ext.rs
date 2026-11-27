/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Written by hand on top of the generated [`BareboneInjectedAgentConfig`].

use std::path::Path;

use crate::gir::runtime::Lease;
use crate::gir::{BareboneInjectedAgentConfig, BareboneInjectingTransportConfig, Error, marshal};

impl BareboneInjectedAgentConfig {
    /// The agent at `path`, read the way frida-core reads it (`map_agent_file`), with
    /// `transport`.
    ///
    /// # Errors
    ///
    /// frida-core's, if the file cannot be read, and
    /// [`ErrorKind::InvalidArgument`](crate::gir::ErrorKind::InvalidArgument) if the path
    /// is not UTF-8 or holds a NUL byte.
    pub fn from_file(
        path: &Path,
        transport: impl Into<BareboneInjectingTransportConfig>,
    ) -> Result<Self, Error> {
        let _lease = Lease::new()?;
        let path_raw = marshal::path(path)?;
        let mut raw_error: *mut frida_sys::GError = std::ptr::null_mut();
        // SAFETY: frida-core is initialized; a NUL-terminated path, and no transport, which
        // is set on the value instead.
        let raw = unsafe {
            frida_sys::frida_barebone_injected_agent_config_new_from_file(
                path_raw.as_ptr(),
                std::ptr::null_mut(),
                &raw mut raw_error,
            )
        };
        // SAFETY: NULL, or a new instance whose reference this takes, freed on return.
        let object =
            unsafe { <crate::gir::Object as crate::gir::ObjectType>::from_glib_full(raw.cast()) };
        // SAFETY: the error the call set, if any, which this now owns.
        if let Some(error) = unsafe { marshal::take_error(raw_error) } {
            return Err(error);
        }
        let object =
            marshal::non_null(object, "frida_barebone_injected_agent_config_new_from_file")?;
        // SAFETY: a live BareboneInjectedAgentConfig; `image` is transfer none.
        let image = unsafe {
            marshal::bytes(
                frida_sys::frida_barebone_injected_agent_config_get_image(object.as_ptr().cast()),
                false,
            )
        };
        Ok(Self::new()
            .image(image.unwrap_or_default())
            .transport(transport))
    }
}
