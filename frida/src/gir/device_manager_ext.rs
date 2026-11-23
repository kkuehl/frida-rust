/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Written by hand on top of the generated [`DeviceManager`].

use std::time::Duration;

use crate::gir::{Device, DeviceManager, DeviceType, Error};

impl DeviceManager {
    /// The local device: [`get_device_by_type`](Self::get_device_by_type) with
    /// [`DeviceType::Local`], without waiting, and no cancellable.
    ///
    /// # Errors
    ///
    /// frida-core's, should the manager be closed, or have no local backend (one made
    /// with [`with_nonlocal_backends_only`](Self::with_nonlocal_backends_only)).
    pub fn get_local_device(&self) -> Result<Device, Error> {
        self.get_device_by_type(DeviceType::Local, Some(Duration::ZERO), None)
    }
}
