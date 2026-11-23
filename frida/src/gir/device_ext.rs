/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Written by hand on top of the generated [`Device`].

use crate::gir::{
    Application, ApplicationQueryOptions, Cancellable, Device, Error, Process, ProcessQueryOptions,
    Scope,
};

impl Device {
    /// The device's processes, each carrying as much metadata as `scope` asks for: with
    /// [`Scope::Full`], [`Process::parameters`] holds the parent pid, path, user and so on.
    ///
    /// The same as [`enumerate_processes`](Self::enumerate_processes) with a
    /// [`ProcessQueryOptions`] of that scope.
    ///
    /// # Errors
    ///
    /// frida-core's, such as when the device is lost.
    pub fn enumerate_processes_with_scope(
        &self,
        scope: Scope,
        cancellable: Option<&Cancellable>,
    ) -> Result<Vec<Process>, Error> {
        self.enumerate_processes(Some(&ProcessQueryOptions::new().scope(scope)), cancellable)
    }

    /// The device's applications, each carrying as much metadata as `scope` asks for.
    ///
    /// The same as [`enumerate_applications`](Self::enumerate_applications) with an
    /// [`ApplicationQueryOptions`] of that scope.
    ///
    /// # Errors
    ///
    /// frida-core's, such as when the device is lost.
    pub fn enumerate_applications_with_scope(
        &self,
        scope: Scope,
        cancellable: Option<&Cancellable>,
    ) -> Result<Vec<Application>, Error> {
        self.enumerate_applications(
            Some(&ApplicationQueryOptions::new().scope(scope)),
            cancellable,
        )
    }
}
