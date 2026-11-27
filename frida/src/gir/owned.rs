/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! [`Owned`]: the value that owns a resource frida-core holds open, and releases it when
//! dropped.
//!
//! # Owners and handles
//!
//! A handle, such as [`Session`](crate::gir::Session), is a reference to a frida-core
//! object: cloning it is cheap, and dropping one releases nothing, as others may still
//! use the object. frida-core hands handles out freely, in lists and signals.
//!
//! What a call *acquires* comes back as an [`Owned`] instead:
//! [`Device::attach`](crate::gir::Device::attach) returns an `Owned<Session>`, and
//! dropping it detaches the session, the way dropping a [`std::fs::File`] closes it. An
//! owner is not `Clone`: there is one per acquisition. It dereferences to its handle, so
//! every method of the handle is called on it directly, and cloning through it
//! (`owner.clone()`) gives a plain handle, which may outlive the owner; calls on it after
//! the release fail with an error.
//!
//! | Acquired by | Owner | Released on drop with |
//! |---|---|---|
//! | [`DeviceManager::new`](crate::gir::DeviceManager::new) and its variants | `Owned<DeviceManager>` | `close` |
//! | [`Device::attach`](crate::gir::Device::attach) | `Owned<Session>` | `detach` |
//! | [`Session::create_script`](crate::gir::Session::create_script) and `create_script_from_bytes` | `Owned<Script>` | `unload` |
//! | [`Session::join_portal`](crate::gir::Session::join_portal) | `Owned<PortalMembership>` | `terminate` |
//! | [`Injector::new`](crate::gir::Injector::new) and `new_inprocess` | `Owned<Injector>` | `close` |
//! | [`ControlService::new`](crate::gir::ControlService::new) | `Owned<ControlService>` | `stop` |
//! | [`PortalService::new`](crate::gir::PortalService::new) | `Owned<PortalService>` | `stop` |
//! | [`LanguageServer::new`](crate::gir::LanguageServer::new) | `Owned<LanguageServer>` | `stop` |
//! | [`FileMonitor::new`](crate::gir::FileMonitor::new) | `Owned<FileMonitor>` | `disable` |
//!
//! # Dropping, and releasing explicitly
//!
//! Each owner has the release as a method that consumes it and returns the error, such
//! as [`Owned::<Session>::detach`]: use it when the error matters, or to know the release
//! is complete when it returns. `Drop` cannot report an error, so it discards it, as
//! `File` does.
//!
//! `Drop` never blocks: it queues the release on frida-core's thread and returns. So it
//! cannot deadlock, whichever thread it runs on: on frida-core's own thread inside a
//! signal handler, where a blocking call would have to run a nested main loop under the
//! handler, the release runs once the handler has returned. It cannot panic either,
//! during unwinding or otherwise. The object stays alive, and frida-core initialized,
//! until the release has run. Releases queued from one thread run in the order they were
//! queued, so dropping a script's owner and then its session's unloads, then detaches.
//!
//! [`keep`](Owned::keep) gives up ownership without releasing, for a resource that should
//! stay open, such as an eternalized script.

use std::fmt;
use std::mem::ManuallyDrop;
use std::ops::Deref;

use crate::gir::ObjectType;

pub(crate) mod sealed {
    pub trait Sealed {}
}

/// A class whose objects an [`Owned`] can hold: one with a release, such as a
/// [`Session`](crate::gir::Session)'s `detach`. Implemented by the generated classes
/// only.
pub trait Release: ObjectType + sealed::Sealed {
    /// Starts the release of `object`, on frida-core's thread, without waiting for it.
    ///
    /// # Safety
    ///
    /// Called on frida-core's thread, with an instance of this class.
    #[doc(hidden)]
    unsafe fn start_release(object: *mut frida_sys::GObject);
}

/// Implements [`Release`] for a class: `$start` is called on frida-core's thread with the
/// object's pointer.
macro_rules! release {
    ($class:ty, |$object:ident| $start:expr) => {
        impl crate::gir::owned::sealed::Sealed for $class {}

        impl crate::gir::Release for $class {
            unsafe fn start_release($object: *mut frida_sys::GObject) {
                $start
            }
        }
    };
}

pub(crate) use release;

/// The value that owns a resource frida-core holds open, and releases it when dropped.
/// The [module](self) documentation says which calls return one, and how dropping works.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), frida::Error> {
/// use frida::{DeviceManager, Script};
///
/// let manager = DeviceManager::new()?;
/// let session = manager.get_local_device()?.attach(std::process::id(), None, None)?;
/// let script = session.create_script("1 + 1", None, None)?;
/// let handle: Script = script.handle().clone(); // a reference, which releases nothing
/// script.load(None)?;
/// script.unload(None)?; // consumes the owner, and reports the error
/// assert!(handle.is_destroyed());
/// // `session` and `manager` are released when they go out of scope.
/// # Ok(())
/// # }
/// ```
#[must_use = "dropping an Owned releases what it owns at once"]
pub struct Owned<T: Release> {
    handle: ManuallyDrop<T>,
}

impl<T: Release> Owned<T> {
    /// Takes ownership of what `handle` refers to, which the caller has just acquired.
    pub(crate) fn new(handle: T) -> Self {
        Self {
            handle: ManuallyDrop::new(handle),
        }
    }

    /// Gives up ownership without releasing: the resource stays open, and the handle is
    /// returned. It is released only by calling its release method on a handle, or by
    /// frida-core when the object goes.
    #[must_use = "the handle is the only way left to release it"]
    pub fn keep(self) -> T {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is never dropped, so the handle is taken out exactly once.
        unsafe { ManuallyDrop::take(&mut this.handle) }
    }

    /// A handle to what this owns, which does not own it.
    #[must_use]
    pub fn handle(&self) -> &T {
        &self.handle
    }
}

impl<T: Release> Deref for Owned<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.handle
    }
}

impl<T: Release> AsRef<T> for Owned<T> {
    fn as_ref(&self) -> &T {
        &self.handle
    }
}

impl<T: Release> Drop for Owned<T> {
    fn drop(&mut self) {
        // SAFETY: drop runs once, and nothing uses the handle after.
        let handle = unsafe { ManuallyDrop::take(&mut self.handle) };
        crate::gir::runtime::release_later(handle.as_object().clone(), T::start_release);
    }
}

impl<T: Release + fmt::Debug> fmt::Debug for Owned<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Owned").field(&*self.handle).finish()
    }
}
