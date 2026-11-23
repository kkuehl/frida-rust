/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! The Gio types frida-core's API mentions: handles, with only what using them takes.

use std::path::{Path, PathBuf};

use crate::gir::runtime::{Lease, object_type};
use crate::gir::{Error, ObjectType, marshal};

/// The handle's pointer, for its `Debug`.
macro_rules! debug_as_pointer {
    ($name:ident) => {
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_tuple(stringify!($name))
                    .field(&self.as_object().as_ptr())
                    .finish()
            }
        }
    };
}

object_type! {
    /// A `GCancellable`: hand one to a blocking call, then [`cancel`](Cancellable::cancel)
    /// it, from any thread, to make the call give up with an
    /// [`ErrorKind::Cancelled`](crate::gir::ErrorKind::Cancelled) error.
    pub struct Cancellable: frida_sys::GCancellable = frida_sys::g_cancellable_get_type;
    parent: crate::gir::Object;
    ancestors: [crate::gir::Object];
}

// SAFETY: GCancellable's state is behind a lock, and g_cancellable_cancel() may be called
// from any thread (GIO documents it so); its references are atomic like every GObject's.
unsafe impl Send for Cancellable {}
// SAFETY: as for Send.
unsafe impl Sync for Cancellable {}

impl Cancellable {
    /// A cancellable that has not been cancelled.
    ///
    /// # Errors
    ///
    /// Only once frida-core has been deinitialized, with [`deinit`](crate::gir::deinit).
    pub fn new() -> Result<Self, Error> {
        let _lease = Lease::new()?;
        // SAFETY: GIO's constructor, with frida-core (and so GLib) initialized.
        let raw = unsafe { frida_sys::g_cancellable_new() };
        // SAFETY: a new instance, whose reference this takes.
        marshal::non_null(unsafe { Self::from_glib_full(raw) }, "g_cancellable_new")
    }

    /// Cancels the operations using this cancellable. Doing it again does nothing.
    pub fn cancel(&self) {
        // SAFETY: a live cancellable; GIO makes this thread-safe.
        unsafe { frida_sys::g_cancellable_cancel(self.as_raw()) };
    }

    /// Whether it has been cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        // SAFETY: a live cancellable; GIO makes this thread-safe.
        unsafe { frida_sys::g_cancellable_is_cancelled(self.as_raw()) != 0 }
    }
}

impl std::fmt::Debug for Cancellable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cancellable")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

object_type! {
    /// A `GTlsCertificate`, such as the one an endpoint serves.
    pub struct TlsCertificate: frida_sys::GTlsCertificate = frida_sys::g_tls_certificate_get_type;
    parent: crate::gir::Object;
    ancestors: [crate::gir::Object];
}

// SAFETY: a GTlsCertificate does not change once created, and no method that would change
// it is exposed; its references are atomic.
unsafe impl Send for TlsCertificate {}
// SAFETY: as for Send.
unsafe impl Sync for TlsCertificate {}

impl TlsCertificate {
    /// A certificate, with its private key if `pem` holds one, from PEM text.
    ///
    /// # Errors
    ///
    /// GIO's error if the text is not a certificate, and
    /// [`ErrorKind::InvalidArgument`](crate::gir::ErrorKind::InvalidArgument) if it holds
    /// a NUL byte.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let _lease = Lease::new()?;
        let pem_raw = marshal::cstring(pem)?;
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        // SAFETY: a NUL-terminated string, with its length left to GIO (-1).
        let raw = unsafe {
            frida_sys::g_tls_certificate_new_from_pem(pem_raw.as_ptr(), -1, &raw mut error)
        };
        // SAFETY: the error the call set, if any, which this now owns.
        if let Some(error) = unsafe { marshal::take_error(error) } {
            // SAFETY: NULL, or a reference that is ours to give back.
            drop(unsafe { Self::from_glib_full(raw) });
            return Err(error);
        }
        // SAFETY: a new instance, whose reference this takes.
        marshal::non_null(
            unsafe { Self::from_glib_full(raw) },
            "g_tls_certificate_new_from_pem",
        )
    }
}

debug_as_pointer!(TlsCertificate);

object_type! {
    /// A `GIOStream`, such as a channel opened with
    /// [`Device::open_channel`](crate::gir::Device::open_channel). It is closed when its
    /// last reference goes. Reading and writing it is a later phase.
    pub struct IoStream: frida_sys::GIOStream = frida_sys::g_io_stream_get_type;
    parent: crate::gir::Object;
    ancestors: [crate::gir::Object];
}

// SAFETY: nothing but its references can be used from Rust, and those are atomic; its
// last unref runs on frida-core's thread, where its dispose closes it.
unsafe impl Send for IoStream {}
// SAFETY: as for Send.
unsafe impl Sync for IoStream {}

debug_as_pointer!(IoStream);

object_type! {
    /// A `GFile`: a path, for frida-core's asset roots.
    pub struct File: frida_sys::GFile = frida_sys::g_file_get_type;
    parent: crate::gir::Object;
    ancestors: [crate::gir::Object];
}

// SAFETY: a GFile is immutable, and GIO documents GFile objects as thread-safe.
unsafe impl Send for File {}
// SAFETY: as for Send.
unsafe impl Sync for File {}

impl File {
    /// The file at `path`. It need not exist.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidArgument`](crate::gir::ErrorKind::InvalidArgument) if the path
    /// is not UTF-8 or holds a NUL byte.
    pub fn for_path(path: &Path) -> Result<Self, Error> {
        let _lease = Lease::new()?;
        let path_raw = marshal::path(path)?;
        // SAFETY: a NUL-terminated path.
        let raw = unsafe { frida_sys::g_file_new_for_path(path_raw.as_ptr()) };
        // SAFETY: a new instance, whose reference this takes.
        marshal::non_null(unsafe { Self::from_glib_full(raw) }, "g_file_new_for_path")
    }

    /// The file's local path, if it has one.
    #[must_use]
    pub fn path(&self) -> Option<PathBuf> {
        // SAFETY: a live GFile; the result is a new string, or NULL.
        let raw = unsafe { frida_sys::g_file_get_path(self.as_raw()) };
        // SAFETY: NULL, or a string this owns.
        unsafe { marshal::string(raw, true) }.map(PathBuf::from)
    }
}

impl std::fmt::Debug for File {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("File").field(&self.path()).finish()
    }
}

object_type! {
    /// A `GSocketAddress`: the address a portal's peer connected from.
    pub struct SocketAddress: frida_sys::GSocketAddress = frida_sys::g_socket_address_get_type;
    parent: crate::gir::Object;
    ancestors: [crate::gir::Object];
}

// SAFETY: a GSocketAddress is immutable once constructed, and its references are atomic.
unsafe impl Send for SocketAddress {}
// SAFETY: as for Send.
unsafe impl Sync for SocketAddress {}

impl SocketAddress {
    /// The address as text, such as `192.0.2.1:27042`.
    #[must_use]
    pub fn to_text(&self) -> String {
        // SAFETY: every GSocketAddress implements GSocketConnectable; the result is a new
        // string.
        let raw = unsafe { frida_sys::g_socket_connectable_to_string(self.as_raw().cast()) };
        // SAFETY: NULL, or a string this owns.
        unsafe { marshal::string(raw, true) }.unwrap_or_default()
    }
}

impl std::fmt::Display for SocketAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_text())
    }
}

impl std::fmt::Debug for SocketAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SocketAddress")
            .field(&self.to_text())
            .finish()
    }
}

/// What a [`FileMonitor`](crate::gir::FileMonitor) saw happen: Gio's `GFileMonitorEvent`.
///
/// Raw values this version has no variant for convert to [`Self::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FileMonitorEvent {
    /// The file's contents changed.
    Changed,
    /// A hint that a series of changes is over.
    ChangesDoneHint,
    /// The file was deleted.
    Deleted,
    /// The file was created.
    Created,
    /// One of the file's attributes changed.
    AttributeChanged,
    /// The file's mount is about to be unmounted.
    PreUnmount,
    /// The file's mount was unmounted.
    Unmounted,
    /// The file was moved.
    Moved,
    /// The file was renamed within its directory.
    Renamed,
    /// The file was moved into the monitored directory.
    MovedIn,
    /// The file was moved out of the monitored directory.
    MovedOut,
    /// A raw value this version of the bindings has no name for.
    Unknown(i32),
}

impl FileMonitorEvent {
    /// The variant for `raw`. Never fails: an unknown value becomes [`Self::Unknown`].
    #[must_use]
    pub fn from_raw(raw: frida_sys::GFileMonitorEvent) -> Self {
        match raw {
            frida_sys::GFileMonitorEvent_G_FILE_MONITOR_EVENT_CHANGED => Self::Changed,
            frida_sys::GFileMonitorEvent_G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT => {
                Self::ChangesDoneHint
            }
            frida_sys::GFileMonitorEvent_G_FILE_MONITOR_EVENT_DELETED => Self::Deleted,
            frida_sys::GFileMonitorEvent_G_FILE_MONITOR_EVENT_CREATED => Self::Created,
            frida_sys::GFileMonitorEvent_G_FILE_MONITOR_EVENT_ATTRIBUTE_CHANGED => {
                Self::AttributeChanged
            }
            frida_sys::GFileMonitorEvent_G_FILE_MONITOR_EVENT_PRE_UNMOUNT => Self::PreUnmount,
            frida_sys::GFileMonitorEvent_G_FILE_MONITOR_EVENT_UNMOUNTED => Self::Unmounted,
            frida_sys::GFileMonitorEvent_G_FILE_MONITOR_EVENT_MOVED => Self::Moved,
            frida_sys::GFileMonitorEvent_G_FILE_MONITOR_EVENT_RENAMED => Self::Renamed,
            frida_sys::GFileMonitorEvent_G_FILE_MONITOR_EVENT_MOVED_IN => Self::MovedIn,
            frida_sys::GFileMonitorEvent_G_FILE_MONITOR_EVENT_MOVED_OUT => Self::MovedOut,
            other => Self::Unknown(other as i32),
        }
    }

    /// The raw `GFileMonitorEvent` value.
    #[must_use]
    pub fn into_raw(self) -> frida_sys::GFileMonitorEvent {
        match self {
            Self::Changed => frida_sys::GFileMonitorEvent_G_FILE_MONITOR_EVENT_CHANGED,
            Self::ChangesDoneHint => {
                frida_sys::GFileMonitorEvent_G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT
            }
            Self::Deleted => frida_sys::GFileMonitorEvent_G_FILE_MONITOR_EVENT_DELETED,
            Self::Created => frida_sys::GFileMonitorEvent_G_FILE_MONITOR_EVENT_CREATED,
            Self::AttributeChanged => {
                frida_sys::GFileMonitorEvent_G_FILE_MONITOR_EVENT_ATTRIBUTE_CHANGED
            }
            Self::PreUnmount => frida_sys::GFileMonitorEvent_G_FILE_MONITOR_EVENT_PRE_UNMOUNT,
            Self::Unmounted => frida_sys::GFileMonitorEvent_G_FILE_MONITOR_EVENT_UNMOUNTED,
            Self::Moved => frida_sys::GFileMonitorEvent_G_FILE_MONITOR_EVENT_MOVED,
            Self::Renamed => frida_sys::GFileMonitorEvent_G_FILE_MONITOR_EVENT_RENAMED,
            Self::MovedIn => frida_sys::GFileMonitorEvent_G_FILE_MONITOR_EVENT_MOVED_IN,
            Self::MovedOut => frida_sys::GFileMonitorEvent_G_FILE_MONITOR_EVENT_MOVED_OUT,
            Self::Unknown(raw) => raw as frida_sys::GFileMonitorEvent,
        }
    }
}
