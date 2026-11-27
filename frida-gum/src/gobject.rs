/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Giving Gum an object that implements one of its interfaces with Rust code: a plain `GObject`
//! subtype whose interface functions find a Rust value attached to the object.

use {
    crate::glib_compat,
    core::ffi::c_void,
    frida_gum_sys::{GInterfaceInfo, GObject, GType, gchar, gpointer},
};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format};

/// The key the Rust value is attached to its object under.
const DATA_KEY: &[u8] = b"frida-rust-data\0";

/// A type that implements one Gum interface, registered the first time it is asked for.
pub(crate) struct InterfaceType {
    registered: spin::Mutex<GType>,
}

impl InterfaceType {
    pub(crate) const fn new() -> Self {
        Self {
            registered: spin::Mutex::new(0),
        }
    }

    /// The type, which implements `interface_type` with the functions `interface_init` puts in
    /// the interface's table. `name` only has to tell this type from others in this crate.
    pub(crate) fn get(
        &self,
        name: &str,
        interface_type: GType,
        interface_init: unsafe extern "C" fn(gpointer, gpointer),
    ) -> GType {
        let mut registered = self.registered.lock();
        if *registered == 0 {
            // Type names are per process, and another copy of this crate in the process would
            // register the same ones for its own functions. The address of this static tells
            // the copies apart.
            let name = format!("FridaRust{name}{:x}\0", self as *const Self as usize);
            let info = GInterfaceInfo {
                interface_init: Some(interface_init),
                interface_finalize: None,
                interface_data: core::ptr::null_mut(),
            };
            // SAFETY: the name is NUL-terminated, and the type is new, so it has no instances.
            unsafe {
                *registered = glib_compat::g_object_subtype_register(name.as_ptr().cast());
                glib_compat::g_type_add_interface_static(*registered, interface_type, &info);
            }
        }
        *registered
    }
}

unsafe extern "C" fn destroy_data<T>(data: gpointer) {
    drop(unsafe { Box::from_raw(data as *mut T) });
}

/// A new object of `object_type` that owns `data`. The caller owns the one reference to it.
///
/// # Safety
///
/// `object_type` must be a type an [`InterfaceType`] returned.
pub(crate) unsafe fn new_object<T>(object_type: GType, data: T) -> *mut GObject {
    unsafe {
        let object = glib_compat::g_object_new(object_type);
        glib_compat::g_object_set_data_full(
            object,
            DATA_KEY.as_ptr() as *const gchar,
            Box::into_raw(Box::new(data)) as *mut c_void,
            Some(destroy_data::<T>),
        );
        object
    }
}

/// The value [`new_object`] gave `object`.
///
/// # Safety
///
/// `object` must have been made by `new_object::<T>` and be alive for `'a`.
pub(crate) unsafe fn data<'a, T>(object: *mut GObject) -> &'a T {
    unsafe {
        &*(glib_compat::g_object_get_data(object, DATA_KEY.as_ptr() as *const gchar) as *const T)
    }
}
