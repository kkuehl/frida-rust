/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Cross-platform GLib symbol shims.
//!
//! Frida's static devkit exposes GLib helpers under their bare `g_*` names on
//! Windows, macOS, and iOS, but under a `_frida_g_*` prefix on the Linux/FreeBSD
//! devkits (to avoid clashing with a system GLib). `frida-gum-sys` therefore
//! only generates bindings for whichever name the current target's devkit
//! provides. This module papers over that difference so the rest of the crate
//! can call a single stable name regardless of platform (mirroring the existing
//! `_frida_g_get_*_dir` handling in [`crate::process`]).

use frida_gum_sys::{
    GArray, GBytes, GDestroyNotify, GError, GInterfaceInfo, GObject, GPtrArray, GType, gboolean,
    gchar, gconstpointer, gpointer, gsize, guint,
};

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod sys {
    pub use frida_gum_sys::{
        _frida_g_array_free as g_array_free, _frida_g_bytes_get_data as g_bytes_get_data,
        _frida_g_bytes_new as g_bytes_new, _frida_g_bytes_unref as g_bytes_unref,
        _frida_g_error_free as g_error_free, _frida_g_free as g_free,
        _frida_g_object_get_data as g_object_get_data, _frida_g_object_new as g_object_new,
        _frida_g_object_set_data_full as g_object_set_data_full,
        _frida_g_ptr_array_add as g_ptr_array_add, _frida_g_ptr_array_free as g_ptr_array_free,
        _frida_g_ptr_array_sized_new as g_ptr_array_sized_new,
        _frida_g_type_add_interface_static as g_type_add_interface_static,
        _frida_g_type_register_static_simple as g_type_register_static_simple,
    };
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
mod sys {
    pub use frida_gum_sys::{
        g_array_free, g_bytes_get_data, g_bytes_new, g_bytes_unref, g_error_free, g_free,
        g_object_get_data, g_object_new, g_object_set_data_full, g_ptr_array_add, g_ptr_array_free,
        g_ptr_array_sized_new, g_type_add_interface_static, g_type_register_static_simple,
    };
}

/// Free a block previously allocated by GLib.
///
/// # Safety
///
/// `mem` must have been returned by a GLib allocation and not yet freed.
pub unsafe fn g_free(mem: gpointer) {
    unsafe { sys::g_free(mem) }
}

/// Free a `GError`.
///
/// # Safety
///
/// `error` must be a valid `GError` that has not already been freed.
pub unsafe fn g_error_free(error: *mut GError) {
    unsafe { sys::g_error_free(error) }
}

/// Create a `GBytes` holding a copy of `size` bytes at `data`.
///
/// # Safety
///
/// `data` must be readable for `size` bytes.
pub unsafe fn g_bytes_new(data: gconstpointer, size: gsize) -> *mut GBytes {
    unsafe { sys::g_bytes_new(data, size) }
}

/// The data a `GBytes` holds, with its length written to `size`.
///
/// # Safety
///
/// `bytes` must be a valid `GBytes` and `size` writable.
pub unsafe fn g_bytes_get_data(bytes: *mut GBytes, size: *mut gsize) -> gconstpointer {
    unsafe { sys::g_bytes_get_data(bytes, size) }
}

/// Release a reference to a `GBytes`.
///
/// # Safety
///
/// `bytes` must be a valid `GBytes` the caller holds a reference to.
pub unsafe fn g_bytes_unref(bytes: *mut GBytes) {
    unsafe { sys::g_bytes_unref(bytes) }
}

/// Free a `GArray`, optionally freeing the element segment.
///
/// # Safety
///
/// `array` must be a valid `GArray` that has not already been freed.
pub unsafe fn g_array_free(array: *mut GArray, free_segment: gboolean) -> *mut gchar {
    unsafe { sys::g_array_free(array, free_segment) }
}

/// Allocate a `GPtrArray` with space reserved for `reserved_size` elements.
pub fn g_ptr_array_sized_new(reserved_size: guint) -> *mut GPtrArray {
    unsafe { sys::g_ptr_array_sized_new(reserved_size) }
}

/// Append a pointer to a `GPtrArray`.
///
/// # Safety
///
/// `array` must be a valid `GPtrArray`.
pub unsafe fn g_ptr_array_add(array: *mut GPtrArray, data: gpointer) {
    unsafe { sys::g_ptr_array_add(array, data) }
}

/// Free a `GPtrArray`, optionally freeing the underlying segment.
///
/// # Safety
///
/// `array` must be a valid `GPtrArray` that has not already been freed.
pub unsafe fn g_ptr_array_free(array: *mut GPtrArray, free_seg: gboolean) -> *mut gpointer {
    unsafe { sys::g_ptr_array_free(array, free_seg) }
}

/// Register a type derived from `GObject` that adds nothing to it, to implement interfaces
/// with. Returns zero if `type_name` is taken.
///
/// # Safety
///
/// `type_name` must be a NUL-terminated string.
pub unsafe fn g_object_subtype_register(type_name: *const gchar) -> GType {
    /// `G_TYPE_OBJECT`: the twentieth fundamental type.
    const G_TYPE_OBJECT: GType = 20 << frida_gum_sys::G_TYPE_FUNDAMENTAL_SHIFT;

    unsafe {
        sys::g_type_register_static_simple(
            G_TYPE_OBJECT,
            type_name,
            core::mem::size_of::<frida_gum_sys::GObjectClass>() as guint,
            None,
            core::mem::size_of::<GObject>() as guint,
            None,
            0,
        )
    }
}

/// Have `instance_type` implement `interface_type` as `info` says.
///
/// # Safety
///
/// Both must be registered types, and `instance_type` must have no instances yet.
pub unsafe fn g_type_add_interface_static(
    instance_type: GType,
    interface_type: GType,
    info: &GInterfaceInfo,
) {
    unsafe { sys::g_type_add_interface_static(instance_type, interface_type, info) }
}

/// Create an object of `object_type` with every property at its default.
///
/// # Safety
///
/// `object_type` must be a registered type derived from `GObject`.
pub unsafe fn g_object_new(object_type: GType) -> *mut GObject {
    unsafe { sys::g_object_new(object_type, core::ptr::null()).cast() }
}

/// Attach `data` to `object` under `key`, to be passed to `destroy` when the object is
/// finalized or the data replaced.
///
/// # Safety
///
/// `object` must be a valid object and `key` a NUL-terminated string.
pub unsafe fn g_object_set_data_full(
    object: *mut GObject,
    key: *const gchar,
    data: gpointer,
    destroy: GDestroyNotify,
) {
    unsafe { sys::g_object_set_data_full(object, key, data, destroy) }
}

/// The data attached to `object` under `key`, or null.
///
/// # Safety
///
/// `object` must be a valid object and `key` a NUL-terminated string.
pub unsafe fn g_object_get_data(object: *mut GObject, key: *const gchar) -> gpointer {
    unsafe { sys::g_object_get_data(object, key) }
}
