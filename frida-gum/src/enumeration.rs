/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Plumbing for Gum's `enumerate` functions, which call back once per item with a pointer that
//! is valid only during the call.

use {
    core::ffi::CStr,
    frida_gum_sys::{gboolean, gchar, gpointer},
};

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

/// What an enumeration hands each item to. A thin pointer to one of these is the C callback's
/// user data, so no closure is boxed and none outlives the call.
pub(crate) type Sink<'a, Item> = &'a mut dyn FnMut(Item) -> bool;

/// The C callback for an enumeration of `Raw` details whose user data is a `*mut Sink<*const Raw>`.
pub(crate) unsafe extern "C" fn details_callout<Raw>(
    details: *const Raw,
    user_data: gpointer,
) -> gboolean {
    let sink = unsafe { &mut *(user_data as *mut Sink<'_, *const Raw>) };
    sink(details) as gboolean
}

/// Everything `enumerate` yields, collected.
pub(crate) fn collected<Item>(enumerate: impl FnOnce(&mut dyn FnMut(Item) -> bool)) -> Vec<Item> {
    let mut items = Vec::new();
    enumerate(&mut |item| {
        items.push(item);
        true
    });
    items
}

/// The text at `text`, or `None` for a null pointer.
///
/// # Safety
///
/// A non-null `text` must point at a NUL-terminated string.
pub(crate) unsafe fn string_at(text: *const gchar) -> Option<String> {
    if text.is_null() {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(text.cast()) }
            .to_string_lossy()
            .into_owned(),
    )
}
