/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Written by hand on top of the generated [`PatternValue`].

use crate::gir::{ObjectType, PatternValue};

impl PatternValue {
    /// The value, when it is a floating-point number: [`value`](Self::value) gives a
    /// [`Variant::Unsupported("d")`](crate::Variant::Unsupported) for one, as
    /// [`crate::Variant`] has no floating-point case.
    #[must_use]
    pub fn value_as_f64(&self) -> Option<f64> {
        // SAFETY: a live PatternValue; the variant is transfer none, alive while it is.
        let value = unsafe { frida_sys::frida_pattern_value_get_value(self.as_raw()) };
        if value.is_null() {
            return None;
        }
        // SAFETY: a live GVariant, whose type string is static.
        let signature =
            unsafe { std::ffi::CStr::from_ptr(frida_sys::g_variant_get_type_string(value)) };
        // SAFETY: a GVariant of type "d".
        (signature.to_bytes() == b"d").then(|| unsafe { frida_sys::g_variant_get_double(value) })
    }
}
