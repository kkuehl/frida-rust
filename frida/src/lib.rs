/*
 * Copyright © 2020-2022 Keegan Saunders
 * Copyright © 2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Frida bindings for Rust.

#![deny(warnings)]
#![deny(missing_docs)]
#![allow(clippy::missing_safety_doc)]

use std::ffi::CStr;

/// The code and message of a `GError` frida-core returned, and free it.
pub(crate) unsafe fn take_gerror(error: *mut frida_sys::GError) -> (i32, String) {
    let code = unsafe { (*error).code };
    let message = unsafe { (*error).message };
    let message = if message.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(message) }
            .to_string_lossy()
            .into_owned()
    };
    unsafe { frida_sys::g_error_free(error) };
    (code, message)
}

mod barebone;
pub use barebone::*;

mod binary_metadata;
pub use binary_metadata::*;

mod compiler;
pub use compiler::*;

mod application;
pub use application::*;

mod device;
pub use device::*;

mod device_manager;
pub use device_manager::*;

mod error;
pub use error::Error;

mod injector;
pub use injector::*;

mod kernel;
pub use kernel::*;

mod language_server;
pub use language_server::*;

mod pattern;
pub use pattern::*;

mod process;
pub use process::*;

mod script;
pub use script::*;

mod session;
pub use session::*;

mod variant;
pub use variant::*;

#[doc(hidden)]
pub type Result<T> = std::result::Result<T, error::Error>;

/// Context required for instantiation of all structures under the Frida namespace.
pub struct Frida;

impl Frida {
    /// Obtain a Frida handle, ensuring that the runtime is properly initialized. This may
    /// be called as many times as needed, and results in a no-op if the Frida runtime is
    /// already initialized.
    pub unsafe fn obtain() -> Frida {
        unsafe {
            frida_sys::frida_init();
            Frida {}
        }
    }

    /// Gets the current version of frida core
    pub fn version() -> &'static str {
        let version = unsafe { CStr::from_ptr(frida_sys::frida_version_string() as _) };
        version.to_str().unwrap_or_default()
    }

    /// Schedules the closure to be executed on the main frida context.
    pub fn schedule_on_main<F>(&self, func: F)
    where
        F: FnOnce() + Send + 'static,
    {
        unsafe {
            unsafe extern "C" fn trampoline<F: FnOnce() + Send + 'static>(
                func: frida_sys::gpointer,
            ) -> frida_sys::gboolean {
                let func: &mut Option<F> = unsafe { &mut *(func as *mut Option<F>) };
                if let Some(func) = func.take() {
                    // A panic must not unwind into GLib's C frames. The default
                    // hook has reported it by the time it is caught here.
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(func));
                }
                frida_sys::G_SOURCE_REMOVE as frida_sys::gboolean
            }
            unsafe extern "C" fn destroy_closure<F: FnOnce() + Send + 'static>(
                ptr: frida_sys::gpointer,
            ) {
                unsafe {
                    let _ = Box::<Option<F>>::from_raw(ptr as *mut _);
                }
            }

            let func = Box::into_raw(Box::new(Some(func)));
            let source = frida_sys::g_idle_source_new();
            let ctx = frida_sys::frida_get_main_context();

            frida_sys::g_source_set_callback(
                source,
                Some(trampoline::<F>),
                func as frida_sys::gpointer,
                Some(destroy_closure::<F>),
            );
            frida_sys::g_source_attach(source, ctx);
            frida_sys::g_source_unref(source);
        }
    }
}

impl Drop for Frida {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_deinit() };
    }
}

/// Checks that the enums mapped from frida-core's values name every value the
/// linked frida-core has, so that a new one in a later release is not quietly
/// read as one of the old ones.
#[cfg(test)]
mod enum_coverage {
    /// The enumerators of the C enum `name` in the committed frida-core.h,
    /// which a FRIDA_VERSION bump updates with the devkit.
    fn enumerators(name: &str) -> Vec<String> {
        let header = include_str!("../../frida-sys/include/frida-core.h");
        let end = header
            .find(&format!("}} {name};"))
            .unwrap_or_else(|| panic!("{name} is not in frida-core.h"));
        let start = header[..end].rfind("typedef enum {").unwrap() + "typedef enum {".len();
        header[start..end]
            .split(',')
            .map(|item| item.split('=').next().unwrap().trim().to_string())
            .filter(|item| !item.is_empty())
            .collect()
    }

    /// `count` raw values map to `count` different variants, and the header
    /// has exactly `count` values.
    fn check<T: PartialEq + std::fmt::Debug>(name: &str, mapped: &[(u32, T)]) {
        let values = enumerators(name);
        assert_eq!(
            values.len(),
            mapped.len(),
            "{name} has {values:?}; map each one in its from_raw and list it here"
        );
        for (i, (raw, variant)) in mapped.iter().enumerate() {
            assert_eq!(*raw as usize, i, "{name}: {variant:?}");
            for (_, other) in &mapped[..i] {
                assert_ne!(other, variant, "{name}: two values map to {variant:?}");
            }
        }
    }

    macro_rules! coverage {
        ($test:ident, $c:literal, $from:expr, [$($raw:path),* $(,)?]) => {
            #[test]
            fn $test() {
                check($c, &[$(($raw as u32, $from($raw))),*]);
            }
        };
    }

    use crate::barebone::BareboneStubFlavor;
    use crate::pattern::{
        PatternBitKind, PatternByteOrder, PatternTypeKind, PatternTypeRefKind,
        PatternVisualizerArgumentKind, PatternVisualizerPresentation,
    };
    use frida_sys::*;

    coverage!(
        barebone_stub_flavor,
        "FridaBareboneStubFlavor",
        BareboneStubFlavor::from_raw,
        [
            FridaBareboneStubFlavor_FRIDA_BAREBONE_STUB_FLAVOR_GDB_REMOTE,
            FridaBareboneStubFlavor_FRIDA_BAREBONE_STUB_FLAVOR_VZ,
            FridaBareboneStubFlavor_FRIDA_BAREBONE_STUB_FLAVOR_PARALLELS,
            FridaBareboneStubFlavor_FRIDA_BAREBONE_STUB_FLAVOR_ANDROID_EMULATOR,
            FridaBareboneStubFlavor_FRIDA_BAREBONE_STUB_FLAVOR_VIRTUALBOX,
            FridaBareboneStubFlavor_FRIDA_BAREBONE_STUB_FLAVOR_VIRTUALBOX_CONSOLE,
        ]
    );
    coverage!(
        source_maps,
        "FridaSourceMaps",
        crate::compiler::source_maps_from_raw,
        [
            FridaSourceMaps_FRIDA_SOURCE_MAPS_INCLUDED,
            FridaSourceMaps_FRIDA_SOURCE_MAPS_OMITTED,
        ]
    );
    coverage!(
        pattern_type_kind,
        "FridaPatternTypeKind",
        PatternTypeKind::from_raw,
        [
            FridaPatternTypeKind_FRIDA_PATTERN_TYPE_KIND_STRUCT,
            FridaPatternTypeKind_FRIDA_PATTERN_TYPE_KIND_UNION,
            FridaPatternTypeKind_FRIDA_PATTERN_TYPE_KIND_ENUM,
            FridaPatternTypeKind_FRIDA_PATTERN_TYPE_KIND_BITFIELD,
            FridaPatternTypeKind_FRIDA_PATTERN_TYPE_KIND_ALIAS,
        ]
    );
    coverage!(
        pattern_type_ref_kind,
        "FridaPatternTypeRefKind",
        PatternTypeRefKind::from_raw,
        [
            FridaPatternTypeRefKind_FRIDA_PATTERN_TYPE_REF_KIND_PRIMITIVE,
            FridaPatternTypeRefKind_FRIDA_PATTERN_TYPE_REF_KIND_NAMED,
            FridaPatternTypeRefKind_FRIDA_PATTERN_TYPE_REF_KIND_POINTER,
            FridaPatternTypeRefKind_FRIDA_PATTERN_TYPE_REF_KIND_ARRAY,
            FridaPatternTypeRefKind_FRIDA_PATTERN_TYPE_REF_KIND_PADDING,
        ]
    );
    coverage!(
        pattern_byte_order,
        "FridaPatternByteOrder",
        PatternByteOrder::from_raw,
        [
            FridaPatternByteOrder_FRIDA_PATTERN_BYTE_ORDER_NATIVE,
            FridaPatternByteOrder_FRIDA_PATTERN_BYTE_ORDER_LITTLE,
            FridaPatternByteOrder_FRIDA_PATTERN_BYTE_ORDER_BIG,
        ]
    );
    coverage!(
        pattern_bit_kind,
        "FridaPatternBitKind",
        PatternBitKind::from_raw,
        [
            FridaPatternBitKind_FRIDA_PATTERN_BIT_KIND_UNSIGNED,
            FridaPatternBitKind_FRIDA_PATTERN_BIT_KIND_SIGNED,
            FridaPatternBitKind_FRIDA_PATTERN_BIT_KIND_BOOL,
            FridaPatternBitKind_FRIDA_PATTERN_BIT_KIND_ENUM,
        ]
    );
    coverage!(
        pattern_visualizer_presentation,
        "FridaPatternVisualizerPresentation",
        PatternVisualizerPresentation::from_raw,
        [
            FridaPatternVisualizerPresentation_FRIDA_PATTERN_VISUALIZER_PRESENTATION_DETACHED,
            FridaPatternVisualizerPresentation_FRIDA_PATTERN_VISUALIZER_PRESENTATION_INLINE,
        ]
    );
    coverage!(
        pattern_visualizer_argument_kind,
        "FridaPatternVisualizerArgumentKind",
        PatternVisualizerArgumentKind::from_raw,
        [
            FridaPatternVisualizerArgumentKind_FRIDA_PATTERN_VISUALIZER_ARGUMENT_KIND_VALUE,
            FridaPatternVisualizerArgumentKind_FRIDA_PATTERN_VISUALIZER_ARGUMENT_KIND_PATTERN,
        ]
    );
}
