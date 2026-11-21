/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Bindings to `Frida.PatternCompiler`: compile a pattern language source into the types it
//! declares, laid out for a target, and decode bytes read from that target as one of them.
//!
//! ```no_run
//! use frida::{Frida, PatternCompiler};
//!
//! let _frida = unsafe { Frida::obtain() };
//! let module = PatternCompiler::new().compile("player.pat", None).unwrap();
//! for diagnostic in module.diagnostics() {
//!     eprintln!("{}:{}: {}", diagnostic.file(), diagnostic.line(), diagnostic.message());
//! }
//! let player = module.decode("Player", &[0; 32], 0x1000, None).unwrap();
//! for field in player.fields() {
//!     println!("{} = {:?}", field.name(), field.value());
//! }
//! ```
//!
//! Only the blocking forms of `compile`, `decode` and `call_function` are bound, as with the
//! rest of this crate.

use frida_sys::{GBytes, GError, GHashTable, GVariant};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use crate::error::{string_at, take_gerror};
use crate::{Error, Result, Variant};

/// The text at `text`, or an empty string for a null pointer.
unsafe fn text_at(text: *const c_char) -> String {
    unsafe { string_at(text) }.unwrap_or_default()
}

/// The error a pattern operation left in `error`.
unsafe fn pattern_error(error: *mut GError) -> Error {
    let (code, message) = unsafe { take_gerror(error) };
    Error::PatternFailed { code, message }
}

fn c_string(text: &str) -> Result<CString> {
    CString::new(text).map_err(|_| Error::CStringFailed)
}

/// A new `GBytes` holding a copy of `bytes`, for the caller to unref.
fn blob_of(bytes: &[u8]) -> *mut GBytes {
    unsafe { frida_sys::g_bytes_new(bytes.as_ptr().cast(), bytes.len() as _) }
}

unsafe extern "C" fn unref_variant(variant: frida_sys::gpointer) {
    unsafe { frida_sys::g_variant_unref(variant.cast()) };
}

/// A new table of `values` by name, as Frida keeps defines and inputs, for the caller to unref.
/// A value can be a string, a boolean or an integer.
fn parameters_table(values: &HashMap<String, Variant>) -> Result<*mut GHashTable> {
    let mut entries = Vec::with_capacity(values.len());
    for (name, value) in values {
        let name = c_string(name)?;
        let value = match value {
            Variant::String(text) => {
                let text = c_string(text)?;
                unsafe { frida_sys::g_variant_new_string(text.as_ptr()) }
            }
            Variant::Boolean(flag) => unsafe { frida_sys::g_variant_new_boolean(*flag as _) },
            Variant::Int64(number) => unsafe { frida_sys::g_variant_new_int64(*number) },
            other => {
                return Err(Error::PatternFailed {
                    code: 0,
                    message: format!(
                        "{} is {other:?}, where a string, a boolean or an integer is needed",
                        name.to_string_lossy()
                    ),
                });
            }
        };
        entries.push((name, value));
    }

    unsafe {
        let table = frida_sys::g_hash_table_new_full(
            Some(frida_sys::g_str_hash),
            Some(frida_sys::g_str_equal),
            Some(frida_sys::g_free),
            Some(unref_variant),
        );
        for (name, value) in entries {
            frida_sys::g_hash_table_insert(
                table,
                frida_sys::g_strdup(name.as_ptr()).cast(),
                frida_sys::g_variant_ref_sink(value).cast(),
            );
        }
        Ok(table)
    }
}

/// What is in a table of values by name that Frida keeps.
unsafe fn parameters_of(table: *mut GHashTable) -> HashMap<String, Variant> {
    let mut values = HashMap::new();
    if table.is_null() {
        return values;
    }
    unsafe {
        let mut iter: frida_sys::GHashTableIter = std::mem::zeroed();
        let mut name: frida_sys::gpointer = std::ptr::null_mut();
        let mut value: frida_sys::gpointer = std::ptr::null_mut();
        frida_sys::g_hash_table_iter_init(&mut iter, table);
        while frida_sys::g_hash_table_iter_next(&mut iter, &mut name, &mut value) != 0 {
            values.insert(
                text_at(name as *const c_char),
                Variant::from_ptr(value.cast()),
            );
        }
    }
    values
}

/// The value in `variant`, which the caller borrows, or `None` for a null pointer.
unsafe fn variant_at(variant: *mut GVariant) -> Option<Variant> {
    (!variant.is_null()).then(|| unsafe { Variant::from_ptr(variant) })
}

/// The value in `variant`, which the caller owns.
unsafe fn variant_from_owned(variant: *mut GVariant) -> Variant {
    unsafe {
        let value = Variant::from_ptr(variant);
        frida_sys::g_variant_unref(variant);
        value
    }
}

/// Defines a handle to one of the pattern compiler's objects, which holds a reference to it.
macro_rules! pattern_object {
    ($(#[$doc:meta])* $name:ident, $raw:ident) => {
        $(#[$doc])*
        pub struct $name {
            ptr: *mut frida_sys::$raw,
        }

        impl $name {
            /// Takes over the caller's reference to `ptr`.
            #[allow(dead_code)]
            unsafe fn from_owned(ptr: *mut frida_sys::$raw) -> Self {
                Self { ptr }
            }

            /// Takes a reference of its own to `ptr`, which the caller borrows. `None` for a
            /// null pointer.
            #[allow(dead_code)]
            unsafe fn from_borrowed(ptr: *mut frida_sys::$raw) -> Option<Self> {
                if ptr.is_null() {
                    return None;
                }
                unsafe { frida_sys::g_object_ref(ptr.cast()) };
                Some(Self { ptr })
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                unsafe { frida_sys::frida_unref(self.ptr as _) }
            }
        }
    };
}

/// Every item of a list that one of the pattern compiler's objects lends out.
macro_rules! items_of {
    ($list:expr, $size:ident, $get:ident, $item:ident) => {{
        let list = $list;
        let count = unsafe { frida_sys::$size(list) };
        (0..count)
            .map(|index| unsafe { $item::from_owned(frida_sys::$get(list, index)) })
            .collect()
    }};
}

/// What kind of type a [`PatternType`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternTypeKind {
    /// A struct.
    Struct,
    /// A union.
    Union,
    /// An enum.
    Enum,
    /// A bitfield.
    Bitfield,
    /// Another name for a type.
    Alias,
}

impl PatternTypeKind {
    pub(crate) fn from_raw(raw: frida_sys::FridaPatternTypeKind) -> Self {
        match raw {
            frida_sys::FridaPatternTypeKind_FRIDA_PATTERN_TYPE_KIND_UNION => Self::Union,
            frida_sys::FridaPatternTypeKind_FRIDA_PATTERN_TYPE_KIND_ENUM => Self::Enum,
            frida_sys::FridaPatternTypeKind_FRIDA_PATTERN_TYPE_KIND_BITFIELD => Self::Bitfield,
            frida_sys::FridaPatternTypeKind_FRIDA_PATTERN_TYPE_KIND_ALIAS => Self::Alias,
            frida_sys::FridaPatternTypeKind_FRIDA_PATTERN_TYPE_KIND_STRUCT => Self::Struct,
            // Every value the linked frida-core has is named above, which
            // `enum_coverage` checks against its header. The enum has no
            // variant for a value from some other version.
            _ => Self::Struct,
        }
    }
}

/// What kind of reference to a type a [`PatternTypeRef`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternTypeRefKind {
    /// A built-in type, such as `u32`.
    Primitive,
    /// A declared type, by name.
    Named,
    /// A pointer to a type.
    Pointer,
    /// An array of a type.
    Array,
    /// Padding.
    Padding,
}

impl PatternTypeRefKind {
    pub(crate) fn from_raw(raw: frida_sys::FridaPatternTypeRefKind) -> Self {
        match raw {
            frida_sys::FridaPatternTypeRefKind_FRIDA_PATTERN_TYPE_REF_KIND_NAMED => Self::Named,
            frida_sys::FridaPatternTypeRefKind_FRIDA_PATTERN_TYPE_REF_KIND_POINTER => Self::Pointer,
            frida_sys::FridaPatternTypeRefKind_FRIDA_PATTERN_TYPE_REF_KIND_ARRAY => Self::Array,
            frida_sys::FridaPatternTypeRefKind_FRIDA_PATTERN_TYPE_REF_KIND_PADDING => Self::Padding,
            frida_sys::FridaPatternTypeRefKind_FRIDA_PATTERN_TYPE_REF_KIND_PRIMITIVE => {
                Self::Primitive
            }
            // Every value the linked frida-core has is named above, which
            // `enum_coverage` checks against its header. The enum has no
            // variant for a value from some other version.
            _ => Self::Primitive,
        }
    }
}

/// The byte order a value is stored in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternByteOrder {
    /// The target's own.
    Native,
    /// Least significant byte first.
    Little,
    /// Most significant byte first.
    Big,
}

impl PatternByteOrder {
    pub(crate) fn from_raw(raw: frida_sys::FridaPatternByteOrder) -> Self {
        match raw {
            frida_sys::FridaPatternByteOrder_FRIDA_PATTERN_BYTE_ORDER_LITTLE => Self::Little,
            frida_sys::FridaPatternByteOrder_FRIDA_PATTERN_BYTE_ORDER_BIG => Self::Big,
            frida_sys::FridaPatternByteOrder_FRIDA_PATTERN_BYTE_ORDER_NATIVE => Self::Native,
            // Every value the linked frida-core has is named above, which
            // `enum_coverage` checks against its header. The enum has no
            // variant for a value from some other version.
            _ => Self::Native,
        }
    }
}

/// How the bits of a [`PatternBit`] are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternBitKind {
    /// As an unsigned integer.
    Unsigned,
    /// As a signed integer.
    Signed,
    /// As a boolean.
    Bool,
    /// As a value of an enum.
    Enum,
}

impl PatternBitKind {
    pub(crate) fn from_raw(raw: frida_sys::FridaPatternBitKind) -> Self {
        match raw {
            frida_sys::FridaPatternBitKind_FRIDA_PATTERN_BIT_KIND_SIGNED => Self::Signed,
            frida_sys::FridaPatternBitKind_FRIDA_PATTERN_BIT_KIND_BOOL => Self::Bool,
            frida_sys::FridaPatternBitKind_FRIDA_PATTERN_BIT_KIND_ENUM => Self::Enum,
            frida_sys::FridaPatternBitKind_FRIDA_PATTERN_BIT_KIND_UNSIGNED => Self::Unsigned,
            // Every value the linked frida-core has is named above, which
            // `enum_coverage` checks against its header. The enum has no
            // variant for a value from some other version.
            _ => Self::Unsigned,
        }
    }
}

/// Where a [`PatternVisualizer`] is to be shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternVisualizerPresentation {
    /// Apart from the value, when asked for.
    Detached,
    /// In place of the value.
    Inline,
}

impl PatternVisualizerPresentation {
    pub(crate) fn from_raw(raw: frida_sys::FridaPatternVisualizerPresentation) -> Self {
        match raw {
            frida_sys::FridaPatternVisualizerPresentation_FRIDA_PATTERN_VISUALIZER_PRESENTATION_INLINE => {
                Self::Inline
            }
            frida_sys::FridaPatternVisualizerPresentation_FRIDA_PATTERN_VISUALIZER_PRESENTATION_DETACHED => {
                Self::Detached
            }
            // Every value the linked frida-core has is named above, which
            // `enum_coverage` checks against its header. The enum has no
            // variant for a value from some other version.
            _ => Self::Detached,
        }
    }
}

/// What a [`PatternVisualizerArgument`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternVisualizerArgumentKind {
    /// A value.
    Value,
    /// A decoded pattern: its ID, where it is, and its bytes.
    Pattern,
}

impl PatternVisualizerArgumentKind {
    pub(crate) fn from_raw(raw: frida_sys::FridaPatternVisualizerArgumentKind) -> Self {
        match raw {
            frida_sys::FridaPatternVisualizerArgumentKind_FRIDA_PATTERN_VISUALIZER_ARGUMENT_KIND_PATTERN => {
                Self::Pattern
            }
            frida_sys::FridaPatternVisualizerArgumentKind_FRIDA_PATTERN_VISUALIZER_ARGUMENT_KIND_VALUE => {
                Self::Value
            }
            // Every value the linked frida-core has is named above, which
            // `enum_coverage` checks against its header. The enum has no
            // variant for a value from some other version.
            _ => Self::Value,
        }
    }
}

pattern_object!(
    /// Compiles pattern language sources. [`Frida`](crate::Frida) must have been obtained
    /// before one is created.
    PatternCompiler,
    _FridaPatternCompiler
);

impl PatternCompiler {
    /// Create a pattern compiler.
    pub fn new() -> Self {
        Self {
            ptr: unsafe { frida_sys::frida_pattern_compiler_new() },
        }
    }

    /// Compile the pattern at `entrypoint`, a path relative to the project root unless it is
    /// absolute, laying out its types for the target `options` describe.
    ///
    /// A pattern that does not compile still gives a module: one whose
    /// [`diagnostics`](PatternModule::diagnostics) say why. The error is for a pattern that
    /// could not be read at all.
    pub fn compile(
        &self,
        entrypoint: &str,
        options: Option<&PatternCompileOptions>,
    ) -> Result<PatternModule> {
        let entrypoint = c_string(entrypoint)?;
        let options = options.map_or(std::ptr::null_mut(), |options| options.ptr);
        let mut error: *mut GError = std::ptr::null_mut();
        unsafe {
            let module = frida_sys::frida_pattern_compiler_compile_sync(
                self.ptr,
                entrypoint.as_ptr(),
                options,
                std::ptr::null_mut(),
                &mut error,
            );
            if !error.is_null() {
                return Err(pattern_error(error));
            }
            Ok(PatternModule::from_owned(module))
        }
    }
}

impl Default for PatternCompiler {
    fn default() -> Self {
        Self::new()
    }
}

pattern_object!(
    /// Where a pattern's project is rooted, and the target to lay its types out for.
    PatternCompileOptions,
    _FridaPatternCompileOptions
);

impl PatternCompileOptions {
    /// Create options with the defaults: the project root is inferred from the entrypoint, the
    /// target is the system running the compiler, and nothing is defined.
    pub fn new() -> Self {
        Self {
            ptr: unsafe { frida_sys::frida_pattern_compile_options_new() },
        }
    }

    /// The project root, or `None` where it is to be inferred from the entrypoint.
    pub fn project_root(&self) -> Option<String> {
        unsafe {
            string_at(frida_sys::frida_pattern_compile_options_get_project_root(
                self.ptr,
            ))
        }
    }

    /// Set the project root. A path with a NUL in it is ignored.
    pub fn set_project_root(&self, path: &str) {
        if let Ok(path) = CString::new(path) {
            unsafe {
                frida_sys::frida_pattern_compile_options_set_project_root(self.ptr, path.as_ptr())
            };
        }
    }

    /// The platform the decoded data comes from, as `Process.platform` reports it, or `None`
    /// for the one running the compiler.
    pub fn platform(&self) -> Option<String> {
        unsafe {
            string_at(frida_sys::frida_pattern_compile_options_get_platform(
                self.ptr,
            ))
        }
    }

    /// Set the platform the decoded data comes from. One with a NUL in it is ignored.
    pub fn set_platform(&self, platform: &str) {
        if let Ok(platform) = CString::new(platform) {
            unsafe {
                frida_sys::frida_pattern_compile_options_set_platform(self.ptr, platform.as_ptr())
            };
        }
    }

    /// The architecture the decoded data comes from, as `Process.arch` reports it, or `None`
    /// for the one running the compiler.
    pub fn arch(&self) -> Option<String> {
        unsafe { string_at(frida_sys::frida_pattern_compile_options_get_arch(self.ptr)) }
    }

    /// Set the architecture the decoded data comes from. One with a NUL in it is ignored.
    pub fn set_arch(&self, arch: &str) {
        if let Ok(arch) = CString::new(arch) {
            unsafe { frida_sys::frida_pattern_compile_options_set_arch(self.ptr, arch.as_ptr()) };
        }
    }

    /// The preprocessor macros defined before the source is read, by name.
    pub fn defines(&self) -> HashMap<String, Variant> {
        unsafe {
            parameters_of(frida_sys::frida_pattern_compile_options_get_defines(
                self.ptr,
            ))
        }
    }

    /// Set the preprocessor macros to define before the source is read, the way a `#define` at
    /// the top of the entrypoint would, in place of any set before. A macro's value is a
    /// string, a boolean or an integer.
    pub fn set_defines(&self, defines: &HashMap<String, Variant>) -> Result<()> {
        let table = parameters_table(defines)?;
        unsafe {
            frida_sys::frida_pattern_compile_options_set_defines(self.ptr, table);
            // The options hold their own reference.
            frida_sys::g_hash_table_unref(table);
        }
        Ok(())
    }
}

impl Default for PatternCompileOptions {
    fn default() -> Self {
        Self::new()
    }
}

pattern_object!(
    /// The values to decode with.
    PatternDecodeOptions,
    _FridaPatternDecodeOptions
);

impl PatternDecodeOptions {
    /// Create options with no inputs set.
    pub fn new() -> Self {
        Self {
            ptr: unsafe { frida_sys::frida_pattern_decode_options_new() },
        }
    }

    /// The values for the module's `in` variables, by name.
    pub fn inputs(&self) -> HashMap<String, Variant> {
        unsafe { parameters_of(frida_sys::frida_pattern_decode_options_get_inputs(self.ptr)) }
    }

    /// Set the values for the module's `in` variables, in place of any set before. A value is
    /// a string, a boolean or an integer.
    pub fn set_inputs(&self, inputs: &HashMap<String, Variant>) -> Result<()> {
        let table = parameters_table(inputs)?;
        unsafe {
            frida_sys::frida_pattern_decode_options_set_inputs(self.ptr, table);
            // The options hold their own reference.
            frida_sys::g_hash_table_unref(table);
        }
        Ok(())
    }
}

impl Default for PatternDecodeOptions {
    fn default() -> Self {
        Self::new()
    }
}

pattern_object!(
    /// A compiled pattern language source, with the types it declares.
    PatternModule,
    _FridaPatternModule
);

impl PatternModule {
    /// The declared types, in declaration order.
    pub fn types(&self) -> Vec<PatternType> {
        items_of!(
            unsafe { frida_sys::frida_pattern_module_get_types(self.ptr) },
            frida_pattern_type_list_size,
            frida_pattern_type_list_get,
            PatternType
        )
    }

    /// The name of the type made of the source's top-level placements, or `None` when it has
    /// none.
    pub fn root_type(&self) -> Option<String> {
        unsafe { string_at(frida_sys::frida_pattern_module_get_root_type(self.ptr)) }
    }

    /// The module's `in` variables, which [`PatternDecodeOptions::set_inputs`] gives values.
    pub fn inputs(&self) -> Vec<PatternInput> {
        items_of!(
            unsafe { frida_sys::frida_pattern_module_get_inputs(self.ptr) },
            frida_pattern_input_list_size,
            frida_pattern_input_list_get,
            PatternInput
        )
    }

    /// What is wrong with the source. Empty for one that compiled.
    pub fn diagnostics(&self) -> Vec<PatternDiagnostic> {
        items_of!(
            unsafe { frida_sys::frida_pattern_module_get_diagnostics(self.ptr) },
            frida_pattern_diagnostic_list_size,
            frida_pattern_diagnostic_list_get,
            PatternDiagnostic
        )
    }

    /// The declared type named `name`, if there is one.
    pub fn lookup(&self, name: &str) -> Option<PatternType> {
        let name = CString::new(name).ok()?;
        unsafe {
            let found = frida_sys::frida_pattern_module_lookup(self.ptr, name.as_ptr());
            (!found.is_null()).then(|| PatternType::from_owned(found))
        }
    }

    /// Decode `data`, which was read from `address`, as an instance of the type `type_name`.
    pub fn decode(
        &self,
        type_name: &str,
        data: &[u8],
        address: u64,
        options: Option<&PatternDecodeOptions>,
    ) -> Result<PatternValue> {
        let type_name = c_string(type_name)?;
        let options = options.map_or(std::ptr::null_mut(), |options| options.ptr);
        let mut error: *mut GError = std::ptr::null_mut();
        unsafe {
            let blob = blob_of(data);
            let value = frida_sys::frida_pattern_module_decode_sync(
                self.ptr,
                type_name.as_ptr(),
                blob,
                address,
                options,
                std::ptr::null_mut(),
                &mut error,
            );
            frida_sys::g_bytes_unref(blob);
            if !error.is_null() {
                return Err(pattern_error(error));
            }
            Ok(PatternValue::from_owned(value))
        }
    }

    /// Decode `data` as [`PatternModule::decode`] does, then call the source's function
    /// `function` with the value whose [`id`](PatternValue::id) is `pattern`, the way
    /// `hex::inline_visualize("button")` does when clicked. Returns what the function printed.
    pub fn call_function(
        &self,
        type_name: &str,
        data: &[u8],
        address: u64,
        pattern: u32,
        function: &str,
        options: Option<&PatternDecodeOptions>,
    ) -> Result<String> {
        let type_name = c_string(type_name)?;
        let function = c_string(function)?;
        let options = options.map_or(std::ptr::null_mut(), |options| options.ptr);
        let mut error: *mut GError = std::ptr::null_mut();
        unsafe {
            let blob = blob_of(data);
            let output = frida_sys::frida_pattern_module_call_function_sync(
                self.ptr,
                type_name.as_ptr(),
                blob,
                address,
                pattern,
                function.as_ptr(),
                options,
                std::ptr::null_mut(),
                &mut error,
            );
            frida_sys::g_bytes_unref(blob);
            if !error.is_null() {
                return Err(pattern_error(error));
            }
            let text = text_at(output);
            frida_sys::g_free(output.cast());
            Ok(text)
        }
    }
}

pattern_object!(
    /// A variable a pattern takes a value for when it decodes.
    PatternInput,
    _FridaPatternInput
);

impl PatternInput {
    /// The name to pass the variable's value under.
    pub fn name(&self) -> String {
        unsafe { text_at(frida_sys::frida_pattern_input_get_name(self.ptr)) }
    }

    /// The variable's declared type, or `None` for a string or an untyped input.
    pub fn type_ref(&self) -> Option<PatternTypeRef> {
        unsafe {
            PatternTypeRef::from_borrowed(frida_sys::frida_pattern_input_get_type_ref(self.ptr))
        }
    }
}

pattern_object!(
    /// A type a pattern declares.
    PatternType,
    _FridaPatternType
);

impl PatternType {
    /// What kind of type it is.
    pub fn kind(&self) -> PatternTypeKind {
        PatternTypeKind::from_raw(unsafe { frida_sys::frida_pattern_type_get_kind(self.ptr) })
    }

    /// The type's name.
    pub fn name(&self) -> String {
        unsafe { text_at(frida_sys::frida_pattern_type_get_name(self.ptr)) }
    }

    /// The comment that documents the type, if it has one.
    pub fn doc(&self) -> Option<String> {
        unsafe { string_at(frida_sys::frida_pattern_type_get_doc(self.ptr)) }
    }

    /// The file that declares the type, relative to the project root.
    pub fn file(&self) -> String {
        unsafe { text_at(frida_sys::frida_pattern_type_get_file(self.ptr)) }
    }

    /// The line of the declaration, counted from zero.
    pub fn line(&self) -> u32 {
        unsafe { frida_sys::frida_pattern_type_get_line(self.ptr) }
    }

    /// The character on its line at which the declaration starts, counted from zero.
    pub fn character(&self) -> u32 {
        unsafe { frida_sys::frida_pattern_type_get_character(self.ptr) }
    }

    /// The type's size in bytes, or -1 when it depends on the data.
    pub fn size(&self) -> i64 {
        unsafe { frida_sys::frida_pattern_type_get_size(self.ptr) }
    }

    /// The type's alignment in bytes.
    pub fn align(&self) -> u32 {
        unsafe { frida_sys::frida_pattern_type_get_align(self.ptr) }
    }

    /// The fields of a struct or a union, in memory order.
    pub fn fields(&self) -> Vec<PatternField> {
        items_of!(
            unsafe { frida_sys::frida_pattern_type_get_fields(self.ptr) },
            frida_pattern_field_list_size,
            frida_pattern_field_list_get,
            PatternField
        )
    }

    /// The integer type an enum is stored as.
    pub fn underlying(&self) -> Option<PatternTypeRef> {
        unsafe {
            PatternTypeRef::from_borrowed(frida_sys::frida_pattern_type_get_underlying(self.ptr))
        }
    }

    /// The values of an enum.
    pub fn values(&self) -> Vec<PatternEnumValue> {
        items_of!(
            unsafe { frida_sys::frida_pattern_type_get_values(self.ptr) },
            frida_pattern_enum_value_list_size,
            frida_pattern_enum_value_list_get,
            PatternEnumValue
        )
    }

    /// The members of a bitfield, from the least significant bit.
    pub fn bits(&self) -> Vec<PatternBit> {
        items_of!(
            unsafe { frida_sys::frida_pattern_type_get_bits(self.ptr) },
            frida_pattern_bit_list_size,
            frida_pattern_bit_list_get,
            PatternBit
        )
    }

    /// The type an alias is another name for.
    pub fn target(&self) -> Option<PatternTypeRef> {
        unsafe { PatternTypeRef::from_borrowed(frida_sys::frida_pattern_type_get_target(self.ptr)) }
    }
}

pattern_object!(
    /// A field of a struct or a union.
    PatternField,
    _FridaPatternField
);

impl PatternField {
    /// The field's name, empty for an anonymous field and for padding.
    pub fn name(&self) -> String {
        unsafe { text_at(frida_sys::frida_pattern_field_get_name(self.ptr)) }
    }

    /// The comment that documents the field, if it has one.
    pub fn doc(&self) -> Option<String> {
        unsafe { string_at(frida_sys::frida_pattern_field_get_doc(self.ptr)) }
    }

    /// Whether the field is marked as not to be shown.
    pub fn hidden(&self) -> bool {
        unsafe { frida_sys::frida_pattern_field_get_hidden(self.ptr) != 0 }
    }

    /// Whether the field is only there when a condition on earlier fields holds.
    pub fn conditional(&self) -> bool {
        unsafe { frida_sys::frida_pattern_field_get_conditional(self.ptr) != 0 }
    }

    /// Whether the field takes up no room of its own, and overlaps whatever follows it.
    pub fn no_unique_address(&self) -> bool {
        unsafe { frida_sys::frida_pattern_field_get_no_unique_address(self.ptr) != 0 }
    }

    /// The field's type.
    pub fn type_ref(&self) -> Option<PatternTypeRef> {
        unsafe {
            PatternTypeRef::from_borrowed(frida_sys::frida_pattern_field_get_type_ref(self.ptr))
        }
    }

    /// The field's offset in bytes from the start of its type, or -1 when it depends on the
    /// data.
    pub fn offset(&self) -> i64 {
        unsafe { frida_sys::frida_pattern_field_get_offset(self.ptr) }
    }

    /// The field's size in bytes, or -1 when it depends on the data.
    pub fn size(&self) -> i64 {
        unsafe { frida_sys::frida_pattern_field_get_size(self.ptr) }
    }
}

pattern_object!(
    /// A reference to a type: what a field, an input or an alias is declared as.
    PatternTypeRef,
    _FridaPatternTypeRef
);

impl PatternTypeRef {
    /// What kind of reference it is.
    pub fn kind(&self) -> PatternTypeRefKind {
        PatternTypeRefKind::from_raw(unsafe {
            frida_sys::frida_pattern_type_ref_get_kind(self.ptr)
        })
    }

    /// The type as the source writes it, such as `be u32` or `Player*`.
    pub fn display(&self) -> String {
        unsafe { text_at(frida_sys::frida_pattern_type_ref_get_display(self.ptr)) }
    }

    /// The name of a built-in or a declared type.
    pub fn name(&self) -> Option<String> {
        unsafe { string_at(frida_sys::frida_pattern_type_ref_get_name(self.ptr)) }
    }

    /// The byte order of a built-in type.
    pub fn order(&self) -> PatternByteOrder {
        PatternByteOrder::from_raw(unsafe { frida_sys::frida_pattern_type_ref_get_order(self.ptr) })
    }

    /// The type a pointer points at.
    pub fn target(&self) -> Option<PatternTypeRef> {
        unsafe {
            PatternTypeRef::from_borrowed(frida_sys::frida_pattern_type_ref_get_target(self.ptr))
        }
    }

    /// The integer type a pointer is stored as, or `None` for a native pointer.
    pub fn width(&self) -> Option<PatternTypeRef> {
        unsafe {
            PatternTypeRef::from_borrowed(frida_sys::frida_pattern_type_ref_get_width(self.ptr))
        }
    }

    /// The type of an array's elements.
    pub fn element(&self) -> Option<PatternTypeRef> {
        unsafe {
            PatternTypeRef::from_borrowed(frida_sys::frida_pattern_type_ref_get_element(self.ptr))
        }
    }

    /// How many elements an array has, or -1 when it depends on the data.
    pub fn length(&self) -> i64 {
        unsafe { frida_sys::frida_pattern_type_ref_get_length(self.ptr) }
    }

    /// Whether an array runs until a null terminator.
    pub fn null_terminated(&self) -> bool {
        unsafe { frida_sys::frida_pattern_type_ref_get_null_terminated(self.ptr) != 0 }
    }

    /// The size of padding, in bytes.
    pub fn size(&self) -> i64 {
        unsafe { frida_sys::frida_pattern_type_ref_get_size(self.ptr) }
    }
}

pattern_object!(
    /// A value of an enum.
    PatternEnumValue,
    _FridaPatternEnumValue
);

impl PatternEnumValue {
    /// The value's name.
    pub fn name(&self) -> String {
        unsafe { text_at(frida_sys::frida_pattern_enum_value_get_name(self.ptr)) }
    }

    /// The comment that documents the value, if it has one.
    pub fn doc(&self) -> Option<String> {
        unsafe { string_at(frida_sys::frida_pattern_enum_value_get_doc(self.ptr)) }
    }

    /// The number the name stands for, or the first of them where it stands for a range.
    pub fn value(&self) -> i64 {
        unsafe { frida_sys::frida_pattern_enum_value_get_value(self.ptr) }
    }

    /// The last number of a range, and the same as [`value`](Self::value) otherwise.
    pub fn last(&self) -> i64 {
        unsafe { frida_sys::frida_pattern_enum_value_get_last(self.ptr) }
    }
}

pattern_object!(
    /// A member of a bitfield.
    PatternBit,
    _FridaPatternBit
);

impl PatternBit {
    /// The member's name.
    pub fn name(&self) -> String {
        unsafe { text_at(frida_sys::frida_pattern_bit_get_name(self.ptr)) }
    }

    /// The comment that documents the member, if it has one.
    pub fn doc(&self) -> Option<String> {
        unsafe { string_at(frida_sys::frida_pattern_bit_get_doc(self.ptr)) }
    }

    /// How the member's bits are read.
    pub fn kind(&self) -> PatternBitKind {
        PatternBitKind::from_raw(unsafe { frida_sys::frida_pattern_bit_get_kind(self.ptr) })
    }

    /// The position of the member's least significant bit.
    pub fn offset(&self) -> u32 {
        unsafe { frida_sys::frida_pattern_bit_get_offset(self.ptr) }
    }

    /// How many bits the member has.
    pub fn bits(&self) -> u32 {
        unsafe { frida_sys::frida_pattern_bit_get_bits(self.ptr) }
    }

    /// The enum the member's bits are a value of, when it is typed as one.
    pub fn enum_name(&self) -> Option<String> {
        unsafe { string_at(frida_sys::frida_pattern_bit_get_enum_name(self.ptr)) }
    }
}

pattern_object!(
    /// Something wrong with a pattern's source, and where.
    PatternDiagnostic,
    _FridaPatternDiagnostic
);

impl PatternDiagnostic {
    /// The file it is in, relative to the project root.
    pub fn file(&self) -> String {
        unsafe { text_at(frida_sys::frida_pattern_diagnostic_get_file(self.ptr)) }
    }

    /// The line it is on, counted from zero.
    pub fn line(&self) -> u32 {
        unsafe { frida_sys::frida_pattern_diagnostic_get_line(self.ptr) }
    }

    /// The character on its line at which it starts, counted from zero.
    pub fn character(&self) -> u32 {
        unsafe { frida_sys::frida_pattern_diagnostic_get_character(self.ptr) }
    }

    /// What is wrong.
    pub fn message(&self) -> String {
        unsafe { text_at(frida_sys::frida_pattern_diagnostic_get_message(self.ptr)) }
    }
}

pattern_object!(
    /// Bytes decoded as a type: a value, or a struct's fields, or an array's elements, each a
    /// value in turn.
    PatternValue,
    _FridaPatternValue
);

impl PatternValue {
    /// A number that identifies the value within its decoded tree: what a visualizer's
    /// arguments refer to it by, and what [`PatternModule::call_function`] is given.
    pub fn id(&self) -> u32 {
        unsafe { frida_sys::frida_pattern_value_get_id(self.ptr) }
    }

    /// The name of the field the value is, empty for the root and for an array's elements.
    pub fn name(&self) -> String {
        unsafe { text_at(frida_sys::frida_pattern_value_get_name(self.ptr)) }
    }

    /// The value's type as the source writes it.
    pub fn type_name(&self) -> String {
        unsafe { text_at(frida_sys::frida_pattern_value_get_type_name(self.ptr)) }
    }

    /// The address the value was decoded from.
    pub fn address(&self) -> u64 {
        unsafe { frida_sys::frida_pattern_value_get_address(self.ptr) }
    }

    /// The value's offset in bytes from the root value.
    pub fn offset(&self) -> u64 {
        unsafe { frida_sys::frida_pattern_value_get_offset(self.ptr) }
    }

    /// The value's size in bytes, or -1 when the data ended before it was known.
    pub fn size(&self) -> i64 {
        unsafe { frida_sys::frida_pattern_value_get_size(self.ptr) }
    }

    /// The scalar value: an integer, a boolean or a string, with a pointer as an integer.
    /// `None` for a struct, a union, a bitfield, an array, and a value the data was too short
    /// for.
    ///
    /// A floating-point value has no place in [`Variant`], and comes back as
    /// [`Variant::Unsupported`]: [`PatternValue::value_as_f64`] reads it.
    pub fn value(&self) -> Option<Variant> {
        unsafe { variant_at(frida_sys::frida_pattern_value_get_value(self.ptr)) }
    }

    /// The value itself, where it is a floating-point number.
    pub fn value_as_f64(&self) -> Option<f64> {
        unsafe {
            let value = frida_sys::frida_pattern_value_get_value(self.ptr);
            if value.is_null() {
                return None;
            }
            let signature = CStr::from_ptr(frida_sys::g_variant_get_type_string(value));
            (signature.to_bytes() == b"d").then(|| frida_sys::g_variant_get_double(value))
        }
    }

    /// The name of the enum value that matches the value, if any.
    pub fn label(&self) -> Option<String> {
        unsafe { string_at(frida_sys::frida_pattern_value_get_label(self.ptr)) }
    }

    /// The name to show in place of the field's, from `[[name]]` or
    /// `std::core::set_display_name`.
    pub fn display_name(&self) -> Option<String> {
        unsafe { string_at(frida_sys::frida_pattern_value_get_display_name(self.ptr)) }
    }

    /// The value as a `[[format]]` function rendered it, if one applies.
    pub fn formatted(&self) -> Option<String> {
        unsafe { string_at(frida_sys::frida_pattern_value_get_formatted(self.ptr)) }
    }

    /// The comment attached with `[[comment]]`, if any.
    pub fn comment(&self) -> Option<String> {
        unsafe { string_at(frida_sys::frida_pattern_value_get_comment(self.ptr)) }
    }

    /// The highlight colour attached with `[[color]]`, as `RRGGBB`, if any.
    pub fn color(&self) -> Option<String> {
        unsafe { string_at(frida_sys::frida_pattern_value_get_color(self.ptr)) }
    }

    /// Whether the pattern asked for the value to be hidden.
    pub fn hidden(&self) -> bool {
        unsafe { frida_sys::frida_pattern_value_get_hidden(self.ptr) != 0 }
    }

    /// Whether the pattern asked for the value's children to be shown in its parent's place.
    pub fn inlined(&self) -> bool {
        unsafe { frida_sys::frida_pattern_value_get_inlined(self.ptr) != 0 }
    }

    /// Whether the pattern asked for the value's children to be kept out of view.
    pub fn sealed(&self) -> bool {
        unsafe { frida_sys::frida_pattern_value_get_sealed(self.ptr) != 0 }
    }

    /// The bit position within the containing bitfield's storage, or -1 for a value that is
    /// addressed by byte.
    pub fn bit_offset(&self) -> i32 {
        unsafe { frida_sys::frida_pattern_value_get_bit_offset(self.ptr) }
    }

    /// The width in bits of a bitfield member, or 0 otherwise.
    pub fn bits(&self) -> u32 {
        unsafe { frida_sys::frida_pattern_value_get_bits(self.ptr) }
    }

    /// How many elements an array has, or -1 for other values. Of a large array only the
    /// first elements are decoded.
    pub fn count(&self) -> i64 {
        unsafe { frida_sys::frida_pattern_value_get_count(self.ptr) }
    }

    /// The fields of a struct, a union or a bitfield.
    pub fn fields(&self) -> Vec<PatternValue> {
        items_of!(
            unsafe { frida_sys::frida_pattern_value_get_fields(self.ptr) },
            frida_pattern_value_list_size,
            frida_pattern_value_list_get,
            PatternValue
        )
    }

    /// The elements of an array.
    pub fn elements(&self) -> Vec<PatternValue> {
        items_of!(
            unsafe { frida_sys::frida_pattern_value_get_elements(self.ptr) },
            frida_pattern_value_list_size,
            frida_pattern_value_list_get,
            PatternValue
        )
    }

    /// Whether the data ended before the value did.
    pub fn truncated(&self) -> bool {
        unsafe { frida_sys::frida_pattern_value_get_truncated(self.ptr) != 0 }
    }

    /// The section the value is in: 0 for the decoded data, and otherwise a section the
    /// pattern created, into which [`address`](Self::address) is then an offset.
    pub fn section(&self) -> u64 {
        unsafe { frida_sys::frida_pattern_value_get_section(self.ptr) }
    }

    /// The visualizer the pattern attached to the value, if any.
    pub fn visualizer(&self) -> Option<PatternVisualizer> {
        unsafe {
            PatternVisualizer::from_borrowed(frida_sys::frida_pattern_value_get_visualizer(
                self.ptr,
            ))
        }
    }

    /// The value and everything below it, as a dictionary.
    pub fn to_variant(&self) -> Variant {
        unsafe { variant_from_owned(frida_sys::frida_pattern_value_to_variant(self.ptr)) }
    }
}

pattern_object!(
    /// A visualizer a pattern attached to a value, with `hex::visualize` or
    /// `hex::inline_visualize`.
    PatternVisualizer,
    _FridaPatternVisualizer
);

impl PatternVisualizer {
    /// The visualizer's name, such as `image` or `line_plot`.
    pub fn name(&self) -> String {
        unsafe { text_at(frida_sys::frida_pattern_visualizer_get_name(self.ptr)) }
    }

    /// Where the visualizer is to be shown.
    pub fn presentation(&self) -> PatternVisualizerPresentation {
        PatternVisualizerPresentation::from_raw(unsafe {
            frida_sys::frida_pattern_visualizer_get_presentation(self.ptr)
        })
    }

    /// The arguments that follow the name.
    pub fn arguments(&self) -> Vec<PatternVisualizerArgument> {
        items_of!(
            unsafe { frida_sys::frida_pattern_visualizer_get_arguments(self.ptr) },
            frida_pattern_visualizer_argument_list_size,
            frida_pattern_visualizer_argument_list_get,
            PatternVisualizerArgument
        )
    }

    /// The visualizer, as a dictionary.
    pub fn to_variant(&self) -> Variant {
        unsafe { variant_from_owned(frida_sys::frida_pattern_visualizer_to_variant(self.ptr)) }
    }
}

pattern_object!(
    /// Something a [`PatternVisualizer`] is given: a value, or a decoded pattern.
    PatternVisualizerArgument,
    _FridaPatternVisualizerArgument
);

impl PatternVisualizerArgument {
    /// Which of the two it is.
    pub fn kind(&self) -> PatternVisualizerArgumentKind {
        PatternVisualizerArgumentKind::from_raw(unsafe {
            frida_sys::frida_pattern_visualizer_argument_get_kind(self.ptr)
        })
    }

    /// The value, or a pattern's own value when it has one.
    pub fn value(&self) -> Option<Variant> {
        unsafe {
            variant_at(frida_sys::frida_pattern_visualizer_argument_get_value(
                self.ptr,
            ))
        }
    }

    /// The [`id`](PatternValue::id) of the pattern's value, or 0 when it is not part of the
    /// decoded tree.
    pub fn pattern(&self) -> u32 {
        unsafe { frida_sys::frida_pattern_visualizer_argument_get_pattern(self.ptr) }
    }

    /// The pattern's address.
    pub fn address(&self) -> u64 {
        unsafe { frida_sys::frida_pattern_visualizer_argument_get_address(self.ptr) }
    }

    /// The pattern's size in bytes, or -1 when it could not be determined.
    pub fn size(&self) -> i64 {
        unsafe { frida_sys::frida_pattern_visualizer_argument_get_size(self.ptr) }
    }

    /// The pattern's bytes, or `None` when its size could not be determined.
    pub fn data(&self) -> Option<Vec<u8>> {
        unsafe {
            let blob = frida_sys::frida_pattern_visualizer_argument_get_data(self.ptr);
            if blob.is_null() {
                return None;
            }
            let mut size = 0;
            let data = frida_sys::g_bytes_get_data(blob, &mut size);
            if data.is_null() {
                return Some(Vec::new());
            }
            Some(std::slice::from_raw_parts(data.cast::<u8>(), size as usize).to_vec())
        }
    }

    /// The argument, as a dictionary.
    pub fn to_variant(&self) -> Variant {
        unsafe {
            variant_from_owned(frida_sys::frida_pattern_visualizer_argument_to_variant(
                self.ptr,
            ))
        }
    }
}
