/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Moving values between Rust and frida-core: strings, paths, string arrays, bytes,
//! variants, variant dictionaries, durations, environments, errors and callbacks.
//!
//! The `*In` types own what a call borrows (`transfer none` arguments) and free it when
//! dropped, after the call. The functions taking `full` copy a returned value and, when
//! `full` is true (`transfer full`), free the original.
//!
//! Nothing here panics. What cannot be passed to C (a string holding a NUL byte, a path
//! that is not UTF-8, a length or a duration too large for the C type) is an
//! [`ErrorKind::InvalidArgument`](crate::gir::ErrorKind::InvalidArgument) error.

use std::any::Any;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::Variant;
use crate::gir::Error;

// --- Strings ---------------------------------------------------------------

/// `text` as a C string, or an error if it holds a NUL byte, which no C string can.
pub(crate) fn cstring(text: &str) -> Result<CString, Error> {
    CString::new(text).map_err(|nul| {
        let at = nul.nul_position();
        Error::with_source(
            crate::gir::ErrorKind::InvalidArgument,
            format!("a string passed to frida-core holds a NUL byte at offset {at}"),
            nul,
        )
    })
}

/// `text` as a C string, if there is one.
pub(crate) fn opt_cstring(text: Option<&str>) -> Result<Option<CString>, Error> {
    text.map(cstring).transpose()
}

/// The pointer for an optional C string: null for `None`.
pub(crate) fn opt_cstring_ptr(text: Option<&CString>) -> *mut c_char {
    text.map_or(std::ptr::null_mut(), |c| c.as_ptr().cast_mut())
}

/// A copy of the string at `ptr`, or `None` for a null pointer. Frees it with `g_free`
/// when `full`. Bytes that are not UTF-8 are replaced, as everywhere in this crate.
///
/// # Safety
///
/// `ptr` must be null or a NUL-terminated string; when `full`, one the caller owns.
pub(crate) unsafe fn string(ptr: *const c_char, full: bool) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the caller promises a NUL-terminated string.
    let text = unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned();
    if full {
        // SAFETY: the caller owns it, and GLib allocated it.
        unsafe { frida_sys::g_free(ptr.cast_mut().cast()) };
    }
    Some(text)
}

/// The string at `ptr`, borrowed when it is UTF-8 and copied when it is not; `None` for a
/// null pointer. For a signal's arguments, which live as long as the emission.
///
/// # Safety
///
/// `ptr` must be null or a NUL-terminated string that outlives `'a`.
pub(crate) unsafe fn str_arg<'a>(ptr: *const c_char) -> Option<std::borrow::Cow<'a, str>> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the caller promises a NUL-terminated string that outlives 'a.
    Some(unsafe { CStr::from_ptr(ptr) }.to_string_lossy())
}

// --- Paths -----------------------------------------------------------------

/// `path` as the UTF-8 C string frida-core takes for a path.
pub(crate) fn path(path: &Path) -> Result<CString, Error> {
    match path.to_str() {
        Some(text) => cstring(text),
        None => Err(Error::invalid_argument(format!(
            "the path {} is not UTF-8, which frida-core needs",
            path.display()
        ))),
    }
}

/// A path frida-core returned.
pub(crate) fn path_buf(text: String) -> PathBuf {
    PathBuf::from(text)
}

// --- Lengths and durations ---------------------------------------------------

/// A Rust length as a C `gint`, or an error if it does not fit.
pub(crate) fn length(len: usize) -> Result<frida_sys::gint, Error> {
    frida_sys::gint::try_from(len).map_err(|overflow| {
        Error::with_source(
            crate::gir::ErrorKind::InvalidArgument,
            format!("a length of {len} does not fit frida-core's 32-bit length"),
            overflow,
        )
    })
}

/// A wait in milliseconds, as frida-core's `timeout` arguments take it: `None` is "wait
/// for ever" (any negative value), and [`Duration::ZERO`] is "do not wait".
pub(crate) fn timeout_ms(timeout: Option<Duration>) -> Result<frida_sys::gint, Error> {
    match timeout {
        None => Ok(-1),
        Some(timeout) => i32::try_from(timeout.as_millis()).map_err(|overflow| {
            Error::with_source(
                crate::gir::ErrorKind::InvalidArgument,
                format!("a timeout of {timeout:?} is longer than frida-core can wait"),
                overflow,
            )
        }),
    }
}

/// A duration in whole seconds, as `T`, or an error if it does not fit.
pub(crate) fn seconds<T: TryFrom<u64>>(value: Duration) -> Result<T, Error>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    T::try_from(value.as_secs()).map_err(|overflow| {
        Error::with_source(
            crate::gir::ErrorKind::InvalidArgument,
            format!("{value:?} is more seconds than frida-core can take"),
            overflow,
        )
    })
}

/// A duration frida-core reported in seconds.
pub(crate) fn from_seconds(value: u64) -> Duration {
    Duration::from_secs(value)
}

/// An interval in seconds where -1 disables it: `None` is disabled.
pub(crate) fn interval_s(value: Option<Duration>) -> Result<frida_sys::gint, Error> {
    value.map_or(Ok(-1), seconds::<frida_sys::gint>)
}

// --- Environments ------------------------------------------------------------

/// Environment entries as the `NAME=VALUE` strings frida-core takes. A name may not be
/// empty or hold `=`, and neither may hold a NUL byte.
pub(crate) fn env_entries(pairs: &[(String, String)]) -> Result<Vec<String>, Error> {
    pairs
        .iter()
        .map(|(name, value)| {
            if name.is_empty() || name.contains('=') {
                Err(Error::invalid_argument(format!(
                    "{name:?} is not an environment variable name: it is empty or holds '='"
                )))
            } else {
                Ok(format!("{name}={value}"))
            }
        })
        .collect()
}

/// `NAME=VALUE` strings from frida-core as pairs, split at the first `=`; an entry with
/// none is a name with an empty value.
pub(crate) fn env_pairs(entries: Vec<String>) -> Vec<(String, String)> {
    entries
        .into_iter()
        .map(|entry| match entry.split_once('=') {
            Some((name, value)) => (name.to_string(), value.to_string()),
            None => (entry, String::new()),
        })
        .collect()
}

// --- String arrays -------------------------------------------------------------

/// A string array argument: the C strings, and a NULL-terminated array of pointers to them.
pub(crate) struct StrArray {
    _strings: Vec<CString>,
    pointers: Vec<*mut c_char>,
    len: frida_sys::gint,
}

impl StrArray {
    pub(crate) fn new<S: AsRef<str>>(strings: &[S]) -> Result<Self, Error> {
        let owned = strings
            .iter()
            .map(|s| cstring(s.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        let len = length(owned.len())?;
        let mut pointers: Vec<*mut c_char> = owned.iter().map(|c| c.as_ptr().cast_mut()).collect();
        pointers.push(std::ptr::null_mut());
        Ok(Self {
            _strings: owned,
            pointers,
            len,
        })
    }

    pub(crate) fn as_ptr(&self) -> *mut *mut c_char {
        self.pointers.as_ptr().cast_mut()
    }

    /// The number of strings, without the terminator.
    pub(crate) fn len(&self) -> frida_sys::gint {
        self.len
    }
}

/// A copy of the first `len` strings at `ptr`, or `None` for a null array. When `full`,
/// frees each string and then the array, the way Vala frees an owned array.
///
/// # Safety
///
/// `ptr` must be null, or point to at least `len` strings; when `full`, ones the caller
/// owns, in an array it owns.
pub(crate) unsafe fn string_array(
    ptr: *mut *mut c_char,
    len: frida_sys::gint,
    full: bool,
) -> Option<Vec<String>> {
    if ptr.is_null() {
        return None;
    }
    let len = usize::try_from(len).unwrap_or(0);
    let mut result = Vec::with_capacity(len);
    for i in 0..len {
        // SAFETY: the caller promises `len` strings at `ptr`.
        let item = unsafe { *ptr.add(i) };
        // SAFETY: each is null or a string, owned by the caller when `full`.
        result.push(unsafe { string(item, full) }.unwrap_or_default());
    }
    if full {
        // SAFETY: the caller owns the array, which GLib allocated.
        unsafe { frida_sys::g_free(ptr.cast()) };
    }
    Some(result)
}

// --- Bytes -----------------------------------------------------------------

/// A `GBytes` argument holding a copy of a Rust slice.
pub(crate) struct BytesIn(*mut frida_sys::GBytes);

impl BytesIn {
    pub(crate) fn new(data: &[u8]) -> Result<Self, Error> {
        let len = frida_sys::gsize::try_from(data.len()).map_err(|overflow| {
            Error::with_source(
                crate::gir::ErrorKind::InvalidArgument,
                "the data is larger than GLib can hold",
                overflow,
            )
        })?;
        // SAFETY: g_bytes_new copies `len` bytes from a valid slice.
        Ok(Self(unsafe {
            frida_sys::g_bytes_new(data.as_ptr().cast(), len)
        }))
    }

    pub(crate) fn new_opt(data: Option<&[u8]>) -> Result<Self, Error> {
        data.map_or(Ok(Self(std::ptr::null_mut())), Self::new)
    }

    pub(crate) fn as_ptr(&self) -> *mut frida_sys::GBytes {
        self.0
    }
}

impl Drop for BytesIn {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this holds the reference g_bytes_new returned.
            unsafe { frida_sys::g_bytes_unref(self.0) };
        }
    }
}

/// A copy of the bytes in `ptr`, or `None` for a null pointer. Unrefs it when `full`.
///
/// # Safety
///
/// `ptr` must be null or a `GBytes`; when `full`, one the caller holds a reference to.
pub(crate) unsafe fn bytes(ptr: *mut frida_sys::GBytes, full: bool) -> Option<Vec<u8>> {
    // SAFETY: as this function's.
    let result = unsafe { bytes_arg(ptr) }.map(<[u8]>::to_vec);
    if full && !ptr.is_null() {
        // SAFETY: the caller holds this reference.
        unsafe { frida_sys::g_bytes_unref(ptr) };
    }
    result
}

/// The bytes in `ptr`, borrowed, or `None` for a null pointer. For a signal's arguments,
/// which live as long as the emission.
///
/// # Safety
///
/// `ptr` must be null or a `GBytes` that outlives `'a`.
pub(crate) unsafe fn bytes_arg<'a>(ptr: *mut frida_sys::GBytes) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    let mut size = 0;
    // SAFETY: `ptr` is a live GBytes.
    let data = unsafe { frida_sys::g_bytes_get_data(ptr, &raw mut size) };
    let Ok(size) = usize::try_from(size) else {
        return Some(&[]);
    };
    if data.is_null() || size == 0 {
        return Some(&[]);
    }
    // SAFETY: GLib says `size` bytes live at `data`, for as long as the GBytes does.
    Some(unsafe { std::slice::from_raw_parts(data.cast::<u8>(), size) })
}

// --- Variants --------------------------------------------------------------

/// A new, floating `GVariant`, freed if it is not handed on.
struct NewVariant(*mut frida_sys::GVariant);

impl NewVariant {
    /// Hands the floating reference to a GLib constructor, which consumes it.
    fn into_floating(self) -> *mut frida_sys::GVariant {
        let ptr = self.0;
        std::mem::forget(self);
        ptr
    }

    /// Sinks it and hands over the reference.
    fn into_sunk(self) -> *mut frida_sys::GVariant {
        // SAFETY: ref_sink turns the floating reference into one the caller owns.
        unsafe { frida_sys::g_variant_ref_sink(self.into_floating()) }
    }
}

impl Drop for NewVariant {
    fn drop(&mut self) {
        // SAFETY: sinking then unreffing frees a floating variant nobody took.
        unsafe { frida_sys::g_variant_unref(frida_sys::g_variant_ref_sink(self.0)) };
    }
}

/// A new `GVariant` holding `value`, with a reference the caller owns (sunk).
///
/// A [`Variant::Unsupported`] records only a type signature and has no value to send,
/// and a string may not hold a NUL byte: both are errors.
pub(crate) fn to_gvariant(value: &Variant) -> Result<*mut frida_sys::GVariant, Error> {
    new_variant(value).map(NewVariant::into_sunk)
}

fn new_variant(value: &Variant) -> Result<NewVariant, Error> {
    // Each result is wrapped at once, so that it is freed if a later step fails.
    Ok(match value {
        Variant::String(s) => {
            let s = cstring(s)?;
            // SAFETY: a NUL-terminated string, which GLib copies.
            NewVariant(unsafe { frida_sys::g_variant_new_string(s.as_ptr()) })
        }
        Variant::Boolean(b) => {
            let b = frida_sys::gboolean::from(*b);
            // SAFETY: GLib's constructor takes any gboolean.
            NewVariant(unsafe { frida_sys::g_variant_new_boolean(b) })
        }
        Variant::Int64(i) => {
            // SAFETY: GLib's constructor takes any gint64.
            NewVariant(unsafe { frida_sys::g_variant_new_int64(*i) })
        }
        Variant::Map(map) => vardict_variant(map)?,
        Variant::MapList(list) => {
            let children = list
                .iter()
                .map(vardict_variant)
                .collect::<Result<Vec<_>, _>>()?;
            new_array(c"a{sv}", children)
        }
        Variant::StringList(list) => {
            let array = StrArray::new(list)?;
            let len = frida_sys::gssize::from(array.len());
            // SAFETY: `len` NUL-terminated strings at the array's pointer, which GLib copies.
            NewVariant(unsafe { frida_sys::g_variant_new_strv(array.as_ptr().cast(), len) })
        }
        Variant::Unsupported(signature) => {
            return Err(Error::invalid_argument(format!(
                "a Variant::Unsupported({signature:?}) holds no value, so it cannot be passed to frida-core"
            )));
        }
    })
}

/// An `a{sv}` variant, its keys in order so that equal maps build equal variants.
fn vardict_variant(map: &HashMap<String, Variant>) -> Result<NewVariant, Error> {
    let mut entries: Vec<(&String, &Variant)> = map.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    let entries = entries
        .into_iter()
        .map(|(key, value)| {
            let key = cstring(key)?;
            let value = new_variant(value)?;
            // SAFETY: each constructor consumes the floating variant it is given.
            Ok(NewVariant(unsafe {
                let boxed = frida_sys::g_variant_new_variant(value.into_floating());
                frida_sys::g_variant_new_dict_entry(
                    frida_sys::g_variant_new_string(key.as_ptr()),
                    boxed,
                )
            }))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(new_array(c"{sv}", entries))
}

/// An array variant of `children`, of element type `element`.
fn new_array(element: &CStr, children: Vec<NewVariant>) -> NewVariant {
    let children: Vec<*mut frida_sys::GVariant> = children
        .into_iter()
        .map(NewVariant::into_floating)
        .collect();
    // SAFETY: the type string is valid, and the array consumes its floating children.
    unsafe {
        let element_type = frida_sys::g_variant_type_new(element.as_ptr());
        let array = frida_sys::g_variant_new_array(
            element_type,
            children.as_ptr(),
            children.len() as frida_sys::gsize,
        );
        frida_sys::g_variant_type_free(element_type);
        NewVariant(array)
    }
}

/// A `GVariant` argument: a reference this side owns for the length of the call.
pub(crate) struct VariantIn(*mut frida_sys::GVariant);

impl VariantIn {
    pub(crate) fn new(value: &Variant) -> Result<Self, Error> {
        to_gvariant(value).map(Self)
    }

    pub(crate) fn as_ptr(&self) -> *mut frida_sys::GVariant {
        self.0
    }
}

impl Drop for VariantIn {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this holds one reference.
            unsafe { frida_sys::g_variant_unref(self.0) };
        }
    }
}

/// The value of `ptr`, or `None` for a null pointer. Unrefs it when `full`.
///
/// # Safety
///
/// `ptr` must be null or a `GVariant`; when `full`, one the caller holds a reference to.
pub(crate) unsafe fn variant(ptr: *mut frida_sys::GVariant, full: bool) -> Option<Variant> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: `ptr` is a live GVariant.
    let value = unsafe { Variant::from_ptr(ptr) };
    if full {
        // SAFETY: the caller holds this reference.
        unsafe { frida_sys::g_variant_unref(ptr) };
    }
    Some(value)
}

// --- Variant dictionaries (GHashTable<utf8, GVariant>) ---------------------

unsafe extern "C" fn unref_variant(variant: frida_sys::gpointer) {
    // SAFETY: the table holds one reference to each value.
    unsafe { frida_sys::g_variant_unref(variant.cast()) };
}

/// A `GHashTable<utf8, GVariant>` argument built from a map, freed after the call.
pub(crate) struct VarDictIn(*mut frida_sys::GHashTable);

impl VarDictIn {
    pub(crate) fn new(map: &HashMap<String, Variant>) -> Result<Self, Error> {
        // SAFETY: a new table with GLib's string functions; it owns what is inserted.
        let table = Self(unsafe {
            frida_sys::g_hash_table_new_full(
                Some(frida_sys::g_str_hash),
                Some(frida_sys::g_str_equal),
                Some(frida_sys::g_free),
                Some(unref_variant),
            )
        });
        for (key, value) in map {
            let key = cstring(key)?;
            let value = to_gvariant(value)?;
            // SAFETY: the table takes the duplicated key and the variant's reference.
            unsafe {
                frida_sys::g_hash_table_insert(
                    table.0,
                    frida_sys::g_strdup(key.as_ptr()).cast(),
                    value.cast(),
                )
            };
        }
        Ok(table)
    }

    pub(crate) fn as_ptr(&self) -> *mut frida_sys::GHashTable {
        self.0
    }
}

impl Drop for VarDictIn {
    fn drop(&mut self) {
        // SAFETY: this holds the table's only reference of its own.
        unsafe { frida_sys::g_hash_table_unref(self.0) };
    }
}

/// A copy of the `GHashTable<utf8, GVariant>` at `ptr`, or `None` for a null pointer.
/// Unrefs it when `full`.
///
/// # Safety
///
/// `ptr` must be null or a hash table of strings to variants; when `full`, one the caller
/// holds a reference to.
pub(crate) unsafe fn vardict(
    ptr: *mut frida_sys::GHashTable,
    full: bool,
) -> Option<HashMap<String, Variant>> {
    if ptr.is_null() {
        return None;
    }
    let mut map = HashMap::new();
    // SAFETY: iterating a live table of strings to variants, as the caller promises.
    unsafe {
        let mut iter: frida_sys::GHashTableIter = std::mem::zeroed();
        frida_sys::g_hash_table_iter_init(&raw mut iter, ptr);
        let mut key = std::ptr::null_mut();
        let mut value = std::ptr::null_mut();
        while frida_sys::g_hash_table_iter_next(&raw mut iter, &raw mut key, &raw mut value) != 0 {
            let key = string(key as *const c_char, false).unwrap_or_default();
            if let Some(value) = variant(value.cast(), false) {
                map.insert(key, value);
            }
        }
        if full {
            frida_sys::g_hash_table_unref(ptr);
        }
    }
    Some(map)
}

// --- Values the GIR promises -------------------------------------------------

/// The value a call promised not to leave out, or an
/// [`ErrorKind::Unexpected`](crate::gir::ErrorKind::Unexpected) error if it is missing
/// after all: Vala does not enforce non-null types, so a NULL can still arrive where the
/// GIR says none will.
pub(crate) fn non_null<T>(value: Option<T>, function: &str) -> Result<T, Error> {
    value.ok_or_else(|| Error::unexpected_null(function))
}

// --- Errors ------------------------------------------------------------------

/// The error a call set, as an [`Error`], or `None` when it set none. Frees it.
///
/// # Safety
///
/// `error` must be null or a `GError` the caller owns.
pub(crate) unsafe fn take_error(error: *mut frida_sys::GError) -> Option<Error> {
    if error.is_null() {
        return None;
    }
    // SAFETY: a GError the caller owns, read and then freed.
    unsafe {
        let domain = (*error).domain;
        let code = (*error).code;
        let message = string((*error).message, false).unwrap_or_default();
        frida_sys::g_error_free(error);
        let frida = domain == frida_sys::frida_error_quark();
        let name = string(frida_sys::g_quark_to_string(domain), false).unwrap_or_default();
        Some(Error::from_gerror(name, code, message, frida))
    }
}

// --- Callbacks -----------------------------------------------------------------

/// A closure lent to a call for the length of that call (`scope="call"`), and the panic
/// it raised, if any, to raise again once the call is over. A panic must not unwind
/// through frida-core's C frames.
pub(crate) struct CallState<F> {
    f: F,
    panic: Option<Box<dyn Any + Send>>,
}

impl<F> CallState<F> {
    pub(crate) fn new(f: F) -> Self {
        Self { f, panic: None }
    }

    /// The user data to give frida-core. Valid while `self` stays where it is.
    pub(crate) fn as_ptr(&mut self) -> frida_sys::gpointer {
        std::ptr::from_mut(self).cast()
    }

    /// Raises again the panic the closure raised, if it did: the caller's own panic,
    /// carried across frida-core's frames, not one of this crate's.
    pub(crate) fn finish(self) {
        if let Some(panic) = self.panic {
            resume_unwind(panic);
        }
    }
}

/// Calls the closure behind `user_data`. Once it has panicked, later calls return the
/// default without running it.
///
/// # Safety
///
/// `user_data` must come from [`CallState::as_ptr`] of a live `CallState<F>`.
pub(crate) unsafe fn invoke<F, R: Default>(
    user_data: frida_sys::gpointer,
    call: impl FnOnce(&mut F) -> R,
) -> R {
    // SAFETY: the caller promises a live CallState<F>, used by this call alone.
    let state = unsafe { &mut *user_data.cast::<CallState<F>>() };
    if state.panic.is_some() {
        return R::default();
    }
    match catch_unwind(AssertUnwindSafe(|| call(&mut state.f))) {
        Ok(result) => result,
        Err(panic) => {
            state.panic = Some(panic);
            R::default()
        }
    }
}

/// The destroy notify of a closure handed over for good (`scope="notified"`).
///
/// # Safety
///
/// `data` must come from [`NotifiedState::into_raw`] with this `F`, and not be used again.
pub(crate) unsafe extern "C" fn drop_boxed<F>(data: frida_sys::gpointer) {
    // A panic while dropping it must not unwind into frida-core.
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: as this function's; the box is freed once.
        drop(unsafe { Box::from_raw(data.cast::<NotifiedState<F>>()) });
    }));
}

/// A closure handed over for good (`scope="notified"`), and whether it has panicked.
/// It runs on frida-core's thread, where there is no caller to raise a panic again in: a
/// panic is caught, and the closure is not run again.
pub(crate) struct NotifiedState<F> {
    f: F,
    panicked: bool,
}

impl<F> NotifiedState<F> {
    /// The user data to give frida-core, which now owns it, and frees it with
    /// [`drop_boxed::<F>`](drop_boxed).
    pub(crate) fn into_raw(f: F) -> frida_sys::gpointer {
        Box::into_raw(Box::new(Self { f, panicked: false })).cast()
    }
}

/// Calls the closure behind `user_data`. Once it has panicked, later calls return the
/// default without running it.
///
/// # Safety
///
/// `user_data` must come from [`NotifiedState::into_raw`] with this `F`, and not have
/// been freed.
pub(crate) unsafe fn invoke_notified<F, R: Default>(
    user_data: frida_sys::gpointer,
    call: impl FnOnce(&mut F) -> R,
) -> R {
    // SAFETY: the caller promises a live NotifiedState<F>, run on one thread at a time.
    let state = unsafe { &mut *user_data.cast::<NotifiedState<F>>() };
    if state.panicked {
        return R::default();
    }
    match catch_unwind(AssertUnwindSafe(|| call(&mut state.f))) {
        Ok(result) => result,
        Err(_) => {
            state.panicked = true;
            R::default()
        }
    }
}
