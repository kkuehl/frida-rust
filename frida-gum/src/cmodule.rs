/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Compiling C source to machine code in memory, to call or to hand to Gum as a callback.
//!
//! ```no_run
//! use frida_gum::{CModule, CModuleToolchain, Gum};
//!
//! let gum = Gum::obtain();
//! let module = CModule::new(
//!     &gum,
//!     "int add (int a, int b) { return a + b; }",
//!     CModuleToolchain::Any,
//! )
//! .unwrap();
//! unsafe { module.link() }.unwrap();
//! let add = module.find_symbol_by_name("add").unwrap();
//! let add: extern "C" fn(i32, i32) -> i32 = unsafe { core::mem::transmute(add.0) };
//! assert_eq!(add(2, 3), 5);
//! ```

use {
    crate::{
        Gum, MemoryRange, NativePointer,
        enumeration::{enumerate_every_details, string_at},
        glib_compat,
    },
    core::{cell::Cell, ffi::c_void, fmt, ptr},
    cstr_core::CString,
    frida_gum_sys as gum_sys,
};

#[cfg(not(feature = "std"))]
use alloc::{
    borrow::ToOwned,
    string::{String, ToString},
    vec::Vec,
};

/// What compiles a [`CModule`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CModuleToolchain {
    /// The compiler built into Gum if this build of it has one, the system's otherwise.
    Any,
    /// The compiler built into Gum, TinyCC.
    Internal,
    /// The system's compiler.
    External,
}

impl CModuleToolchain {
    fn to_raw(self) -> gum_sys::GumCModuleToolchain {
        (match self {
            Self::Any => gum_sys::_GumCModuleToolchain_GUM_CMODULE_TOOLCHAIN_ANY,
            Self::Internal => gum_sys::_GumCModuleToolchain_GUM_CMODULE_TOOLCHAIN_INTERNAL,
            Self::External => gum_sys::_GumCModuleToolchain_GUM_CMODULE_TOOLCHAIN_EXTERNAL,
        }) as gum_sys::GumCModuleToolchain
    }
}

/// Why a [`CModule`] could not be compiled or linked: the compiler's or the linker's messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CModuleError(pub String);

impl fmt::Display for CModuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CModuleError {}

impl CModuleError {
    /// Takes the message from `error` and frees it. A null `error` gives `fallback`.
    unsafe fn take(error: *mut gum_sys::GError, fallback: &str) -> Self {
        if error.is_null() {
            return Self(fallback.to_owned());
        }
        let message = unsafe { string_at((*error).message) };
        unsafe { glib_compat::g_error_free(error) };
        Self(message.unwrap_or_else(|| fallback.to_owned()))
    }
}

/// A symbol a [`CModule`] defines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CSymbolDetails {
    pub name: String,
    pub address: NativePointer,
}

/// A macro that is defined for every [`CModule`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CDefineDetails {
    pub name: String,
    /// What the macro expands to, or `None` for one that is only defined.
    pub value: Option<String>,
}

/// Whose a header that every [`CModule`] can include is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CHeaderKind {
    /// Frida's: Gum, GLib, capstone and the like.
    Frida,
    /// The built-in compiler's own.
    Tcc,
}

/// A header that every [`CModule`] can include.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CHeaderDetails {
    /// The name to include it by.
    pub name: String,
    /// Its text.
    pub data: String,
    pub kind: CHeaderKind,
}

/// C code compiled to memory.
///
/// When it is dropped, a linked module's `finalize` function, if it defines one, is called, and
/// its code is freed: nothing may call into it afterwards.
pub struct CModule {
    inner: *mut gum_sys::GumCModule,
    linked: Cell<bool>,
    has_metadata: Cell<bool>,
}

impl CModule {
    /// Compiles `source`.
    pub fn new(
        _gum: &Gum,
        source: &str,
        toolchain: CModuleToolchain,
    ) -> Result<Self, CModuleError> {
        let source = CString::new(source)
            .map_err(|_| CModuleError("the source has a NUL in it".to_owned()))?;
        let options = gum_sys::GumCModuleOptions {
            toolchain: toolchain.to_raw(),
        };
        let mut error: *mut gum_sys::GError = ptr::null_mut();
        let inner = unsafe {
            gum_sys::gum_cmodule_new(
                source.as_ptr().cast(),
                ptr::null_mut(),
                &options,
                &mut error,
            )
        };
        unsafe { Self::from_new(inner, error) }
    }

    /// Takes code already compiled: `binary` is a shared library, as the system's compiler
    /// makes one. The bytes are copied.
    pub fn from_binary(_gum: &Gum, binary: &[u8]) -> Result<Self, CModuleError> {
        let options = gum_sys::GumCModuleOptions {
            toolchain: CModuleToolchain::External.to_raw(),
        };
        let mut error: *mut gum_sys::GError = ptr::null_mut();
        unsafe {
            let blob = glib_compat::g_bytes_new(binary.as_ptr().cast(), binary.len() as _);
            let inner = gum_sys::gum_cmodule_new(ptr::null(), blob, &options, &mut error);
            // The module holds its own reference to the blob.
            glib_compat::g_bytes_unref(blob);
            Self::from_new(inner, error)
        }
    }

    /// Takes ownership of what `gum_cmodule_new` returned and of the error it may have set.
    unsafe fn from_new(
        inner: *mut gum_sys::GumCModule,
        error: *mut gum_sys::GError,
    ) -> Result<Self, CModuleError> {
        if inner.is_null() {
            return Err(unsafe { CModuleError::take(error, "the module could not be created") });
        }
        if !error.is_null() {
            unsafe { glib_compat::g_error_free(error) };
        }
        Ok(Self {
            inner,
            linked: Cell::new(false),
            has_metadata: Cell::new(true),
        })
    }

    /// Gives the code something to link against: where it declares `name` as `extern`, it
    /// gets `value`. Has no effect once the module is linked.
    ///
    /// # Safety
    ///
    /// `value` must be what the code declares `name` to be, a function or a variable of the
    /// declared type, and must stay valid for as long as the module's code can run.
    pub unsafe fn add_symbol(&self, name: &str, value: *const c_void) {
        let Ok(name) = CString::new(name) else {
            return;
        };
        if self.linked.get() || !self.has_metadata.get() {
            return;
        }
        unsafe { gum_sys::gum_cmodule_add_symbol(self.inner, name.as_ptr().cast(), value) };
    }

    /// Links the code and loads it into memory, then calls its `init` function if it defines
    /// one. Only after this do its symbols have addresses.
    ///
    /// # Safety
    ///
    /// This runs the module's `init`, which like the rest of its code is C that the compiler
    /// has not checked for memory safety.
    pub unsafe fn link(&self) -> Result<(), CModuleError> {
        if self.linked.get() {
            return Err(CModuleError("the module is already linked".to_owned()));
        }
        if !self.has_metadata.get() {
            return Err(CModuleError(
                "the module's metadata was dropped before it was linked".to_owned(),
            ));
        }
        let mut error: *mut gum_sys::GError = ptr::null_mut();
        let linked = unsafe { gum_sys::gum_cmodule_link(self.inner, &mut error) };
        if linked == 0 {
            return Err(unsafe { CModuleError::take(error, "the module could not be linked") });
        }
        if !error.is_null() {
            unsafe { glib_compat::g_error_free(error) };
        }
        self.linked.set(true);
        Ok(())
    }

    /// Where the linked code is in memory. Empty before the module is linked.
    pub fn range(&self) -> MemoryRange {
        MemoryRange::from_raw(unsafe { gum_sys::gum_cmodule_get_range(self.inner) })
    }

    /// The symbols the module defines. Empty once its metadata is dropped.
    pub fn enumerate_symbols(&self) -> Vec<CSymbolDetails> {
        let mut symbols = Vec::new();
        if !self.has_metadata.get() {
            return symbols;
        }
        enumerate_every_details(
            |details: *const gum_sys::GumCSymbolDetails| {
                let details = unsafe { &*details };
                symbols.push(CSymbolDetails {
                    name: unsafe { string_at(details.name) }.unwrap_or_default(),
                    address: NativePointer(details.address),
                });
            },
            |func, data| unsafe {
                gum_sys::gum_cmodule_enumerate_symbols(self.inner, Some(func), data)
            },
        );
        symbols
    }

    /// The address of the symbol `name`, once the module is linked. `None` if the module
    /// defines no such symbol, or its metadata is dropped.
    pub fn find_symbol_by_name(&self, name: &str) -> Option<NativePointer> {
        let name = CString::new(name).ok()?;
        if !self.has_metadata.get() {
            return None;
        }
        let address =
            unsafe { gum_sys::gum_cmodule_find_symbol_by_name(self.inner, name.as_ptr().cast()) };
        (!address.is_null()).then_some(NativePointer(address))
    }

    /// Frees what the compiler keeps about the module, which a linked module needs only to
    /// look symbols up: afterwards the module has no symbols to find or enumerate. Its code
    /// stays.
    pub fn drop_metadata(&self) {
        if self.has_metadata.replace(false) {
            unsafe { gum_sys::gum_cmodule_drop_metadata(self.inner) };
        }
    }

    /// The macros defined for every module.
    pub fn builtin_defines() -> Vec<CDefineDetails> {
        let mut defines = Vec::new();
        enumerate_every_details(
            |details: *const gum_sys::GumCDefineDetails| {
                let details = unsafe { &*details };
                defines.push(CDefineDetails {
                    name: unsafe { string_at(details.name) }.unwrap_or_default(),
                    value: unsafe { string_at(details.value) },
                });
            },
            |func, data| unsafe {
                gum_sys::gum_cmodule_enumerate_builtin_defines(Some(func), data)
            },
        );
        defines
    }

    /// The headers every module can include.
    pub fn builtin_headers() -> Vec<CHeaderDetails> {
        let mut headers = Vec::new();
        enumerate_every_details(
            |details: *const gum_sys::GumCHeaderDetails| {
                let details = unsafe { &*details };
                let data = if details.data.is_null() {
                    &[][..]
                } else {
                    // SAFETY: a header's data is `size` bytes long.
                    unsafe {
                        core::slice::from_raw_parts(
                            details.data.cast::<u8>(),
                            details.size as usize,
                        )
                    }
                };
                headers.push(CHeaderDetails {
                    name: unsafe { string_at(details.name) }.unwrap_or_default(),
                    data: String::from_utf8_lossy(data).to_string(),
                    kind: if details.kind
                        == gum_sys::_GumCHeaderKind_GUM_CHEADER_TCC as gum_sys::GumCHeaderKind
                    {
                        CHeaderKind::Tcc
                    } else {
                        CHeaderKind::Frida
                    },
                });
            },
            |func, data| unsafe {
                gum_sys::gum_cmodule_enumerate_builtin_headers(Some(func), data)
            },
        );
        headers
    }
}

impl Drop for CModule {
    fn drop(&mut self) {
        unsafe { gum_sys::g_object_unref(self.inner as *mut c_void) };
    }
}
