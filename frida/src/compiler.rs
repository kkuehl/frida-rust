/*
 * Copyright © 2026 Frida-rust contributors
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Bindings to the `Frida.Compiler`, which turns a TypeScript or JavaScript
//! project into a single script bundle suitable for
//! [`Session::create_script`](crate::Session::create_script).
//!
//! Frida 17.18.0 upgraded the underlying TypeScript to 7.0 and now shares the
//! parse cache with [`LanguageServer`](crate::LanguageServer).

use frida_sys::{
    _FridaBuildOptions, _FridaCompiler, _FridaCompilerOptions, _FridaWatchOptions, GError,
};
use std::ffi::{CStr, CString};
use std::marker::PhantomData;

use crate::{DeviceManager, Error, Result};

/// Emitted-script text format.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Raw JavaScript source.
    Unescaped = frida_sys::FridaOutputFormat_FRIDA_OUTPUT_FORMAT_UNESCAPED as _,
    /// Hex-encoded bytes.
    HexBytes = frida_sys::FridaOutputFormat_FRIDA_OUTPUT_FORMAT_HEX_BYTES as _,
    /// Escaped C string literal.
    CString = frida_sys::FridaOutputFormat_FRIDA_OUTPUT_FORMAT_C_STRING as _,
}

/// Module format used for the emitted bundle.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleFormat {
    /// ECMAScript module.
    Esm = frida_sys::FridaBundleFormat_FRIDA_BUNDLE_FORMAT_ESM as _,
    /// Immediately-invoked function expression (default for scripts).
    Iife = frida_sys::FridaBundleFormat_FRIDA_BUNDLE_FORMAT_IIFE as _,
}

/// Whether the compiler should run the TypeScript type checker.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeCheckMode {
    /// Run the full type checker (default).
    Full = frida_sys::FridaTypeCheckMode_FRIDA_TYPE_CHECK_MODE_FULL as _,
    /// Skip type checking; still emits code.
    None = frida_sys::FridaTypeCheckMode_FRIDA_TYPE_CHECK_MODE_NONE as _,
}

/// Whether source maps are appended to the bundle.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceMaps {
    /// Inline source maps in the bundle (default).
    Included = frida_sys::FridaSourceMaps_FRIDA_SOURCE_MAPS_INCLUDED as _,
    /// Omit source maps.
    Omitted = frida_sys::FridaSourceMaps_FRIDA_SOURCE_MAPS_OMITTED as _,
}

/// Whether to compress the emitted bundle with terser.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsCompression {
    /// Do not compress (default).
    None = frida_sys::FridaJsCompression_FRIDA_JS_COMPRESSION_NONE as _,
    /// Compress with terser.
    Terser = frida_sys::FridaJsCompression_FRIDA_JS_COMPRESSION_TERSER as _,
}

/// Target platform for the emitted bundle.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsPlatform {
    /// Gum runtime (default).
    Gum = frida_sys::FridaJsPlatform_FRIDA_JS_PLATFORM_GUM as _,
    /// Browser runtime.
    Browser = frida_sys::FridaJsPlatform_FRIDA_JS_PLATFORM_BROWSER as _,
    /// Neutral runtime.
    Neutral = frida_sys::FridaJsPlatform_FRIDA_JS_PLATFORM_NEUTRAL as _,
}

fn set_options_common(opts: *mut _FridaCompilerOptions, options: &CompilerOptionsBuilder) {
    unsafe {
        if let Some(root) = &options.project_root {
            frida_sys::frida_compiler_options_set_project_root(opts, root.as_ptr());
        }
        if let Some(v) = options.output_format {
            frida_sys::frida_compiler_options_set_output_format(opts, v as _);
        }
        if let Some(v) = options.bundle_format {
            frida_sys::frida_compiler_options_set_bundle_format(opts, v as _);
        }
        if let Some(v) = options.type_check {
            frida_sys::frida_compiler_options_set_type_check(opts, v as _);
        }
        if let Some(v) = options.source_maps {
            frida_sys::frida_compiler_options_set_source_maps(opts, v as _);
        }
        if let Some(v) = options.compression {
            frida_sys::frida_compiler_options_set_compression(opts, v as _);
        }
        if let Some(v) = options.platform {
            frida_sys::frida_compiler_options_set_platform(opts, v as _);
        }
        for ext in &options.externals {
            frida_sys::frida_compiler_options_add_external(opts, ext.as_ptr());
        }
    }
}

/// Builder shared by [`BuildOptions`] and [`WatchOptions`].
#[derive(Default)]
pub struct CompilerOptionsBuilder {
    project_root: Option<CString>,
    output_format: Option<OutputFormat>,
    bundle_format: Option<BundleFormat>,
    type_check: Option<TypeCheckMode>,
    source_maps: Option<SourceMaps>,
    compression: Option<JsCompression>,
    platform: Option<JsPlatform>,
    externals: Vec<CString>,
}

impl CompilerOptionsBuilder {
    /// Explicit project root; the compiler otherwise infers one from the entrypoint.
    pub fn project_root(mut self, path: &str) -> Self {
        self.project_root = CString::new(path).ok();
        self
    }

    /// Set the emitted-script text format.
    pub fn output_format(mut self, v: OutputFormat) -> Self {
        self.output_format = Some(v);
        self
    }

    /// Set the module format.
    pub fn bundle_format(mut self, v: BundleFormat) -> Self {
        self.bundle_format = Some(v);
        self
    }

    /// Enable or disable type checking.
    pub fn type_check(mut self, v: TypeCheckMode) -> Self {
        self.type_check = Some(v);
        self
    }

    /// Include or omit source maps.
    pub fn source_maps(mut self, v: SourceMaps) -> Self {
        self.source_maps = Some(v);
        self
    }

    /// Enable or disable terser compression.
    pub fn compression(mut self, v: JsCompression) -> Self {
        self.compression = Some(v);
        self
    }

    /// Target platform.
    pub fn platform(mut self, v: JsPlatform) -> Self {
        self.platform = Some(v);
        self
    }

    /// Mark a module as external (not bundled).
    pub fn add_external(mut self, name: &str) -> Self {
        if let Ok(cs) = CString::new(name) {
            self.externals.push(cs);
        }
        self
    }
}

/// Options for a one-shot [`Compiler::build`].
pub struct BuildOptions {
    ptr: *mut _FridaBuildOptions,
}

impl BuildOptions {
    /// Create a new options object from a builder.
    pub fn from_builder(builder: CompilerOptionsBuilder) -> Self {
        unsafe {
            let ptr = frida_sys::frida_build_options_new();
            set_options_common(ptr as *mut _FridaCompilerOptions, &builder);
            Self { ptr }
        }
    }
}

impl Default for BuildOptions {
    fn default() -> Self {
        Self::from_builder(CompilerOptionsBuilder::default())
    }
}

impl Drop for BuildOptions {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.ptr as _) }
    }
}

/// Options for [`Compiler::watch`].
pub struct WatchOptions {
    ptr: *mut _FridaWatchOptions,
}

impl WatchOptions {
    /// Create a new options object from a builder.
    pub fn from_builder(builder: CompilerOptionsBuilder) -> Self {
        unsafe {
            let ptr = frida_sys::frida_watch_options_new();
            set_options_common(ptr as *mut _FridaCompilerOptions, &builder);
            Self { ptr }
        }
    }
}

impl Default for WatchOptions {
    fn default() -> Self {
        Self::from_builder(CompilerOptionsBuilder::default())
    }
}

impl Drop for WatchOptions {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.ptr as _) }
    }
}

/// Compiles a TypeScript or JavaScript project into a single script bundle.
///
/// Wraps `Frida.Compiler` (see `frida-core`), which in 17.18.0 was upgraded to
/// TypeScript 7.0 and shares its parse cache with [`LanguageServer`].
pub struct Compiler<'a> {
    ptr: *mut _FridaCompiler,
    phantom: PhantomData<&'a _FridaCompiler>,
}

impl<'a> Compiler<'a> {
    /// Create a new compiler. The `DeviceManager` argument is kept for
    /// compatibility with the underlying C API and is unused by the compiler.
    pub fn new<'b>(manager: &'b DeviceManager<'b>) -> Compiler<'a>
    where
        'b: 'a,
    {
        Compiler {
            ptr: unsafe { frida_sys::frida_compiler_new(manager.raw_ptr()) },
            phantom: PhantomData,
        }
    }

    /// Build the project rooted at `entrypoint` once, returning the emitted bundle.
    pub fn build(&self, entrypoint: &str, options: Option<&BuildOptions>) -> Result<String> {
        let entrypoint = CString::new(entrypoint).map_err(|_| Error::CStringFailed)?;
        let opts_ptr = options.map(|o| o.ptr).unwrap_or(std::ptr::null_mut());

        let mut error: *mut GError = std::ptr::null_mut();
        let bundle = unsafe {
            frida_sys::frida_compiler_build_sync(
                self.ptr,
                entrypoint.as_ptr(),
                opts_ptr,
                std::ptr::null_mut(),
                &mut error,
            )
        };

        if !error.is_null() {
            let message = unsafe { CStr::from_ptr((*error).message) }
                .to_string_lossy()
                .into_owned();
            let code = unsafe { (*error).code };
            unsafe { frida_sys::g_error_free(error) };
            return Err(Error::CompilerBuildFailed { code, message });
        }

        if bundle.is_null() {
            return Err(Error::CompilerBuildFailed {
                code: 0,
                message: "compiler returned no bundle".into(),
            });
        }

        let owned = unsafe { CStr::from_ptr(bundle) }
            .to_string_lossy()
            .into_owned();
        unsafe { frida_sys::g_free(bundle as _) };
        Ok(owned)
    }

    /// Build the project and keep rebuilding it as its sources change.
    ///
    /// Consumers should connect to the compiler's `output` signal (via
    /// `g_signal_connect_data` on [`Compiler::as_raw`]) to receive freshly
    /// built bundles. Cancellation is not exposed by the sync API; the watch
    /// stops when the compiler is dropped.
    pub fn watch(&self, entrypoint: &str, options: Option<&WatchOptions>) -> Result<()> {
        let entrypoint = CString::new(entrypoint).map_err(|_| Error::CStringFailed)?;
        let opts_ptr = options.map(|o| o.ptr).unwrap_or(std::ptr::null_mut());

        let mut error: *mut GError = std::ptr::null_mut();
        unsafe {
            frida_sys::frida_compiler_watch_sync(
                self.ptr,
                entrypoint.as_ptr(),
                opts_ptr,
                std::ptr::null_mut(),
                &mut error,
            )
        };

        if !error.is_null() {
            let message = unsafe { CStr::from_ptr((*error).message) }
                .to_string_lossy()
                .into_owned();
            let code = unsafe { (*error).code };
            unsafe { frida_sys::g_error_free(error) };
            return Err(Error::CompilerBuildFailed { code, message });
        }

        Ok(())
    }

    /// Access the raw pointer for signal wiring (`starting`, `finished`, `output`, `diagnostics`).
    pub fn as_raw(&self) -> *mut _FridaCompiler {
        self.ptr
    }
}

impl Drop for Compiler<'_> {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.ptr as _) }
    }
}
