/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Mach-O module inspection: enumerate segments, sections, symbols, exports, imports, binds,
//! rebases, dependencies, and the initializers and thread-local variables an image declares.
//!
//! Added in Frida 17.16.0 as the Darwin module API, which Frida 17.25 renamed to Mach-O and made
//! portable, so it reads Mach-O files on every platform Frida supports. [`Gum`](crate::Gum) must
//! have been obtained before a module is created.

use {
    crate::{
        DependencyDetails, DependencyType, ImportDetails, ImportType,
        enumeration::{Sink, collected, enumerate_details, string_at},
        glib_compat,
    },
    core::{
        ffi::{c_char, c_void},
        mem::MaybeUninit,
        ptr,
    },
    cstr_core::CString,
    frida_gum_sys as gum_sys,
    frida_gum_sys::{gboolean, gchar, gpointer},
};

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

/// The text in a fixed-size name field, which is NUL-terminated.
fn name_in(field: &[gchar]) -> String {
    // SAFETY: gum copies these names with `g_strlcpy`, which always terminates them.
    unsafe { string_at(field.as_ptr()) }.unwrap_or_default()
}

/// Index of `segment` among the segments `first_segment` starts, or zero if either is null.
///
/// # Safety
///
/// A non-null `segment` must be an element of the array a non-null `first_segment` starts.
unsafe fn segment_index(
    segment: *const gum_sys::GumMachoSegment,
    first_segment: *const gum_sys::GumMachoSegment,
) -> u16 {
    if segment.is_null() || first_segment.is_null() {
        0
    } else {
        unsafe { segment.offset_from(first_segment) as u16 }
    }
}

/// Mach-O segment details.
#[derive(Clone, Debug)]
pub struct MachoSegment {
    pub name: String,
    pub vm_address: u64,
    pub vm_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub protection: u32,
}

impl MachoSegment {
    unsafe fn from_raw(details: *const gum_sys::GumMachoSegment) -> Self {
        let details = unsafe { &*details };
        Self {
            name: name_in(&details.name),
            vm_address: details.vm_address,
            vm_size: details.vm_size,
            file_offset: details.file_offset,
            file_size: details.file_size,
            protection: details.protection as u32,
        }
    }
}

/// Mach-O section details.
#[derive(Clone, Debug)]
pub struct MachoSectionDetails {
    pub segment_name: String,
    pub section_name: String,
    pub vm_address: u64,
    pub size: u64,
}

impl MachoSectionDetails {
    unsafe fn from_raw(details: *const gum_sys::GumMachoSectionDetails) -> Self {
        let details = unsafe { &*details };
        Self {
            segment_name: name_in(&details.segment_name),
            section_name: name_in(&details.section_name),
            vm_address: details.vm_address,
            size: details.size,
        }
    }
}

/// Mach-O symbol details.
#[derive(Clone, Debug)]
pub struct MachoSymbolDetails {
    pub name: String,
    pub address: u64,
}

impl MachoSymbolDetails {
    unsafe fn from_raw(details: *const gum_sys::GumMachoSymbolDetails) -> Self {
        let details = unsafe { &*details };
        Self {
            name: unsafe { string_at(details.name) }.unwrap_or_default(),
            address: details.address,
        }
    }
}

/// Mach-O export details.
#[derive(Clone, Debug)]
pub struct MachoExportDetails {
    pub name: String,
    pub flags: u64,
    /// Offset of the symbol from the start of the image, or of its stub for an export with a
    /// resolver. Zero for a re-export, which has no place in this image.
    pub offset: u64,
}

impl MachoExportDetails {
    unsafe fn from_raw(details: *const gum_sys::GumMachoExportDetails) -> Self {
        let details = unsafe { &*details };
        let reexport = gum_sys::_GumMachoExportSymbolFlags_GUM_MACHO_EXPORT_REEXPORT as u64;
        let is_reexport = (details.flags & reexport) != 0;
        Self {
            name: unsafe { string_at(details.name) }.unwrap_or_default(),
            flags: details.flags,
            offset: if is_reexport {
                0
            } else {
                // SAFETY: an export that is not a re-export has an offset or a stub written
                // here, and the two share their place in the union.
                unsafe { details.__bindgen_anon_1.__bindgen_anon_1.offset }
            },
        }
    }
}

/// Mach-O bind details.
#[derive(Clone, Debug)]
pub struct MachoBindDetails {
    /// Index of the segment the bind is in, as [`MachoModule::segments`] orders them.
    pub segment_index: u16,
    pub offset: u64,
    pub type_: u8,
    pub library_ordinal: i16,
    pub symbol_name: String,
    pub symbol_flags: i8,
    pub addend: i64,
}

impl MachoBindDetails {
    /// # Safety
    ///
    /// `first_segment` must be the module's first segment, or null.
    unsafe fn from_raw(
        details: *const gum_sys::GumMachoBindDetails,
        first_segment: *const gum_sys::GumMachoSegment,
    ) -> Self {
        let details = unsafe { &*details };
        Self {
            // SAFETY: a bind's segment is one of the module's.
            segment_index: unsafe { segment_index(details.segment, first_segment) },
            offset: details.offset,
            type_: details.type_,
            library_ordinal: details.library_ordinal as i16,
            symbol_name: unsafe { string_at(details.symbol_name) }.unwrap_or_default(),
            symbol_flags: details.symbol_flags as i8,
            addend: details.addend,
        }
    }
}

/// A place in a Mach-O image that holds an address to adjust when the image is not loaded at its
/// preferred address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MachoRebaseDetails {
    /// Index of the segment the rebase is in, as [`MachoModule::segments`] orders them.
    pub segment_index: u16,
    /// Offset of the rebase in its segment.
    pub offset: u64,
    pub type_: u8,
    /// How far the image is from its preferred address.
    pub slide: u64,
}

/// Where a Mach-O image keeps a blob of its link-edit data: its chained fixups, or the starts of
/// its functions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MachoLinkeditData {
    pub vm_address: u64,
    pub file_offset: u64,
    pub size: u32,
}

/// The chained fixups of a Mach-O image.
pub type MachoChainedFixupsDetails = MachoLinkeditData;

/// The function starts of a Mach-O image.
pub type MachoFunctionStartsDetails = MachoLinkeditData;

/// The thread-local variables a Mach-O image declares.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MachoTlvParameters {
    pub num_descriptors: u32,
    /// File offset of the descriptors.
    pub descriptors_offset: u32,
    /// File offset of the variables' initial data.
    pub data_offset: u32,
    pub data_size: usize,
    /// Size of the zero-filled data that follows the initial data.
    pub bss_size: usize,
}

/// The descriptor of one thread-local variable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MachoTlvDescriptorDetails {
    /// File offset of the descriptor.
    pub file_offset: u64,
    pub thunk: u64,
    pub key: u64,
    /// Offset of the variable in the thread-local data.
    pub offset: usize,
}

/// A table in a Mach-O image, by its address and how many entries it has: a section of
/// initializer pointers, initializer offsets or terminator pointers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MachoPointerTable {
    pub address: u64,
    pub count: u64,
}

/// A section of pointers to a Mach-O image's initializers.
pub type MachoInitPointersDetails = MachoPointerTable;

/// A section of 32-bit offsets to a Mach-O image's initializers.
pub type MachoInitOffsetsDetails = MachoPointerTable;

/// A section of pointers to a Mach-O image's terminators.
pub type MachoTermPointersDetails = MachoPointerTable;

/// An entry of a threaded bind, decoded from the 64 bits an arm64e image stores in the slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MachoThreadedItem {
    pub is_authenticated: bool,
    /// What the entry is: [`MachoThreadedItem::REBASE`] or [`MachoThreadedItem::BIND`].
    pub type_: u8,
    /// Distance to the next entry, in pointers. Zero for the last one.
    pub delta: u16,
    pub key: u8,
    pub has_address_diversity: bool,
    pub diversity: u16,
    /// For a bind, the index of what to bind in the table of threaded binds. Zero for a rebase.
    pub bind_ordinal: u16,
    /// For a rebase, the address to adjust. Zero for a bind.
    pub rebase_address: u64,
}

impl MachoThreadedItem {
    pub const REBASE: u8 = gum_sys::_GumMachoThreadedItemType_GUM_MACHO_THREADED_REBASE as u8;
    pub const BIND: u8 = gum_sys::_GumMachoThreadedItemType_GUM_MACHO_THREADED_BIND as u8;

    /// Decodes the value in a threaded slot.
    pub fn parse(value: u64) -> Self {
        // Zeroed, as only the member for the entry's type is written.
        let mut item = MaybeUninit::<gum_sys::GumMachoThreadedItem>::zeroed();
        let item = unsafe {
            gum_sys::gum_macho_threaded_item_parse(value, item.as_mut_ptr());
            item.assume_init()
        };
        Self {
            is_authenticated: item.is_authenticated != 0,
            type_: item.type_,
            delta: item.delta,
            key: item.key,
            has_address_diversity: item.has_address_diversity != 0,
            diversity: item.diversity,
            bind_ordinal: item.bind_ordinal,
            rebase_address: item.rebase_address,
        }
    }
}

unsafe fn dependency_from_raw(details: *const gum_sys::GumDependencyDetails) -> DependencyDetails {
    let details = unsafe { &*details };
    DependencyDetails {
        name: unsafe { string_at(details.name) }.unwrap_or_default(),
        typ: match details.type_ {
            gum_sys::GumDependencyType_GUM_DEPENDENCY_WEAK => DependencyType::Weak,
            gum_sys::GumDependencyType_GUM_DEPENDENCY_REEXPORT => DependencyType::Reexport,
            gum_sys::GumDependencyType_GUM_DEPENDENCY_UPWARD => DependencyType::Upward,
            _ => DependencyType::Regular,
        },
    }
}

unsafe fn import_from_raw(details: *const gum_sys::GumImportDetails) -> ImportDetails {
    let details = unsafe { &*details };
    ImportDetails {
        typ: match details.type_ {
            gum_sys::GumImportType_GUM_IMPORT_FUNCTION => ImportType::Function,
            gum_sys::GumImportType_GUM_IMPORT_VARIABLE => ImportType::Variable,
            _ => ImportType::Unknown,
        },
        name: unsafe { string_at(details.name) }.unwrap_or_default(),
        module: unsafe { string_at(details.module) },
        address: details.address as usize,
        slot: details.slot as usize,
    }
}

/// What [`MachoModule::enumerate_imports`] passes Gum as the one user data its two callbacks share.
struct ImportSinks<'a> {
    found: Sink<'a, *const gum_sys::GumImportDetails>,
    resolve: &'a mut dyn FnMut(Option<&str>, &str) -> u64,
}

unsafe extern "C" fn found_import_callout(
    details: *const gum_sys::GumImportDetails,
    user_data: gpointer,
) -> gboolean {
    let sinks = unsafe { &mut *(user_data as *mut ImportSinks<'_>) };
    (sinks.found)(details) as gboolean
}

unsafe extern "C" fn resolve_export_callout(
    module_name: *const c_char,
    symbol_name: *const c_char,
    user_data: gpointer,
) -> gum_sys::GumAddress {
    let sinks = unsafe { &mut *(user_data as *mut ImportSinks<'_>) };
    let module_name = unsafe { string_at(module_name.cast()) };
    let symbol_name = unsafe { string_at(symbol_name.cast()) }.unwrap_or_default();
    (sinks.resolve)(module_name.as_deref(), &symbol_name)
}

/// The task whose memory holds an image mapped into this process.
#[cfg(target_vendor = "apple")]
fn current_task() -> gum_sys::GumDarwinPort {
    unsafe extern "C" {
        static mach_task_self_: gum_sys::GumDarwinPort;
    }
    // SAFETY: the system sets this before any of the process's code runs and never writes it
    // again. It is what the C macro `mach_task_self()` reads.
    unsafe { mach_task_self_ }
}

/// The task whose memory holds an image mapped into this process. Only Darwin has tasks; elsewhere
/// gum reads this process's memory whatever the task.
#[cfg(not(target_vendor = "apple"))]
fn current_task() -> gum_sys::GumDarwinPort {
    0
}

/// A Mach-O module parsed by Frida.
pub struct MachoModule {
    inner: *mut gum_sys::GumMachoModule,
}

impl MachoModule {
    /// Open a Mach-O file from disk. From a universal binary, the first slice for a CPU Frida
    /// supports is taken.
    ///
    /// Returns `None` if the file cannot be opened or parsed.
    pub fn from_file(path: &str) -> Option<Self> {
        let path = CString::new(path).ok()?;
        let mut error: *mut gum_sys::GError = ptr::null_mut();
        let inner = unsafe {
            gum_sys::gum_macho_module_new_from_file(
                path.as_ptr().cast(),
                gum_sys::GumCpuType_GUM_CPU_INVALID,
                gum_sys::_GumPtrauthSupport_GUM_PTRAUTH_INVALID as _,
                gum_sys::GumMachoModuleFlags_GUM_MACHO_MODULE_FLAGS_NONE,
                &mut error,
            )
        };
        unsafe { Self::from_new(inner, error) }
    }

    /// Parse a Mach-O file held in `bytes`, which are copied. From a universal binary, the first
    /// slice for a CPU Frida supports is taken.
    ///
    /// Returns `None` if the bytes cannot be parsed.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut error: *mut gum_sys::GError = ptr::null_mut();
        unsafe {
            let blob = glib_compat::g_bytes_new(bytes.as_ptr().cast(), bytes.len() as _);
            let inner = gum_sys::gum_macho_module_new_from_blob(
                blob,
                gum_sys::GumCpuType_GUM_CPU_INVALID,
                gum_sys::_GumPtrauthSupport_GUM_PTRAUTH_INVALID as _,
                gum_sys::GumMachoModuleFlags_GUM_MACHO_MODULE_FLAGS_NONE,
                &mut error,
            );
            // The module holds its own reference to the blob.
            glib_compat::g_bytes_unref(blob);
            Self::from_new(inner, error)
        }
    }

    /// Open a Mach-O module already mapped into this process at `base_address`.
    ///
    /// `base_address` must be the base of a mapped Mach-O image: the image is read on first use,
    /// not here, and Gum reads it in place without checking that the memory is mapped. Returns
    /// `None` for a null `base_address` or a `name` with a NUL in it.
    pub fn from_memory(name: &str, base_address: u64) -> Option<Self> {
        if base_address == 0 {
            // Gum asserts on it.
            return None;
        }
        let name = CString::new(name).ok()?;
        let mut error: *mut gum_sys::GError = ptr::null_mut();
        let inner = unsafe {
            gum_sys::gum_macho_module_new_from_memory(
                name.as_ptr().cast(),
                current_task(),
                base_address,
                gum_sys::GumMachoModuleFlags_GUM_MACHO_MODULE_FLAGS_NONE,
                &mut error,
            )
        };
        unsafe { Self::from_new(inner, error) }
    }

    /// Takes ownership of what a constructor returned, freeing the error it may have set.
    unsafe fn from_new(
        inner: *mut gum_sys::GumMachoModule,
        error: *mut gum_sys::GError,
    ) -> Option<Self> {
        if !error.is_null() {
            unsafe { glib_compat::g_error_free(error) };
        }
        if inner.is_null() {
            None
        } else {
            Some(Self { inner })
        }
    }

    /// Reads the image if it has not been read yet, which a module from memory puts off until
    /// it is first used. Returns whether the module has an image.
    ///
    /// A module without one has nothing in it: every enumeration is empty.
    pub fn ensure_image_loaded(&self) -> bool {
        let mut error: *mut gum_sys::GError = ptr::null_mut();
        let loaded =
            unsafe { gum_sys::gum_macho_module_ensure_image_loaded(self.inner, &mut error) };
        if !error.is_null() {
            unsafe { glib_compat::g_error_free(error) };
        }
        loaded != 0
    }

    /// How far the image is from its preferred address: the difference between where it is loaded
    /// and the address of its `__TEXT` segment. A module from a file is not loaded anywhere, so
    /// its slide takes its addresses to offsets from the start of the image.
    pub fn slide(&self) -> u64 {
        unsafe { gum_sys::gum_macho_module_get_slide(self.inner) }
    }

    /// Whether `address` is in a section of code.
    pub fn is_address_in_text_section(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_macho_module_is_address_in_text_section(self.inner, address) != 0 }
    }

    /// Whether the image leaves the symbols it re-exports out of its own exports, as images
    /// built for macOS 10.11 and iOS 9.0 or later do.
    pub fn lacks_exports_for_reexports(&self) -> bool {
        unsafe { gum_sys::gum_macho_module_get_lacks_exports_for_reexports(self.inner) != 0 }
    }

    /// The module's first segment, or null if its image cannot be read.
    fn first_segment(&self) -> *const gum_sys::GumMachoSegment {
        unsafe { gum_sys::gum_macho_module_get_nth_segment(self.inner, 0) }
    }

    /// Enumerate segments in this module.
    pub fn segments(&self) -> Vec<MachoSegment> {
        let mut result = Vec::new();
        loop {
            let segment =
                unsafe { gum_sys::gum_macho_module_get_nth_segment(self.inner, result.len() as _) };
            if segment.is_null() {
                return result;
            }
            result.push(unsafe { MachoSegment::from_raw(segment) });
        }
    }

    /// Enumerate sections in this module.
    pub fn enumerate_sections<F>(&self, mut callback: F)
    where
        F: FnMut(MachoSectionDetails) -> bool,
    {
        enumerate_details(
            |details| callback(unsafe { MachoSectionDetails::from_raw(details) }),
            |func, data| unsafe {
                gum_sys::gum_macho_module_enumerate_sections(self.inner, Some(func), data)
            },
        );
    }

    /// Enumerate symbols in this module.
    pub fn enumerate_symbols<F>(&self, mut callback: F)
    where
        F: FnMut(MachoSymbolDetails) -> bool,
    {
        enumerate_details(
            |details| callback(unsafe { MachoSymbolDetails::from_raw(details) }),
            |func, data| unsafe {
                gum_sys::gum_macho_module_enumerate_symbols(self.inner, Some(func), data)
            },
        );
    }

    /// The address of the symbol named `name`, or `None` if the image has no such symbol or the
    /// symbol has no address.
    pub fn resolve_symbol_address(&self, name: &str) -> Option<u64> {
        let name = CString::new(name).ok()?;
        let address = unsafe {
            gum_sys::gum_macho_module_resolve_symbol_address(self.inner, name.as_ptr().cast())
        };
        (address != 0).then_some(address)
    }

    /// Enumerate exports from this module.
    pub fn enumerate_exports<F>(&self, mut callback: F)
    where
        F: FnMut(MachoExportDetails) -> bool,
    {
        enumerate_details(
            |details| callback(unsafe { MachoExportDetails::from_raw(details) }),
            |func, data| unsafe {
                gum_sys::gum_macho_module_enumerate_exports(self.inner, Some(func), data)
            },
        );
    }

    /// Enumerate the exports whose names start with `prefix`.
    pub fn enumerate_exports_with_prefix<F>(&self, prefix: &str, mut callback: F)
    where
        F: FnMut(MachoExportDetails) -> bool,
    {
        let Ok(prefix) = CString::new(prefix) else {
            // No name has a NUL in it.
            return;
        };
        enumerate_details(
            |details| callback(unsafe { MachoExportDetails::from_raw(details) }),
            |func, data| unsafe {
                gum_sys::gum_macho_module_enumerate_exports_with_prefix(
                    self.inner,
                    prefix.as_ptr().cast(),
                    Some(func),
                    data,
                )
            },
        );
    }

    /// The export named `name`, compared exactly.
    pub fn resolve_export(&self, name: &str) -> Option<MachoExportDetails> {
        let name = CString::new(name).ok()?;
        let mut details = MaybeUninit::<gum_sys::GumMachoExportDetails>::uninit();
        unsafe {
            let found = gum_sys::gum_macho_module_resolve_export(
                self.inner,
                name.as_ptr().cast(),
                details.as_mut_ptr(),
            );
            // Its name is `name`, which is still alive.
            (found != 0).then(|| MachoExportDetails::from_raw(details.as_ptr()))
        }
    }

    /// Enumerate the symbols this module imports: those it binds, binds lazily, and binds through
    /// chained fixups.
    ///
    /// `resolver` is asked for the address of each import bound through chained fixups, given the
    /// name of the dependency it comes from, if it names one, and the name of the symbol. Gum
    /// tells those imports apart by that address, so a resolver that gives several the same one
    /// leaves only the last of them. Other imports are reported with no address.
    pub fn enumerate_imports<R, F>(&self, mut resolver: R, mut callback: F)
    where
        R: FnMut(Option<&str>, &str) -> u64,
        F: FnMut(ImportDetails) -> bool,
    {
        let mut found = |details| callback(unsafe { import_from_raw(details) });
        let mut sinks = ImportSinks {
            found: &mut found,
            resolve: &mut resolver,
        };
        unsafe {
            gum_sys::gum_macho_module_enumerate_imports(
                self.inner,
                Some(found_import_callout),
                // Gum asserts that there is one.
                Some(resolve_export_callout),
                &mut sinks as *mut _ as gpointer,
            );
        }
    }

    /// Enumerate bind entries (external symbol references).
    pub fn enumerate_binds<F>(&self, mut callback: F)
    where
        F: FnMut(MachoBindDetails) -> bool,
    {
        let first_segment = self.first_segment();
        enumerate_details(
            |details| callback(unsafe { MachoBindDetails::from_raw(details, first_segment) }),
            |func, data| unsafe {
                gum_sys::gum_macho_module_enumerate_binds(self.inner, Some(func), data)
            },
        );
    }

    /// Enumerate the binds dyld puts off until the symbol is first used.
    pub fn enumerate_lazy_binds<F>(&self, mut callback: F)
    where
        F: FnMut(MachoBindDetails) -> bool,
    {
        let first_segment = self.first_segment();
        enumerate_details(
            |details| callback(unsafe { MachoBindDetails::from_raw(details, first_segment) }),
            |func, data| unsafe {
                gum_sys::gum_macho_module_enumerate_lazy_binds(self.inner, Some(func), data)
            },
        );
    }

    /// Enumerate the addresses in the image to adjust when it is not loaded at its preferred
    /// address.
    pub fn enumerate_rebases<F>(&self, mut callback: F)
    where
        F: FnMut(MachoRebaseDetails) -> bool,
    {
        let first_segment = self.first_segment();
        enumerate_details(
            |details: *const gum_sys::GumMachoRebaseDetails| {
                let details = unsafe { &*details };
                callback(MachoRebaseDetails {
                    // SAFETY: a rebase's segment is one of the module's.
                    segment_index: unsafe { segment_index(details.segment, first_segment) },
                    offset: details.offset,
                    type_: details.type_,
                    slide: details.slide,
                })
            },
            |func, data| unsafe {
                gum_sys::gum_macho_module_enumerate_rebases(self.inner, Some(func), data)
            },
        );
    }

    /// Enumerate the image's chained fixups: one entry for each load command that has them.
    pub fn enumerate_chained_fixups<F>(&self, mut callback: F)
    where
        F: FnMut(MachoChainedFixupsDetails) -> bool,
    {
        enumerate_details(
            |details: *const gum_sys::GumMachoChainedFixupsDetails| {
                let details = unsafe { &*details };
                callback(MachoLinkeditData {
                    vm_address: details.vm_address,
                    file_offset: details.file_offset,
                    size: details.size,
                })
            },
            |func, data| unsafe {
                gum_sys::gum_macho_module_enumerate_chained_fixups(self.inner, Some(func), data)
            },
        );
    }

    /// Enumerate the image's function starts: one entry for each load command that has them.
    pub fn enumerate_function_starts<F>(&self, mut callback: F)
    where
        F: FnMut(MachoFunctionStartsDetails) -> bool,
    {
        enumerate_details(
            |details: *const gum_sys::GumMachoFunctionStartsDetails| {
                let details = unsafe { &*details };
                callback(MachoLinkeditData {
                    vm_address: details.vm_address,
                    file_offset: details.file_offset,
                    size: details.size,
                })
            },
            |func, data| unsafe {
                gum_sys::gum_macho_module_enumerate_function_starts(self.inner, Some(func), data)
            },
        );
    }

    /// The thread-local variables the image declares. All zero if it declares none.
    pub fn tlv_parameters(&self) -> MachoTlvParameters {
        let mut params = MaybeUninit::<gum_sys::GumMachoTlvParameters>::uninit();
        let params = unsafe {
            gum_sys::gum_macho_module_query_tlv_parameters(self.inner, params.as_mut_ptr());
            // Every member is written, whether or not there is an image.
            params.assume_init()
        };
        MachoTlvParameters {
            num_descriptors: params.num_descriptors,
            descriptors_offset: params.descriptors_offset,
            data_offset: params.data_offset,
            data_size: params.data_size as usize,
            bss_size: params.bss_size as usize,
        }
    }

    /// Enumerate the descriptors of the image's thread-local variables.
    pub fn enumerate_tlv_descriptors<F>(&self, mut callback: F)
    where
        F: FnMut(MachoTlvDescriptorDetails) -> bool,
    {
        enumerate_details(
            |details: *const gum_sys::GumMachoTlvDescriptorDetails| {
                let details = unsafe { &*details };
                callback(MachoTlvDescriptorDetails {
                    file_offset: details.file_offset,
                    thunk: details.thunk,
                    key: details.key,
                    offset: details.offset as usize,
                })
            },
            |func, data| unsafe {
                gum_sys::gum_macho_module_enumerate_tlv_descriptors(self.inner, Some(func), data)
            },
        );
    }

    /// Enumerate the sections of pointers to the image's initializers.
    pub fn enumerate_init_pointers<F>(&self, mut callback: F)
    where
        F: FnMut(MachoInitPointersDetails) -> bool,
    {
        enumerate_details(
            |details: *const gum_sys::GumMachoInitPointersDetails| {
                let details = unsafe { &*details };
                callback(MachoPointerTable {
                    address: details.address,
                    count: details.count,
                })
            },
            |func, data| unsafe {
                gum_sys::gum_macho_module_enumerate_init_pointers(self.inner, Some(func), data)
            },
        );
    }

    /// Enumerate the sections of 32-bit offsets to the image's initializers.
    pub fn enumerate_init_offsets<F>(&self, mut callback: F)
    where
        F: FnMut(MachoInitOffsetsDetails) -> bool,
    {
        enumerate_details(
            |details: *const gum_sys::GumMachoInitOffsetsDetails| {
                let details = unsafe { &*details };
                callback(MachoPointerTable {
                    address: details.address,
                    count: details.count,
                })
            },
            |func, data| unsafe {
                gum_sys::gum_macho_module_enumerate_init_offsets(self.inner, Some(func), data)
            },
        );
    }

    /// Enumerate the sections of pointers to the image's terminators.
    pub fn enumerate_term_pointers<F>(&self, mut callback: F)
    where
        F: FnMut(MachoTermPointersDetails) -> bool,
    {
        enumerate_details(
            |details: *const gum_sys::GumMachoTermPointersDetails| {
                let details = unsafe { &*details };
                callback(MachoPointerTable {
                    address: details.address,
                    count: details.count,
                })
            },
            |func, data| unsafe {
                gum_sys::gum_macho_module_enumerate_term_pointers(self.inner, Some(func), data)
            },
        );
    }

    /// Enumerate the libraries this module depends on, in the order binds number them from one.
    pub fn enumerate_dependencies<F>(&self, mut callback: F)
    where
        F: FnMut(DependencyDetails) -> bool,
    {
        enumerate_details(
            |details| callback(unsafe { dependency_from_raw(details) }),
            |func, data| unsafe {
                gum_sys::gum_macho_module_enumerate_dependencies(self.inner, Some(func), data)
            },
        );
    }

    /// The name of the library a bind's `library_ordinal` stands for: a dependency for an ordinal
    /// from one up, and this module, if it has a name, for zero. `None` for any other ordinal.
    pub fn dependency_by_ordinal(&self, ordinal: i32) -> Option<String> {
        // Owned by the module.
        unsafe {
            string_at(gum_sys::gum_macho_module_get_dependency_by_ordinal(
                self.inner, ordinal,
            ))
        }
    }

    /// Collect all sections into a Vec.
    pub fn sections(&self) -> Vec<MachoSectionDetails> {
        collected(|sink| self.enumerate_sections(sink))
    }

    /// Collect all symbols into a Vec.
    pub fn symbols(&self) -> Vec<MachoSymbolDetails> {
        collected(|sink| self.enumerate_symbols(sink))
    }

    /// Collect all exports into a Vec.
    pub fn exports(&self) -> Vec<MachoExportDetails> {
        collected(|sink| self.enumerate_exports(sink))
    }

    /// Collect all imports into a Vec, with no address for any of them. Of the imports bound
    /// through chained fixups, which [`MachoModule::enumerate_imports`] needs a resolver to tell
    /// apart, there is only the last.
    pub fn imports(&self) -> Vec<ImportDetails> {
        collected(|sink| self.enumerate_imports(|_, _| 0, sink))
    }

    /// Collect all binds into a Vec.
    pub fn binds(&self) -> Vec<MachoBindDetails> {
        collected(|sink| self.enumerate_binds(sink))
    }

    /// Collect all lazy binds into a Vec.
    pub fn lazy_binds(&self) -> Vec<MachoBindDetails> {
        collected(|sink| self.enumerate_lazy_binds(sink))
    }

    /// Collect all rebases into a Vec.
    pub fn rebases(&self) -> Vec<MachoRebaseDetails> {
        collected(|sink| self.enumerate_rebases(sink))
    }

    /// Collect all chained fixups into a Vec.
    pub fn chained_fixups(&self) -> Vec<MachoChainedFixupsDetails> {
        collected(|sink| self.enumerate_chained_fixups(sink))
    }

    /// Collect all function starts into a Vec.
    pub fn function_starts(&self) -> Vec<MachoFunctionStartsDetails> {
        collected(|sink| self.enumerate_function_starts(sink))
    }

    /// Collect all thread-local variable descriptors into a Vec.
    pub fn tlv_descriptors(&self) -> Vec<MachoTlvDescriptorDetails> {
        collected(|sink| self.enumerate_tlv_descriptors(sink))
    }

    /// Collect all sections of initializer pointers into a Vec.
    pub fn init_pointers(&self) -> Vec<MachoInitPointersDetails> {
        collected(|sink| self.enumerate_init_pointers(sink))
    }

    /// Collect all sections of initializer offsets into a Vec.
    pub fn init_offsets(&self) -> Vec<MachoInitOffsetsDetails> {
        collected(|sink| self.enumerate_init_offsets(sink))
    }

    /// Collect all sections of terminator pointers into a Vec.
    pub fn term_pointers(&self) -> Vec<MachoTermPointersDetails> {
        collected(|sink| self.enumerate_term_pointers(sink))
    }

    /// Collect all dependencies into a Vec.
    pub fn dependencies(&self) -> Vec<DependencyDetails> {
        collected(|sink| self.enumerate_dependencies(sink))
    }
}

impl Drop for MachoModule {
    fn drop(&mut self) {
        unsafe { gum_sys::g_object_unref(self.inner as *mut c_void) };
    }
}

/// The name [`MachoModule`] had before Frida 17.25.
#[deprecated(note = "renamed to `MachoModule`")]
pub type DarwinModule = MachoModule;

/// The name [`MachoSegment`] had before Frida 17.25.
#[deprecated(note = "renamed to `MachoSegment`")]
pub type DarwinSegment = MachoSegment;

/// The name [`MachoSectionDetails`] had before Frida 17.25.
#[deprecated(note = "renamed to `MachoSectionDetails`")]
pub type DarwinSectionDetails = MachoSectionDetails;

/// The name [`MachoSymbolDetails`] had before Frida 17.25.
#[deprecated(note = "renamed to `MachoSymbolDetails`")]
pub type DarwinSymbolDetails = MachoSymbolDetails;

/// The name [`MachoExportDetails`] had before Frida 17.25.
#[deprecated(note = "renamed to `MachoExportDetails`")]
pub type DarwinExportDetails = MachoExportDetails;

/// The name [`MachoBindDetails`] had before Frida 17.25.
#[deprecated(note = "renamed to `MachoBindDetails`")]
pub type DarwinBindDetails = MachoBindDetails;
