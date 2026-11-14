/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! PE module inspection: parse a Portable Executable from a file, from bytes, or from an image
//! mapped into this process, and read its headers, sections, imports, exports, relocations, TLS
//! data and version.
//!
//! Added in Frida 17.25; [`PeModule::version`] and [`PeDirectoryIndex::Resource`] in 17.26.3. The
//! parser is portable, so it reads PE files on every platform Frida supports.
//!
//! ```no_run
//! use frida_gum::{Gum, PeModule};
//!
//! let gum = Gum::obtain();
//! let module = PeModule::from_file(&gum, r"C:\Windows\System32\kernel32.dll").unwrap();
//! println!("{:?} {:?}", module.machine(), module.version());
//! for export in module.exports() {
//!     println!("{} {:?}", export.ordinal, export.name);
//! }
//! ```

use {
    crate::{
        DependencyDetails, DependencyType, Gum, PageProtection,
        enumeration::{Sink, collected, details_callout, string_at},
        glib_compat,
    },
    core::{ffi::c_void, ptr},
    cstr_core::CString,
    frida_gum_sys as gum_sys,
    frida_gum_sys::{gboolean, gpointer},
    num::FromPrimitive,
};

#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, string::String, vec::Vec};

/// The machine a PE image targets, from its COFF header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeMachine {
    Unknown,
    I386,
    /// 32-bit ARM, Thumb-2.
    ArmNt,
    Amd64,
    Arm64,
    /// A machine type the parser has no name for, as the header gives it.
    Other(u32),
}

impl PeMachine {
    fn from_raw(raw: gum_sys::GumPeMachine) -> Self {
        match raw {
            gum_sys::GumPeMachine_GUM_PE_MACHINE_UNKNOWN => Self::Unknown,
            gum_sys::GumPeMachine_GUM_PE_MACHINE_I386 => Self::I386,
            gum_sys::GumPeMachine_GUM_PE_MACHINE_ARMNT => Self::ArmNt,
            gum_sys::GumPeMachine_GUM_PE_MACHINE_AMD64 => Self::Amd64,
            gum_sys::GumPeMachine_GUM_PE_MACHINE_ARM64 => Self::Arm64,
            other => Self::Other(other as u32),
        }
    }
}

/// Where a [`PeModule`] reads its image from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeSourceMode {
    /// A file or a buffer, laid out as on disk.
    Offline,
    /// An image the loader mapped into this process.
    Online,
}

/// A data directory of the optional header that the parser knows.
///
/// [`PeModule::directory`] takes only these: the underlying lookup indexes the header's table
/// without checking the index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeDirectoryIndex {
    Export,
    Import,
    /// Added in Frida 17.26.3.
    Resource,
    Exception,
    BaseReloc,
    Tls,
    LoadConfig,
    DelayImport,
}

impl PeDirectoryIndex {
    fn to_raw(self) -> gum_sys::GumPeDirectoryIndex {
        match self {
            Self::Export => gum_sys::GumPeDirectoryIndex_GUM_PE_DIRECTORY_EXPORT,
            Self::Import => gum_sys::GumPeDirectoryIndex_GUM_PE_DIRECTORY_IMPORT,
            Self::Resource => gum_sys::GumPeDirectoryIndex_GUM_PE_DIRECTORY_RESOURCE,
            Self::Exception => gum_sys::GumPeDirectoryIndex_GUM_PE_DIRECTORY_EXCEPTION,
            Self::BaseReloc => gum_sys::GumPeDirectoryIndex_GUM_PE_DIRECTORY_BASERELOC,
            Self::Tls => gum_sys::GumPeDirectoryIndex_GUM_PE_DIRECTORY_TLS,
            Self::LoadConfig => gum_sys::GumPeDirectoryIndex_GUM_PE_DIRECTORY_LOAD_CONFIG,
            Self::DelayImport => gum_sys::GumPeDirectoryIndex_GUM_PE_DIRECTORY_DELAY_IMPORT,
        }
    }
}

/// A data directory: where it is in the image and how large. Both are zero when the image has
/// no such directory.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeDataDirectory {
    pub rva: u32,
    pub size: u32,
}

/// A section of a PE image.
#[derive(Clone, Debug, PartialEq)]
pub struct PeSectionDetails {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_data_offset: u32,
    pub raw_data_size: u32,
    /// The section header's `Characteristics` flags.
    pub characteristics: u32,
    /// The page protection those flags ask for.
    pub protection: PageProtection,
}

impl PeSectionDetails {
    unsafe fn from_raw(details: *const gum_sys::GumPeSectionDetails) -> Self {
        let details = unsafe { &*details };
        Self {
            name: unsafe { string_at(details.name) }.unwrap_or_default(),
            virtual_address: details.virtual_address,
            virtual_size: details.virtual_size,
            raw_data_offset: details.raw_data_offset,
            raw_data_size: details.raw_data_size,
            characteristics: details.characteristics,
            protection: PageProtection::from_u32(details.protection)
                .unwrap_or(PageProtection::NoAccess),
        }
    }
}

/// How a base relocation patches its target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeRelocationType {
    /// Padding; nothing is patched.
    Absolute,
    High,
    Low,
    HighLow,
    HighAdj,
    Dir64,
    /// A type the parser has no name for, as the relocation block gives it.
    Other(u32),
}

impl PeRelocationType {
    fn from_raw(raw: gum_sys::GumPeRelocationType) -> Self {
        match raw {
            gum_sys::GumPeRelocationType_GUM_PE_RELOCATION_ABSOLUTE => Self::Absolute,
            gum_sys::GumPeRelocationType_GUM_PE_RELOCATION_HIGH => Self::High,
            gum_sys::GumPeRelocationType_GUM_PE_RELOCATION_LOW => Self::Low,
            gum_sys::GumPeRelocationType_GUM_PE_RELOCATION_HIGHLOW => Self::HighLow,
            gum_sys::GumPeRelocationType_GUM_PE_RELOCATION_HIGHADJ => Self::HighAdj,
            gum_sys::GumPeRelocationType_GUM_PE_RELOCATION_DIR64 => Self::Dir64,
            other => Self::Other(other as u32),
        }
    }
}

/// A base relocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeRelocationDetails {
    pub rva: u32,
    pub typ: PeRelocationType,
}

/// Whether the loader binds an import when it loads the image or on first use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeImportLoadMode {
    Regular,
    Delayed,
}

/// What an import asks its module for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeImportSymbol {
    Name(String),
    Ordinal(u16),
}

/// An imported symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeImportDetails {
    /// The module the symbol comes from.
    pub module_name: String,
    pub symbol: PeImportSymbol,
    pub load_mode: PeImportLoadMode,
    /// Where in the image the loader stores the resolved address.
    pub slot_rva: u32,
}

impl PeImportDetails {
    unsafe fn from_raw(details: *const gum_sys::GumPeImportDetails) -> Self {
        let details = unsafe { &*details };
        let symbol = if details.type_ == gum_sys::GumPeImportType_GUM_PE_IMPORT_BY_ORDINAL {
            // SAFETY: the type says which member of the union was written.
            PeImportSymbol::Ordinal(unsafe { details.__bindgen_anon_1.ordinal })
        } else {
            // SAFETY: as above.
            PeImportSymbol::Name(
                unsafe { string_at(details.__bindgen_anon_1.name) }.unwrap_or_default(),
            )
        };
        Self {
            module_name: unsafe { string_at(details.module_name) }.unwrap_or_default(),
            symbol,
            load_mode: if details.load_mode
                == gum_sys::GumPeImportLoadMode_GUM_PE_IMPORT_LOAD_MODE_DELAYED
            {
                PeImportLoadMode::Delayed
            } else {
                PeImportLoadMode::Regular
            },
            slot_rva: details.slot_rva,
        }
    }
}

/// Where an export leads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeExportTarget {
    /// Code or data in this image.
    Rva(u32),
    /// Another module's export, as `MODULE.Symbol` or `MODULE.#ordinal`.
    Forwarder(String),
}

/// An exported symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeExportDetails {
    pub ordinal: u16,
    /// `None` for a symbol exported by ordinal only.
    pub name: Option<String>,
    pub target: PeExportTarget,
}

impl PeExportDetails {
    unsafe fn from_raw(details: *const gum_sys::GumPeExportDetails) -> Self {
        let details = unsafe { &*details };
        let target = if details.type_ == gum_sys::GumPeExportType_GUM_PE_EXPORT_FORWARDED {
            // SAFETY: the type says which member of the union was written.
            PeExportTarget::Forwarder(
                unsafe { string_at(details.__bindgen_anon_1.forwarder) }.unwrap_or_default(),
            )
        } else {
            // SAFETY: as above.
            PeExportTarget::Rva(unsafe { details.__bindgen_anon_1.rva })
        };
        Self {
            ordinal: details.ordinal,
            name: unsafe { string_at(details.name) },
            target,
        }
    }
}

/// The thread-local storage a PE image declares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeTlsDetails {
    /// The initialised data each thread's block starts from.
    pub template_rva: u32,
    pub template_size: usize,
    /// Bytes of zeroes that follow the template in each thread's block.
    pub zero_fill_size: usize,
    /// Where the loader stores the image's TLS index.
    pub index_rva: u32,
}

unsafe extern "C" fn rva_callout(rva: gum_sys::GumAddress, user_data: gpointer) -> gboolean {
    let sink = unsafe { &mut *(user_data as *mut Sink<'_, u64>) };
    sink(rva) as gboolean
}

/// A parsed Portable Executable image.
pub struct PeModule {
    inner: *mut gum_sys::GumPeModule,
}

impl PeModule {
    /// Parses the PE file at `path`.
    ///
    /// Returns `None` if the file cannot be read or is not a PE image.
    pub fn from_file(_gum: &Gum, path: &str) -> Option<Self> {
        let path = CString::new(path).ok()?;
        let mut error: *mut gum_sys::GError = ptr::null_mut();
        let inner =
            unsafe { gum_sys::gum_pe_module_new_from_file(path.as_ptr().cast(), &mut error) };
        unsafe { Self::from_new(inner, error) }
    }

    /// Parses a PE image held in `bytes`, laid out as on disk. The bytes are copied.
    ///
    /// Returns `None` if they are not a PE image.
    pub fn from_bytes(_gum: &Gum, bytes: &[u8]) -> Option<Self> {
        let mut error: *mut gum_sys::GError = ptr::null_mut();
        unsafe {
            let blob = glib_compat::g_bytes_new(bytes.as_ptr().cast(), bytes.len() as _);
            let inner = gum_sys::gum_pe_module_new_from_blob(blob, &mut error);
            // The module holds its own reference to the blob.
            glib_compat::g_bytes_unref(blob);
            Self::from_new(inner, error)
        }
    }

    /// Parses the PE image the loader mapped at `base_address` in this process.
    ///
    /// Returns `None` if no PE image starts there.
    ///
    /// # Safety
    ///
    /// `base_address` must point at readable memory. If an image starts there, all of it must
    /// be mapped as the loader maps it and stay mapped for as long as the returned module is
    /// used: the parser reads the image in place and trusts its headers.
    pub unsafe fn from_memory(_gum: &Gum, base_address: u64) -> Option<Self> {
        let mut error: *mut gum_sys::GError = ptr::null_mut();
        let inner = unsafe { gum_sys::gum_pe_module_new_from_memory(base_address, &mut error) };
        unsafe { Self::from_new(inner, error) }
    }

    /// Takes ownership of what a constructor returned, freeing the error it may have set.
    unsafe fn from_new(
        inner: *mut gum_sys::GumPeModule,
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

    /// Size of a pointer in the image: 4 for PE32, 8 for PE32+.
    pub fn pointer_size(&self) -> u32 {
        unsafe { gum_sys::gum_pe_module_get_pointer_size(self.inner) }
    }

    /// The machine the image targets.
    pub fn machine(&self) -> PeMachine {
        PeMachine::from_raw(unsafe { gum_sys::gum_pe_module_get_machine(self.inner) })
    }

    /// The address the image prefers to be loaded at.
    pub fn image_base(&self) -> u64 {
        unsafe { gum_sys::gum_pe_module_get_image_base(self.inner) }
    }

    /// Size of the image once mapped.
    pub fn size_of_image(&self) -> usize {
        unsafe { gum_sys::gum_pe_module_get_size_of_image(self.inner) as usize }
    }

    /// Size of the headers, section table included.
    pub fn size_of_headers(&self) -> usize {
        unsafe { gum_sys::gum_pe_module_get_size_of_headers(self.inner) as usize }
    }

    /// RVA of the entry point, or zero if the image has none.
    pub fn entrypoint(&self) -> u32 {
        unsafe { gum_sys::gum_pe_module_get_entrypoint(self.inner) }
    }

    /// Whether the image is read as laid out on disk or as mapped.
    pub fn source_mode(&self) -> PeSourceMode {
        let mode = unsafe { gum_sys::gum_pe_module_get_source_mode(self.inner) };
        if mode == gum_sys::GumPeSourceMode_GUM_PE_SOURCE_MODE_ONLINE {
            PeSourceMode::Online
        } else {
            PeSourceMode::Offline
        }
    }

    /// A copy of the bytes the image was parsed from, or `None` for one read from memory.
    pub fn source_bytes(&self) -> Option<Vec<u8>> {
        unsafe {
            // Borrowed: the module keeps the blob.
            let blob = gum_sys::gum_pe_module_get_source_blob(self.inner);
            if blob.is_null() {
                return None;
            }
            let mut size = 0;
            let data = glib_compat::g_bytes_get_data(blob, &mut size);
            if data.is_null() {
                return Some(Vec::new());
            }
            Some(core::slice::from_raw_parts(data.cast::<u8>(), size as usize).to_owned())
        }
    }

    /// The data directory at `index`.
    pub fn directory(&self, index: PeDirectoryIndex) -> PeDataDirectory {
        // Never null: it points into the module's own table, which every `PeDirectoryIndex` is
        // inside.
        let directory =
            unsafe { &*gum_sys::gum_pe_module_get_directory(self.inner, index.to_raw()) };
        PeDataDirectory {
            rva: directory.rva,
            size: directory.size,
        }
    }

    /// Where the image's data for `rva` is, or `None` if the image has no data there.
    ///
    /// The pointer is into the module's source and is valid while the module is; how many bytes
    /// follow it is for the caller to know from the image.
    pub fn data_at_rva(&self, rva: u32) -> Option<*const c_void> {
        let data = unsafe { gum_sys::gum_pe_module_get_data_at_rva(self.inner, rva) };
        if data.is_null() { None } else { Some(data) }
    }

    /// Calls `callback` with each section until it returns `false`.
    pub fn enumerate_sections(&self, mut callback: impl FnMut(PeSectionDetails) -> bool) {
        let mut sink = |details| callback(unsafe { PeSectionDetails::from_raw(details) });
        let mut sink: Sink<'_, *const gum_sys::GumPeSectionDetails> = &mut sink;
        unsafe {
            gum_sys::gum_pe_module_enumerate_sections(
                self.inner,
                Some(details_callout::<gum_sys::GumPeSectionDetails>),
                &mut sink as *mut _ as gpointer,
            );
        }
    }

    /// Every section.
    pub fn sections(&self) -> Vec<PeSectionDetails> {
        collected(|sink| self.enumerate_sections(sink))
    }

    /// Calls `callback` with each base relocation until it returns `false`.
    pub fn enumerate_relocations(&self, mut callback: impl FnMut(PeRelocationDetails) -> bool) {
        let mut sink = |details: *const gum_sys::GumPeRelocationDetails| {
            let details = unsafe { &*details };
            callback(PeRelocationDetails {
                rva: details.rva,
                typ: PeRelocationType::from_raw(details.type_),
            })
        };
        let mut sink: Sink<'_, *const gum_sys::GumPeRelocationDetails> = &mut sink;
        unsafe {
            gum_sys::gum_pe_module_enumerate_relocations(
                self.inner,
                Some(details_callout::<gum_sys::GumPeRelocationDetails>),
                &mut sink as *mut _ as gpointer,
            );
        }
    }

    /// Every base relocation.
    pub fn relocations(&self) -> Vec<PeRelocationDetails> {
        collected(|sink| self.enumerate_relocations(sink))
    }

    /// Calls `callback` with each import, delay-loaded ones last, until it returns `false`.
    pub fn enumerate_imports(&self, mut callback: impl FnMut(PeImportDetails) -> bool) {
        let mut sink = |details| callback(unsafe { PeImportDetails::from_raw(details) });
        let mut sink: Sink<'_, *const gum_sys::GumPeImportDetails> = &mut sink;
        unsafe {
            gum_sys::gum_pe_module_enumerate_imports(
                self.inner,
                Some(details_callout::<gum_sys::GumPeImportDetails>),
                &mut sink as *mut _ as gpointer,
            );
        }
    }

    /// Every import.
    pub fn imports(&self) -> Vec<PeImportDetails> {
        collected(|sink| self.enumerate_imports(sink))
    }

    /// Calls `callback` with each export until it returns `false`.
    pub fn enumerate_exports(&self, mut callback: impl FnMut(PeExportDetails) -> bool) {
        let mut sink = |details| callback(unsafe { PeExportDetails::from_raw(details) });
        let mut sink: Sink<'_, *const gum_sys::GumPeExportDetails> = &mut sink;
        unsafe {
            gum_sys::gum_pe_module_enumerate_exports(
                self.inner,
                Some(details_callout::<gum_sys::GumPeExportDetails>),
                &mut sink as *mut _ as gpointer,
            );
        }
    }

    /// Every export.
    pub fn exports(&self) -> Vec<PeExportDetails> {
        collected(|sink| self.enumerate_exports(sink))
    }

    /// The export named `name`, compared exactly. A forwarded export is returned as such, not
    /// followed.
    pub fn find_export_by_name(&self, name: &str) -> Option<PeExportDetails> {
        let name = CString::new(name).ok()?;
        let mut details = core::mem::MaybeUninit::<gum_sys::GumPeExportDetails>::uninit();
        unsafe {
            let found = gum_sys::gum_pe_module_find_export_by_name(
                self.inner,
                name.as_ptr().cast(),
                details.as_mut_ptr(),
            );
            // The strings it points at belong to the module, which outlives this call.
            (found != 0).then(|| PeExportDetails::from_raw(details.as_ptr()))
        }
    }

    /// The image's thread-local storage, or `None` if it declares none.
    pub fn tls_details(&self) -> Option<PeTlsDetails> {
        let mut details = core::mem::MaybeUninit::<gum_sys::GumPeTlsDetails>::uninit();
        unsafe {
            if gum_sys::gum_pe_module_get_tls_details(self.inner, details.as_mut_ptr()) == 0 {
                return None;
            }
            let details = details.assume_init();
            Some(PeTlsDetails {
                template_rva: details.template_rva,
                template_size: details.template_size as usize,
                zero_fill_size: details.zero_fill_size as usize,
                index_rva: details.index_rva,
            })
        }
    }

    /// Calls `callback` with the RVA of each TLS callback until it returns `false`.
    pub fn enumerate_tls_callbacks(&self, mut callback: impl FnMut(u64) -> bool) {
        let mut sink: Sink<'_, u64> = &mut callback;
        unsafe {
            gum_sys::gum_pe_module_enumerate_tls_callbacks(
                self.inner,
                Some(rva_callout),
                &mut sink as *mut _ as gpointer,
            );
        }
    }

    /// The RVA of every TLS callback.
    pub fn tls_callbacks(&self) -> Vec<u64> {
        collected(|sink| self.enumerate_tls_callbacks(sink))
    }

    /// RVA of the stack cookie the load configuration names, or zero if there is none.
    pub fn security_cookie_rva(&self) -> u32 {
        unsafe { gum_sys::gum_pe_module_get_security_cookie_rva(self.inner) }
    }

    /// RVA of the hybrid (CHPE, ARM64EC) metadata the load configuration names, or zero if there
    /// is none.
    pub fn chpe_metadata_rva(&self) -> u32 {
        unsafe { gum_sys::gum_pe_module_get_chpe_metadata_rva(self.inner) }
    }

    /// Calls `callback` with each module this one imports from until it returns `false`. A
    /// delay-loaded module is a [`DependencyType::Weak`] dependency.
    pub fn enumerate_dependencies(&self, mut callback: impl FnMut(DependencyDetails) -> bool) {
        let mut sink = |details: *const gum_sys::GumDependencyDetails| {
            let details = unsafe { &*details };
            callback(DependencyDetails {
                name: unsafe { string_at(details.name) }.unwrap_or_default(),
                typ: if details.type_ == gum_sys::GumDependencyType_GUM_DEPENDENCY_WEAK {
                    DependencyType::Weak
                } else {
                    DependencyType::Regular
                },
            })
        };
        let mut sink: Sink<'_, *const gum_sys::GumDependencyDetails> = &mut sink;
        unsafe {
            gum_sys::gum_pe_module_enumerate_dependencies(
                self.inner,
                Some(details_callout::<gum_sys::GumDependencyDetails>),
                &mut sink as *mut _ as gpointer,
            );
        }
    }

    /// Every module this one imports from.
    pub fn dependencies(&self) -> Vec<DependencyDetails> {
        collected(|sink| self.enumerate_dependencies(sink))
    }

    /// How many entries the exception directory has. Some describe a fragment of a function,
    /// which [`PeModule::enumerate_function_starts`] leaves out.
    pub fn function_count(&self) -> u32 {
        unsafe { gum_sys::gum_pe_module_get_function_count(self.inner) }
    }

    /// Calls `callback` with the RVA at which each function in the exception directory starts,
    /// until it returns `false`.
    pub fn enumerate_function_starts(&self, mut callback: impl FnMut(u64) -> bool) {
        let mut sink: Sink<'_, u64> = &mut callback;
        unsafe {
            gum_sys::gum_pe_module_enumerate_function_starts(
                self.inner,
                Some(rva_callout),
                &mut sink as *mut _ as gpointer,
            );
        }
    }

    /// The RVA at which each function in the exception directory starts.
    pub fn function_starts(&self) -> Vec<u64> {
        collected(|sink| self.enumerate_function_starts(sink))
    }

    /// The file version from the image's version resource, as `major.minor.build.revision`, or
    /// `None` if it has no version resource.
    ///
    /// Added in Frida 17.26.3.
    pub fn version(&self) -> Option<String> {
        // Owned by the module.
        unsafe { string_at(gum_sys::gum_pe_module_get_version(self.inner)) }
    }
}

impl Drop for PeModule {
    fn drop(&mut self) {
        unsafe { gum_sys::g_object_unref(self.inner as *mut c_void) };
    }
}
