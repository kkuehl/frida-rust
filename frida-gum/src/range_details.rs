/*
 * Copyright © 2021 Keegan Saunders
 * Copyright © 2021 S Rubenstein
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

extern crate alloc;
use {
    crate::MemoryRange,
    core::{
        ffi::{CStr, c_void},
        fmt,
        marker::PhantomData,
    },
    frida_gum_sys as gum_sys,
};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String};

/// The memory protection of an unassociated page.
#[derive(Clone, FromPrimitive, Debug, PartialEq)]
#[repr(u32)]
pub enum PageProtection {
    NoAccess = gum_sys::_GumPageProtection_GUM_PAGE_NO_ACCESS as u32,
    Read = gum_sys::_GumPageProtection_GUM_PAGE_READ as u32,
    Write = gum_sys::_GumPageProtection_GUM_PAGE_WRITE as u32,
    Execute = gum_sys::_GumPageProtection_GUM_PAGE_EXECUTE as u32,
    ReadWrite = gum_sys::_GumPageProtection_GUM_PAGE_READ as u32
        | gum_sys::_GumPageProtection_GUM_PAGE_WRITE as u32,
    WriteExecute = gum_sys::_GumPageProtection_GUM_PAGE_WRITE as u32
        | gum_sys::_GumPageProtection_GUM_PAGE_EXECUTE as u32,
    ReadExecute = gum_sys::_GumPageProtection_GUM_PAGE_READ as u32
        | gum_sys::_GumPageProtection_GUM_PAGE_EXECUTE as u32,
    ReadWriteExecute = gum_sys::_GumPageProtection_GUM_PAGE_READ as u32
        | gum_sys::_GumPageProtection_GUM_PAGE_WRITE as u32
        | gum_sys::_GumPageProtection_GUM_PAGE_EXECUTE as u32,
}

impl fmt::Display for PageProtection {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PageProtection::NoAccess => write!(fmt, "---"),
            PageProtection::Read => write!(fmt, "r--"),
            PageProtection::Write => write!(fmt, "-w-"),
            PageProtection::Execute => write!(fmt, "--e"),
            PageProtection::ReadWrite => write!(fmt, "rw-"),
            PageProtection::WriteExecute => write!(fmt, "-we"),
            PageProtection::ReadExecute => write!(fmt, "r-e"),
            PageProtection::ReadWriteExecute => write!(fmt, "rwe"),
        }
    }
}

/// The file association to a page.
#[derive(Clone, Debug)]
pub struct FileMapping<'a> {
    path: String,
    size: usize,
    offset: u64,
    phantom: PhantomData<&'a gum_sys::GumFileMapping>,
}

impl FileMapping<'_> {
    pub(crate) fn from_raw(file: *const gum_sys::GumFileMapping) -> Option<Self> {
        if file.is_null() {
            None
        } else {
            Some(unsafe {
                Self {
                    path: CStr::from_ptr((*file).path).to_string_lossy().into_owned(),
                    size: (*file).size as usize,
                    offset: (*file).offset,
                    phantom: PhantomData,
                }
            })
        }
    }

    /// The path of the file mapping on disk.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The offset into the file mapping.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// The size of the mapping.
    pub fn size(&self) -> usize {
        self.size
    }
}

/// Whether `address` is one of the `size` addresses starting at `base`.
///
/// The end of the range is never computed, as it does not fit when the range reaches the end of
/// the address space, and this is called from a C callback, where an overflow would abort.
fn range_contains(base: u64, size: u64, address: u64) -> bool {
    address >= base && address - base < size
}

struct SaveRangeDetailsByAddressContext<'a> {
    address: u64,
    details: Option<RangeDetails<'a>>,
}

unsafe extern "C" fn save_range_details_by_address(
    details: *const gum_sys::GumRangeDetails,
    context: *mut c_void,
) -> i32 {
    unsafe {
        let context = &mut *(context as *mut SaveRangeDetailsByAddressContext);
        let range = (*details).range;
        if range_contains((*range).base_address, (*range).size as u64, context.address) {
            context.details = Some(RangeDetails::from_raw(details));
            return 0;
        }

        1
    }
}

unsafe extern "C" fn enumerate_ranges_stub(
    details: *const gum_sys::GumRangeDetails,
    context: *mut c_void,
) -> i32 {
    unsafe {
        if !(*(context as *mut Box<&mut dyn FnMut(&RangeDetails) -> bool>))(
            &RangeDetails::from_raw(details),
        ) {
            return 0;
        }
        1
    }
}

/// Details a range of virtual memory.
pub struct RangeDetails<'a> {
    range: MemoryRange,
    protection: PageProtection,
    file: Option<FileMapping<'a>>,
    phantom: PhantomData<&'a gum_sys::GumRangeDetails>,
}

impl<'a> RangeDetails<'a> {
    pub(crate) fn from_raw(range_details: *const gum_sys::GumRangeDetails) -> Self {
        unsafe {
            Self {
                range: MemoryRange::from_raw((*range_details).range),
                // Frida only reports combinations of R/W/X (0..=7); fall back to
                // NoAccess rather than panicking inside this FFI callback if an
                // unexpected value is ever encountered.
                protection: num::FromPrimitive::from_u32((*range_details).protection)
                    .unwrap_or(PageProtection::NoAccess),
                file: FileMapping::from_raw((*range_details).file),
                phantom: PhantomData,
            }
        }
    }

    /// Get a [`RangeDetails`] for the range containing the given address.
    pub fn with_address(address: u64) -> Option<RangeDetails<'a>> {
        let mut context = SaveRangeDetailsByAddressContext {
            address,
            details: None,
        };
        unsafe {
            gum_sys::gum_process_enumerate_ranges(
                gum_sys::_GumPageProtection_GUM_PAGE_NO_ACCESS as u32,
                Some(save_range_details_by_address),
                &mut context as *mut _ as *mut c_void,
            );
        }

        context.details
    }

    /// Enumerate all ranges which match the given [`PageProtection`], calling the callback
    /// function for each such range.
    pub fn enumerate_with_prot(
        prot: PageProtection,
        callback: &mut dyn FnMut(&RangeDetails) -> bool,
    ) {
        unsafe {
            gum_sys::gum_process_enumerate_ranges(
                prot as u32,
                Some(enumerate_ranges_stub),
                &mut Box::new(callback) as *mut _ as *mut c_void,
            );
        }
    }

    /// The range of memory that is detailed.
    pub fn memory_range(&self) -> MemoryRange {
        self.range.clone()
    }

    /// The page protection of the range.
    pub fn protection(&self) -> PageProtection {
        self.protection.clone()
    }

    /// The associated file mapping, if present.
    pub fn file_mapping(&self) -> Option<FileMapping<'_>> {
        self.file.clone()
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    /// `range_contains` agrees with the definition of a half-open range for every input, worked
    /// out in 128 bits where the end always fits.
    #[kani::proof]
    fn range_contains_matches_its_definition() {
        let base: u64 = kani::any();
        let size: u64 = kani::any();
        let address: u64 = kani::any();
        let end = base as u128 + size as u128;
        let expected = base <= address && (address as u128) < end;
        assert!(range_contains(base, size, address) == expected);
    }

    /// Frida reports a page's protection as any combination of read, write and execute. Each
    /// has a variant of its own, so [`RangeDetails`] never falls back to `NoAccess` for one.
    #[kani::proof]
    fn every_protection_has_a_variant() {
        let raw: u32 = kani::any();
        let all = PageProtection::ReadWriteExecute as u32;
        let protection: Option<PageProtection> = num::FromPrimitive::from_u32(raw);
        if raw <= all {
            assert!(protection.is_some_and(|protection| protection as u32 == raw));
        } else {
            assert!(protection.is_none());
        }
    }
}
