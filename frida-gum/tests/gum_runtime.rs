//! Live-runtime tests exercising [`Gum`], [`Process`], [`Module`], and
//! [`MemoryRange`] against the running test process itself.
//!
//! These tests are deliberately conservative — they only inspect state,
//! never patch code — so they don't need extra privileges and don't
//! interfere with each other. They still share the process-wide `Gum`
//! singleton via `lazy_static!`.

use frida_gum::{Gum, Memory, MemoryRange, NativePointer, PageProtection, Process};
use lazy_static::lazy_static;
use std::ffi::c_void;

lazy_static! {
    static ref GUM: Gum = {
        let gum = Gum::obtain();
        // Gum lists the loaded modules the first time it is asked about them, and a thread that
        // asks while another is still listing gets the list so far. Ask here, where only one
        // thread can be, so that every test sees all of them.
        Process::obtain(&gum).enumerate_modules();
        gum
    };
}

#[test]
fn gum_obtain_is_idempotent_across_repeated_calls() {
    // Gum is reference-counted internally; obtain/drop cycles should not
    // deinit the singleton while another handle is still alive.
    let _root = &*GUM;
    for _ in 0..3 {
        let g = Gum::obtain();
        drop(g);
    }
    // The shared handle must still function after the churn.
    let _p = Process::obtain(&GUM);
}

#[test]
fn process_id_matches_std_process_id() {
    let p = Process::obtain(&GUM);
    assert_eq!(
        p.id(),
        std::process::id(),
        "Process::id must agree with std::process::id"
    );
}

#[test]
fn process_reports_current_thread_id() {
    let p = Process::obtain(&GUM);
    let tid = p.current_thread_id();
    assert_ne!(tid, 0, "current_thread_id must not be zero");
}

#[test]
fn process_home_and_tmp_dirs_are_non_empty() {
    let p = Process::obtain(&GUM);
    assert!(
        !p.home_dir().is_empty(),
        "home_dir must return a populated path"
    );
    assert!(
        !p.tmp_dir().is_empty(),
        "tmp_dir must return a populated path"
    );
    assert!(
        !p.current_dir().is_empty(),
        "current_dir must return a populated path"
    );
}

#[test]
fn main_module_has_name_and_a_range() {
    let p = Process::obtain(&GUM);
    let m = p.main_module();

    let name = m.name();
    assert!(!name.is_empty(), "main module name must not be empty");

    let range = m.range();
    assert!(
        !range.base_address().is_null(),
        "main module range must have a non-null base"
    );
    assert!(range.size() > 0, "main module range size must be > 0");
}

#[test]
fn enumerate_modules_includes_main_module() {
    let p = Process::obtain(&GUM);
    let main = p.main_module();
    let modules = p.enumerate_modules();

    assert!(!modules.is_empty(), "enumerate_modules should not be empty");
    let main_name = main.name();
    assert!(
        modules.iter().any(|m| m.name() == main_name),
        "enumerate_modules must include the main module ({main_name:?})"
    );
}

#[test]
fn find_module_by_address_returns_the_main_module_from_a_code_pointer() {
    let p = Process::obtain(&GUM);
    let main = p.main_module();
    // Take an address we know is inside our own binary (a function pointer to
    // this test function). find_module_by_address should map it back to our
    // main module.
    let addr =
        find_module_by_address_returns_the_main_module_from_a_code_pointer as *const () as usize;
    let module = p
        .find_module_by_address(addr)
        .expect("find_module_by_address should resolve a code pointer inside the test binary");
    assert_eq!(
        module.name(),
        main.name(),
        "resolved module should match main_module"
    );
}

#[test]
fn memory_range_display_and_hex_bracket_the_range() {
    // MemoryRange formats as base..end across Display/LowerHex/UpperHex.
    let base = 0x1000usize;
    let size = 0x40;
    let range = MemoryRange::new(NativePointer(base as *mut c_void), size);

    assert_eq!(format!("{range}"), format!("{}..{}", base, base + size));
    assert_eq!(
        format!("{range:x}"),
        format!("{:x}..{:x}", base, base + size)
    );
    assert_eq!(
        format!("{range:X}"),
        format!("{:X}..{:X}", base, base + size)
    );
}

#[test]
fn memory_range_into_range_usize_is_exclusive_end() {
    let base = 0x2000usize;
    let size = 0x80;
    let r = MemoryRange::new(NativePointer(base as *mut c_void), size);
    let std_range: std::ops::Range<usize> = r.into();
    assert_eq!(std_range.start, base);
    assert_eq!(std_range.end, base + size);
}

#[test]
fn enumerate_readable_ranges_returns_pages() {
    // The process must always have at least one readable range (stack, data,
    // etc.). If frida-gum ever regresses to returning zero of them, that's
    // an alert-worthy break.
    let p = Process::obtain(&GUM);
    let ranges = p.enumerate_ranges(PageProtection::Read);
    assert!(
        !ranges.is_empty(),
        "at least one PageProtection::Read range must exist"
    );
}

#[test]
fn memory_query_region_finds_the_region_an_address_is_in() {
    let _gum = &*GUM;
    let on_the_stack = 0u8;
    let address = &on_the_stack as *const u8 as usize;

    let (range, protection) =
        Memory::query_region(NativePointer(address as *mut c_void)).expect("the stack is mapped");

    let base = range.base_address().0 as usize;
    assert!(
        base <= address && address < base + range.size(),
        "{address:#x} should be in {base:#x}+{:#x}",
        range.size()
    );
    assert_eq!(protection, PageProtection::ReadWrite);
}

#[test]
fn memory_query_region_reports_code_as_executable() {
    let _gum = &*GUM;
    let code = memory_query_region_reports_code_as_executable as *const c_void;

    let (_, protection) =
        Memory::query_region(NativePointer(code as *mut c_void)).expect("code is mapped");

    assert_eq!(protection, PageProtection::ReadExecute);
}

#[test]
fn tag_checks_can_be_suspended_and_resumed() {
    let _gum = &*GUM;

    Memory::suspend_tag_checks();
    let read_meanwhile = std::hint::black_box(42);
    Memory::resume_tag_checks();

    assert_eq!(read_meanwhile, 42);
}

#[test]
fn exports_with_a_prefix_are_the_exports_whose_names_start_with_it() {
    let p = Process::obtain(&GUM);
    let (module, exports) = p
        .enumerate_modules()
        .into_iter()
        .find_map(|module| {
            let exports = module.enumerate_exports();
            exports
                .iter()
                .any(|export| export.name.len() >= 3 && export.name.is_ascii())
                .then_some((module, exports))
        })
        .expect("some loaded module has exports");
    let prefix = exports
        .iter()
        .find(|export| export.name.len() >= 3 && export.name.is_ascii())
        .unwrap()
        .name[..3]
        .to_owned();
    let prefix = prefix.as_str();
    let names = |exports: Vec<frida_gum::ExportDetails>| {
        let mut names: Vec<_> = exports.into_iter().map(|export| export.name).collect();
        names.sort();
        names
    };

    let with_prefix = names(module.enumerate_exports_with_prefix(prefix));

    let mut expected = names(exports);
    expected.retain(|name| name.starts_with(prefix));
    assert!(!with_prefix.is_empty());
    assert_eq!(with_prefix, expected);
    assert!(module.enumerate_exports_with_prefix("\0").is_empty());
}

#[test]
fn memory_range_reaching_past_the_address_space_ends_at_the_top() {
    // The base and the size are the caller's, so their sum may not fit. It used to be added
    // unchecked, which panics in a debug build and wraps to a backwards range in a release one.
    let range = MemoryRange::new(NativePointer(usize::MAX as *mut c_void), 0x1000);

    let converted: std::ops::Range<usize> = (&range).into();
    assert_eq!(converted, usize::MAX..usize::MAX);

    let top = usize::MAX;
    assert_eq!(format!("{range}"), format!("{top}..{top}"));
    assert_eq!(format!("{range:x}"), format!("{top:x}..{top:x}"));
    assert_eq!(format!("{range:X}"), format!("{top:X}..{top:X}"));
}

#[test]
fn module_map_that_rejects_every_module_has_no_values() {
    // GLib leaves an empty array's storage unallocated, and a slice made from that null pointer
    // is undefined behaviour, which a debug build stops at.
    let _gum = &*GUM;
    let map = frida_gum::ModuleMap::new_with_filter(|_| false);
    assert!(map.values().is_empty());
}

#[test]
fn process_platform_is_this_platform() {
    // Every OS Gum reports has a variant (proved by Kani), so this cannot panic.
    let platform = Process::obtain(&GUM).platform();
    #[cfg(target_os = "macos")]
    assert!(matches!(platform, frida_gum::Os::Macos));
    #[cfg(target_os = "linux")]
    assert!(matches!(platform, frida_gum::Os::Linux));
    #[cfg(target_os = "windows")]
    assert!(matches!(platform, frida_gum::Os::Windows));
    let _ = platform;
}

#[test]
fn memory_allocates_with_no_particular_alignment() {
    // `1` is what the documentation says to pass for no alignment, and Gum's arithmetic wraps
    // around for it: fewer bytes than a page could not be allocated at all.
    let _gum = &*GUM;

    let small = Memory::allocate(48, 1, PageProtection::ReadWrite).expect("a small allocation");
    let near = Memory::allocate_near(small, i32::MAX as usize, 48, 1, PageProtection::ReadWrite)
        .expect("a small allocation near the first");

    // SAFETY: both were allocated here with this size and are not used again.
    unsafe {
        assert!(Memory::write(small, b"small"));
        assert!(Memory::free(near, 48));
        assert!(Memory::free(small, 48));
    }
}
