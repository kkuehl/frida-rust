//! Live-runtime tests exercising [`Gum`], [`Process`], [`Module`], and
//! [`MemoryRange`] against the running test process itself.
//!
//! These tests are deliberately conservative — they only inspect state,
//! never patch code — so they don't need extra privileges and don't
//! interfere with each other. They still share the process-wide `Gum`
//! singleton via `lazy_static!`.

use frida_gum::{Gum, MemoryRange, NativePointer, PageProtection, Process};
use lazy_static::lazy_static;
use std::ffi::c_void;

lazy_static! {
    static ref GUM: Gum = Gum::obtain();
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
    let addr = find_module_by_address_returns_the_main_module_from_a_code_pointer as *const ()
        as usize;
    let module = p.find_module_by_address(addr).expect(
        "find_module_by_address should resolve a code pointer inside the test binary",
    );
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
    assert_eq!(format!("{range:x}"), format!("{:x}..{:x}", base, base + size));
    assert_eq!(format!("{range:X}"), format!("{:X}..{:X}", base, base + size));
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
