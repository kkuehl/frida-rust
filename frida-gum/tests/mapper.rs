//! Tests for [`ProcessMemory`], [`NativeModuleResolver`] and [`Mapper`] against this process.

use frida_gum::{Gum, Module, NativeModuleResolver, PageProtection, ProcessMemory};
use lazy_static::lazy_static;
use std::{cell::RefCell, rc::Rc};

lazy_static! {
    static ref GUM: Gum = Gum::obtain();
}

/// A function every process has loaded, by the name its system library exports it under.
const SYSTEM_FUNCTION: &str = if cfg!(windows) {
    "GetCurrentProcessId"
} else {
    "getpid"
};

const PAGE: usize = 0x4000;

#[test]
fn local_memory_is_this_process() {
    let memory = ProcessMemory::local(&GUM);

    assert_eq!(memory.pid(), std::process::id());
    assert!(memory.handle().is_null());
}

#[test]
fn remote_memory_keeps_the_handle_it_was_given() {
    let handle = 0x1234 as *mut std::ffi::c_void;

    // SAFETY: the handle is only stored and read back.
    let memory = unsafe { ProcessMemory::remote(&GUM, 42, handle) };

    assert_eq!(memory.pid(), 42);
    assert_eq!(memory.handle(), handle);
}

#[test]
fn allocated_memory_can_be_written_read_and_protected() {
    let memory = ProcessMemory::local(&GUM);
    let address = memory.alloc(PAGE, PAGE).expect("memory to allocate");

    // SAFETY: the page was just allocated, is as large as what is written, read and protected,
    // and is not used after it is freed.
    unsafe {
        let wrote = memory.write(address, b"frida");
        let read = memory.read(address, 5);
        let protected = memory.protect(address, PAGE, PageProtection::Read);
        let read_while_read_only = memory.read(address + 1, 4);
        memory.free(address, PAGE);

        assert_eq!(address % PAGE as u64, 0);
        assert!(wrote);
        assert_eq!(read.as_deref(), Some(&b"frida"[..]));
        assert!(protected);
        assert_eq!(read_while_read_only.as_deref(), Some(&b"rida"[..]));
    }
}

#[test]
fn memory_can_be_allocated_near_an_address() {
    let memory = ProcessMemory::local(&GUM);
    let anchor = memory.alloc(PAGE, PAGE).unwrap();
    let max_distance = 0x4000_0000;

    let near = memory
        .alloc_near(anchor, max_distance, PAGE, PAGE)
        .expect("memory near the anchor");

    assert_ne!(near, anchor);
    assert!(near.abs_diff(anchor) <= max_distance as u64);
    // SAFETY: both were allocated here with this size and are not used again.
    unsafe {
        memory.free(near, PAGE);
        memory.free(anchor, PAGE);
    }
}

#[test]
fn mapped_memory_holds_the_data_under_the_protection_asked_for() {
    let memory = ProcessMemory::local(&GUM);
    let address = memory.alloc(PAGE, PAGE).unwrap();

    // SAFETY: the page was just allocated and nothing else uses it.
    let mapped = unsafe { memory.map(address, PAGE, b"mapped", PageProtection::Read) };

    // SAFETY: the page is still allocated, and readable.
    let read = unsafe { memory.read(address, 6) };
    assert!(mapped);
    assert_eq!(read.as_deref(), Some(&b"mapped"[..]));
    assert_eq!(
        frida_gum::Memory::query_region(frida_gum::NativePointer(address as *mut _))
            .map(|(_, protection)| protection),
        Some(PageProtection::Read)
    );
    // SAFETY: allocated here with this size and not used again.
    unsafe { memory.free(address, PAGE) };
}

#[test]
fn code_written_to_memory_can_be_marked_executable() {
    let memory = ProcessMemory::local(&GUM);
    let address = memory.alloc(PAGE, PAGE).unwrap();

    // SAFETY: the page was just allocated and nothing is writing to it.
    let marked = unsafe { memory.mark_code(address, PAGE) };

    assert!(marked);
    // SAFETY: allocated here with this size and not used again.
    unsafe { memory.free(address, PAGE) };
}

#[test]
fn resolver_finds_what_the_loader_exports() {
    let resolver = NativeModuleResolver::new(&GUM);
    let expected = Module::find_global_export_by_name(SYSTEM_FUNCTION).map(|p| p.0 as u64);

    let address = resolver.find_dynamic_address(SYSTEM_FUNCTION);
    let symbol = resolver.find_dynamic_symbol(SYSTEM_FUNCTION);

    assert!(expected.is_some());
    assert_eq!(address, expected);
    assert_eq!(symbol.map(|symbol| symbol.address), expected);
    assert_eq!(symbol.map(|symbol| symbol.indirect), Some(false));
    assert_eq!(
        resolver.find_dynamic_address("no_such_symbol_anywhere"),
        None
    );
    assert_eq!(
        resolver.find_dynamic_symbol("no_such_symbol_anywhere"),
        None
    );
    assert_eq!(resolver.find_dynamic_address("interior\0nul"), None);
}

#[test]
fn resolver_asks_its_lookup_handler_first() {
    let resolver = NativeModuleResolver::new(&GUM);
    let unhandled = resolver.find_dynamic_address(SYSTEM_FUNCTION);
    let asked = Rc::new(RefCell::new(Vec::new()));
    let asked_by_handler = Rc::clone(&asked);

    resolver.set_dynamic_lookup_handler(move |symbol| {
        asked_by_handler.borrow_mut().push(symbol.to_owned());
        (symbol == "provided_by_the_handler").then_some(0x1000)
    });
    let handled = resolver.find_dynamic_address("provided_by_the_handler");
    let passed_on = resolver.find_dynamic_address(SYSTEM_FUNCTION);
    resolver.clear_dynamic_lookup_handler();
    let after_clearing = resolver.find_dynamic_address("provided_by_the_handler");

    assert_eq!(handled, Some(0x1000));
    assert_eq!(passed_on, unhandled);
    assert_eq!(after_clearing, None);
    assert_eq!(
        *asked.borrow(),
        ["provided_by_the_handler", SYSTEM_FUNCTION]
    );
    assert_eq!(
        Rc::strong_count(&asked),
        1,
        "clearing the handler destroys it"
    );
}

#[test]
fn dropping_the_resolver_destroys_its_lookup_handler() {
    let held = Rc::new(());
    let held_by_handler = Rc::clone(&held);
    let resolver = NativeModuleResolver::new(&GUM);
    resolver.set_dynamic_lookup_handler(move |_| {
        let _held = &held_by_handler;
        None
    });

    drop(resolver);

    assert_eq!(Rc::strong_count(&held), 1);
}

#[test]
fn resolver_finds_a_loaded_module_and_none_that_does_not_exist() {
    let resolver = NativeModuleResolver::new(&GUM);
    let loaded = frida_gum::Process::obtain(&GUM).main_module().name();

    let found = resolver.find_module_by_name(&loaded);

    assert_eq!(found.map(|module| module.name()), Some(loaded));
    assert!(
        resolver
            .find_module_by_name("no-such-module-anywhere-0123456789")
            .is_none()
    );
}

#[cfg(windows)]
mod on_windows {
    use super::*;
    use frida_gum::Mapper;

    fn version_dll() -> String {
        format!(
            r"{}\System32\version.dll",
            std::env::var("SystemRoot").unwrap()
        )
    }

    #[test]
    fn maps_a_library_and_takes_it_out_again() {
        const EXTRA: usize = 0x1000;
        let resolver = NativeModuleResolver::new(&GUM);
        let mapper = Mapper::from_file(&version_dll(), &resolver).expect("a mapper for a DLL");
        let range_before = mapper.range();

        let extra = mapper.map(EXTRA).expect("the DLL to map");

        let range = mapper.range();
        let base = range.base_address().0 as u64;
        let end = base + range.size() as u64;
        let within = |address: u64| base <= address && address < end;
        // SAFETY: the range was just mapped, and is at least a page.
        let header = unsafe { ProcessMemory::local(&GUM).read(base, 2) };
        let resolved = mapper.resolve("GetFileVersionInfoSizeW");
        let exports = mapper.enumerate_exports();
        let constructor = mapper.constructor();
        let destructor = mapper.destructor();
        // SAFETY: none of the mapped code was run, and nothing uses the mapping after this.
        unsafe { mapper.unmap() };

        assert_eq!(range_before.size(), 0);
        assert_eq!(extra + EXTRA as u64, end, "the extra memory ends the range");
        assert_eq!(header.as_deref(), Some(&b"MZ"[..]));
        assert!(resolved.is_some_and(within), "{resolved:x?}");
        assert!(
            exports
                .iter()
                .any(|export| export.name == "GetFileVersionInfoSizeW"
                    && Some(export.address as u64) == resolved)
        );
        assert!(within(constructor) && within(destructor));
        assert_ne!(constructor, destructor);
        assert_eq!(mapper.resolve("NoSuchExport"), None);
        assert_eq!(
            mapper.range().size(),
            0,
            "nothing is mapped after unmapping"
        );
    }

    #[test]
    fn maps_a_library_held_in_memory() {
        let resolver = NativeModuleResolver::new(&GUM);
        let bytes = std::fs::read(version_dll()).unwrap();
        let mapper = Mapper::from_bytes("version.dll", &bytes, &resolver).expect("a mapper");

        let mapped = mapper.map(0);

        let size = mapper.range().size();
        // SAFETY: none of the mapped code was run, and nothing uses the mapping after this.
        unsafe { mapper.unmap() };
        assert!(mapped.is_some());
        assert!(size > 0);
    }

    #[test]
    fn maps_into_the_target_it_is_given() {
        let resolver = NativeModuleResolver::new(&GUM);
        let mapper = Mapper::from_file(&version_dll(), &resolver).unwrap();
        mapper.set_target(&ProcessMemory::local(&GUM));
        mapper.add_apple_parameter("ignored", "here");

        let mapped = mapper.map(0);

        // SAFETY: none of the mapped code was run, and nothing uses the mapping after this.
        unsafe { mapper.unmap() };
        assert!(mapped.is_some());
    }

    #[test]
    fn has_no_mapper_for_what_is_not_a_library() {
        let resolver = NativeModuleResolver::new(&GUM);
        let missing = std::env::temp_dir().join("frida-gum-mapper-no-such-file.dll");

        assert!(Mapper::from_file(missing.to_str().unwrap(), &resolver).is_none());
        assert!(Mapper::from_file("interior\0nul.dll", &resolver).is_none());
        assert!(Mapper::from_bytes("garbage.dll", b"not a library", &resolver).is_none());
    }
}
