use std::ffi::c_void;
use std::sync::Mutex;

use frida_gum::{interceptor::Interceptor, Gum, Module, NativePointer};

type RtlAllocateHeapFn = extern "C" fn(*mut c_void, u32, usize) -> *mut c_void;
static ORIGINAL: Mutex<Option<RtlAllocateHeapFn>> = Mutex::new(None);

extern "C" fn rtl_detour(heap: *mut c_void, flags: u32, size: usize) -> *mut c_void {
    // Only print for the interesting sizes; full verbosity would flood.
    println!("RtlAllocateHeap intercepted: size={size} flags={flags} heap={heap:#x?}");
    let orig = ORIGINAL.lock().unwrap().unwrap();
    orig(heap, flags, size)
}

fn main() {
    let gum = Gum::obtain();
    let mut interceptor = Interceptor::obtain(&gum);

    let target = Module::find_global_export_by_name("RtlAllocateHeap")
        .expect("RtlAllocateHeap not found");

    let orig = interceptor
        .replace(
            NativePointer(target.0),
            NativePointer(rtl_detour as *mut c_void),
            NativePointer(std::ptr::null_mut()),
        )
        .expect("replace failed");

    *ORIGINAL.lock().unwrap() = Some(unsafe { std::mem::transmute(orig.0) });

    println!("hooked RtlAllocateHeap @ {:#x}", target.0 as usize);

    // Load the vulnerable DLL and call parse_heap_overflow with a 65-byte input.
    let dll_path = std::env::var("VULN_DLL").unwrap_or_else(|_| {
        r"C:\Users\Kirby Kuehl\Source\Repos\mimic-core\mimicx-mcp\target\debug\vulnerable_functions.dll".to_owned()
    });

    let lib = unsafe { libloading::Library::new(&dll_path) }
        .unwrap_or_else(|e| panic!("failed to load {dll_path}: {e}"));
    let parse: libloading::Symbol<unsafe extern "C" fn(*const u8, usize) -> i32> =
        unsafe { lib.get(b"parse_heap_overflow\0") }.expect("parse_heap_overflow not found");

    let data = [0x41u8; 65];
    println!("calling parse_heap_overflow with 65 bytes ...");
    let ret = unsafe { parse(data.as_ptr(), data.len()) };
    println!("parse_heap_overflow returned {ret}");

    interceptor.revert(target);
    println!("done");
}