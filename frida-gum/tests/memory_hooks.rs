//! Tests for [`Memory::set_hooks`]. The hooks are process-wide, so this is the only test in its
//! binary: no other test allocates while they are installed.

use frida_gum::{Gum, Memory, NativePointer, PageProtection};
use frida_gum_sys::{GumAddressSpec, GumMemoryHooks, GumPageProtection, gpointer, gsize};
use std::sync::atomic::{AtomicUsize, Ordering};

/// What the allocation hook hands out. Never executed.
static HOOKED_MEMORY: [u8; 64] = [0; 64];

static ALLOCATED_SIZE: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn allocate(
    _spec: *const GumAddressSpec,
    size: gsize,
    _alignment: gsize,
    _prot: GumPageProtection,
    _user_data: gpointer,
) -> gpointer {
    ALLOCATED_SIZE.store(size as usize, Ordering::SeqCst);
    HOOKED_MEMORY.as_ptr() as gpointer
}

#[test]
fn routes_executable_allocations_through_the_hooks_until_they_are_removed() {
    let _gum = Gum::obtain();
    let hooked = NativePointer(HOOKED_MEMORY.as_ptr() as *mut _);
    let hooks = GumMemoryHooks {
        allocate: Some(allocate),
        protect: None,
        patch_code: None,
        user_data: std::ptr::null_mut(),
    };

    // SAFETY: the hook returns memory that nothing executes, and no other thread uses Gum.
    unsafe { Memory::set_hooks(Some(&hooks)) };
    let executable = Memory::allocate(48, 1, PageProtection::ReadExecute);
    let writable = Memory::allocate(4096, 1, PageProtection::ReadWrite);
    // SAFETY: as above.
    unsafe { Memory::set_hooks(None) };
    let unhooked = Memory::allocate(4096, 1, PageProtection::ReadExecute);

    assert_eq!(executable, Some(hooked));
    assert_eq!(ALLOCATED_SIZE.load(Ordering::SeqCst), 48);
    assert!(writable.is_some_and(|writable| writable != hooked));
    assert!(unhooked.is_some_and(|unhooked| unhooked != hooked));
    for allocation in [writable, unhooked].into_iter().flatten() {
        // SAFETY: both came from `Memory::allocate` with this size.
        assert!(unsafe { Memory::free(allocation, 4096) });
    }
}
