//! Unit tests for [`NativePointer`] behavior.
//!
//! `NativePointer` is Gum's opaque address type. Its Debug/Display/hex
//! implementations are what everyone sees in stalker traces and interceptor
//! logs, so pin the visible contract here.

use frida_gum::NativePointer;
use std::ffi::c_void;

#[test]
fn null_pointer_is_null() {
    let p = NativePointer(std::ptr::null_mut());
    assert!(p.is_null(), "NativePointer::is_null must recognize null");
}

#[test]
fn non_null_pointer_is_not_null() {
    let mut byte = 42u8;
    let p = NativePointer(&mut byte as *mut _ as *mut c_void);
    assert!(
        !p.is_null(),
        "NativePointer::is_null must be false for non-null"
    );
}

#[test]
fn display_and_hex_match_numeric_address() {
    let raw = 0xdead_beef_usize;
    let p = NativePointer(raw as *mut c_void);

    assert_eq!(
        format!("{p}"),
        format!("{raw}"),
        "Display should render the pointer as its numeric address"
    );
    assert_eq!(
        format!("{p:x}"),
        format!("{raw:x}"),
        "LowerHex should match {{:x}} of the numeric address"
    );
    assert_eq!(
        format!("{p:X}"),
        format!("{raw:X}"),
        "UpperHex should match {{:X}} of the numeric address"
    );
}

#[test]
fn try_from_null_pointer_is_memory_access_error() {
    use frida_gum::Error;

    let p = NativePointer(std::ptr::null_mut());
    let err = String::try_from(p).expect_err("null pointer must not decode into a String");
    assert!(
        matches!(err, Error::MemoryAccessError),
        "expected Error::MemoryAccessError, got {err:?}"
    );
}

#[test]
fn try_from_non_null_c_string_roundtrips() {
    // Build a C string, hand its pointer to NativePointer, and confirm the
    // TryFrom<String> conversion returns the same bytes.
    let cs = std::ffi::CString::new("gum-native-pointer").unwrap();
    let p = NativePointer(cs.as_ptr() as *mut c_void);
    let decoded = String::try_from(p).expect("valid C string should decode");
    assert_eq!(decoded, "gum-native-pointer");
}

#[test]
fn equality_and_hash_use_address() {
    use std::collections::HashSet;

    let a = NativePointer(0x1000 as *mut c_void);
    let b = NativePointer(0x1000 as *mut c_void);
    let c = NativePointer(0x2000 as *mut c_void);

    assert_eq!(a, b, "same address should compare equal");
    assert_ne!(a, c, "different addresses should compare non-equal");

    let mut set: HashSet<NativePointer> = HashSet::new();
    set.insert(a);
    assert!(
        set.contains(&b),
        "HashSet lookup must match by address, not identity"
    );
    assert!(
        !set.contains(&c),
        "HashSet lookup must reject a different address"
    );
}

#[test]
fn native_pointer_is_copy() {
    // NativePointer is Copy so callers can hand it around freely — regressions
    // to this trait bound would ripple through every stalker/interceptor call
    // site.
    fn takes_copy<T: Copy>(_: T) {}
    takes_copy(NativePointer(std::ptr::dangling_mut::<c_void>()));
}
