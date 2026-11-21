//! Tests for [`BinaryMetadata`].
//!
//! Only Frida's own binaries (frida-server, frida-gadget, ...) carry the metadata this reads, so
//! these need one: set `FRIDA_TEST_BINARY` to its path and run with `--ignored`.

use frida::{BinaryMetadata, Frida};
use std::ffi::CString;
use std::sync::LazyLock;

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

fn frida_binary() -> CString {
    let path = std::env::var("FRIDA_TEST_BINARY")
        .expect("set FRIDA_TEST_BINARY to the path of a frida-server or frida-gadget");
    CString::new(path).expect("the path has no NUL in it")
}

#[test]
#[ignore = "needs a Frida binary: set FRIDA_TEST_BINARY"]
fn architectures_can_be_read_more_than_once() {
    let _frida = &*FRIDA;
    let metadata =
        BinaryMetadata::from_file(frida_binary()).unwrap_or_else(|error| panic!("{error}"));

    // The array belongs to the metadata. Reading it must leave it in place, for the next read
    // and for when the metadata is dropped.
    let first = metadata.architectures();
    let second = metadata.architectures();
    let third = metadata.architectures();

    assert!(!first.is_empty(), "a Frida binary has an architecture");
    assert!(first.iter().all(|arch| !arch.is_empty()), "{first:?}");
    assert_eq!(first, second);
    assert_eq!(second, third);
    assert!(metadata.name().is_some());
    assert!(metadata.version().is_some());
}
