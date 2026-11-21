//! `ScriptOption`'s name: a script without one, a name that is a slice of a
//! longer string, and a name read before it is replaced.

use frida::{Frida, ScriptOption};
use std::sync::LazyLock;

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

#[test]
fn a_script_without_a_name_has_an_empty_name() {
    let _f = &*FRIDA;
    assert_eq!(ScriptOption::new().get_name(), "");
}

#[test]
fn a_name_is_only_the_slice_it_is_given() {
    let _f = &*FRIDA;
    let text = "abcdef";
    let options = ScriptOption::new().set_name(&text[..3]);
    assert_eq!(options.get_name(), "abc");
}

#[test]
fn a_name_with_a_nul_is_cut_there() {
    let _f = &*FRIDA;
    let options = ScriptOption::new().set_name("ab\0cd");
    assert_eq!(options.get_name(), "ab");
}

#[test]
fn a_name_read_before_it_is_replaced_stays_as_it_was() {
    let _f = &*FRIDA;
    let options = ScriptOption::new().set_name("first-name-of-the-script");
    let first = options.get_name();
    // The same length, so the allocator is likely to reuse the freed block.
    let options = options.set_name("other-name-of-the-script");
    let second = options.get_name();
    drop(options);
    let _reuse: Vec<String> = (0..64).map(|i| format!("{i:0>24}")).collect();
    assert_eq!(first, "first-name-of-the-script");
    assert_eq!(second, "other-name-of-the-script");
}
