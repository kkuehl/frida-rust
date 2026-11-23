//! Unit tests for [`Variant`] getters and Debug formatting.
//!
//! `Variant::from_ptr` is `pub(crate)` and can only be exercised through
//! `Process::get_parameters` (already covered by `process_parameters.rs`);
//! these tests instead lock in the public shape of the enum. If a future
//! change silently reshuffles variants or breaks the getters, these unit
//! tests catch it without needing a live frida-core.

use frida::Variant;
use std::collections::HashMap;

#[test]
fn get_string_only_returns_for_string_variant() {
    assert_eq!(
        Variant::String("hi".into()).get_string(),
        Some("hi"),
        "get_string on String must return the underlying &str"
    );
    assert_eq!(Variant::Int64(1).get_string(), None);
    assert_eq!(Variant::Boolean(true).get_string(), None);
    assert_eq!(Variant::Map(HashMap::new()).get_string(), None);
    assert_eq!(Variant::MapList(vec![]).get_string(), None);
    assert_eq!(Variant::StringList(vec![]).get_string(), None);
    assert_eq!(Variant::Unsupported("ay".into()).get_string(), None);
}

#[test]
fn get_int_only_returns_for_int_variant() {
    assert_eq!(Variant::Int64(-42).get_int(), Some(-42));
    assert_eq!(Variant::String("1".into()).get_int(), None);
    assert_eq!(Variant::Boolean(false).get_int(), None);
}

#[test]
fn get_bool_only_returns_for_boolean_variant() {
    assert_eq!(Variant::Boolean(true).get_bool(), Some(true));
    assert_eq!(Variant::Boolean(false).get_bool(), Some(false));
    assert_eq!(Variant::Int64(0).get_bool(), None);
    assert_eq!(Variant::String("false".into()).get_bool(), None);
}

#[test]
fn get_map_only_returns_for_map_variant() {
    let mut m = HashMap::new();
    m.insert("k".to_string(), Variant::Int64(1));

    let v = Variant::Map(m.clone());
    let back = v.get_map().expect("get_map should return Some");
    assert_eq!(back.get("k"), Some(&Variant::Int64(1)));
    assert!(Variant::String("s".into()).get_map().is_none());
}

#[test]
fn get_maplist_and_string_list_thread_through() {
    let inner = HashMap::from([("k".to_string(), Variant::Boolean(true))]);
    let list = Variant::MapList(vec![inner.clone()]);
    let out = list.get_maplist().expect("get_maplist should return Some");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].get("k"), Some(&Variant::Boolean(true)));

    let names = Variant::StringList(vec!["a".into(), "b".into()]);
    let out = names
        .get_string_list()
        .expect("get_string_list should return Some");
    assert_eq!(out, &["a".to_string(), "b".to_string()]);

    // Cross-variant negatives.
    assert!(Variant::Int64(1).get_maplist().is_none());
    assert!(Variant::Int64(1).get_string_list().is_none());
}

#[test]
fn debug_impl_never_panics_and_labels_unsupported() {
    // The important property is that `{:?}` never panics on any variant —
    // the parameter-enumeration path formats these into logs and we do not
    // want an unexpected GVariant sig to crash callers.
    let cases = [
        Variant::String("s".into()),
        Variant::Boolean(true),
        Variant::Int64(-1),
        Variant::Map(HashMap::from([("k".into(), Variant::Int64(1))])),
        Variant::MapList(vec![HashMap::from([("k".into(), Variant::Boolean(false))])]),
        Variant::StringList(vec!["a".into()]),
        Variant::Unsupported("ay".into()),
    ];
    for c in cases {
        let s = format!("{c:?}");
        assert!(!s.is_empty(), "Debug must produce non-empty output");
    }
    // The Unsupported variant should carry the sig through Debug output so
    // upstream logs remain triageable.
    let sig = format!("{:?}", Variant::Unsupported("ay".into()));
    assert!(
        sig.contains("ay"),
        "Unsupported debug output should mention the sig, got {sig}"
    );
}

#[test]
fn variant_equality_is_structural() {
    // The Variant equality contract is that two variants are equal iff their
    // structure matches. Downstream callers use `matches!` and direct `==`
    // in tests — pin that behavior explicitly.
    assert_eq!(Variant::Int64(3), Variant::Int64(3));
    assert_ne!(Variant::Int64(3), Variant::Int64(4));
    assert_ne!(Variant::Int64(3), Variant::String("3".into()));
    assert_ne!(
        Variant::Unsupported("ay".into()),
        Variant::Unsupported("(sv)".into())
    );
}
