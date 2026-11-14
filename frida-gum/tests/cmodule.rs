//! Tests for [`CModule`], which compile small pieces of C with the compiler built into Gum.

use frida_gum::{CHeaderKind, CModule, CModuleError, CModuleToolchain, Gum};
use lazy_static::lazy_static;
use std::{
    ffi::c_void,
    sync::atomic::{AtomicI32, Ordering},
};

lazy_static! {
    static ref GUM: Gum = Gum::obtain();
}

/// Whether this build of Gum has a compiler in it. Without one there is nothing here to test:
/// the tests that compile return early.
fn has_compiler() -> bool {
    lazy_static! {
        static ref HAS_COMPILER: bool = match compile("int probe;") {
            Ok(_) => true,
            Err(error) if error.0.contains("not available") => false,
            Err(error) => panic!("the compiler should compile a declaration: {error}"),
        };
    }
    *HAS_COMPILER
}

fn compile(source: &str) -> Result<CModule, CModuleError> {
    CModule::new(&GUM, source, CModuleToolchain::Internal)
}

fn linked(source: &str) -> CModule {
    let module = compile(source).expect("the source should compile");
    // SAFETY: the sources in these tests touch nothing but their own variables.
    unsafe { module.link() }.expect("the module should link");
    module
}

/// Calls the function of two `int`s named `name` in `module`.
fn call(module: &CModule, name: &str, a: i32, b: i32) -> i32 {
    let function = module.find_symbol_by_name(name).expect("the function");
    // SAFETY: the tests define each function they call this way as `int (int, int)`.
    let function: extern "C" fn(i32, i32) -> i32 = unsafe { std::mem::transmute(function.0) };
    function(a, b)
}

#[test]
fn compiles_c_that_can_be_called() {
    if !has_compiler() {
        return;
    }
    let module = linked("int add (int a, int b) { return a + b; }");

    assert_eq!(call(&module, "add", 2, 3), 5);
}

#[test]
fn its_symbols_are_inside_its_range() {
    if !has_compiler() {
        return;
    }
    let module = linked("int add (int a, int b) { return a + b; }\nint counter = 7;");

    let range = module.range();
    let base = range.base_address().0 as usize;
    let symbols = module.enumerate_symbols();
    let add = module.find_symbol_by_name("add");

    assert!(range.size() > 0);
    for name in ["add", "counter"] {
        let symbol = symbols
            .iter()
            .find(|symbol| symbol.name == name)
            .unwrap_or_else(|| panic!("{name} among {symbols:?}"));
        let address = symbol.address.0 as usize;
        assert!(
            base <= address && address < base + range.size(),
            "{name} at {address:#x} should be in {base:#x}+{:#x}",
            range.size()
        );
    }
    assert_eq!(
        symbols
            .iter()
            .find(|symbol| symbol.name == "add")
            .map(|symbol| symbol.address),
        add
    );
    assert_eq!(module.find_symbol_by_name("subtract"), None);
    assert_eq!(module.find_symbol_by_name("a\0dd"), None);
}

#[test]
fn has_no_range_before_it_is_linked() {
    if !has_compiler() {
        return;
    }
    let module = compile("int one (void) { return 1; }").unwrap();

    assert_eq!(module.range().size(), 0);
}

#[test]
fn links_against_the_symbols_it_is_given() {
    if !has_compiler() {
        return;
    }
    static SHARED: AtomicI32 = AtomicI32::new(40);
    let module = compile(
        "extern int shared;\nint add_to_shared (int a, int b) { shared += a + b; return shared; }",
    )
    .unwrap();

    // SAFETY: `shared` is declared as the `int` that an `AtomicI32` is, and is static.
    unsafe {
        module.add_symbol("shared", SHARED.as_ptr() as *const c_void);
        module.link().unwrap();
    }

    assert_eq!(call(&module, "add_to_shared", 1, 1), 42);
    assert_eq!(SHARED.load(Ordering::SeqCst), 42);
}

#[test]
fn runs_init_when_linked_and_finalize_when_dropped() {
    if !has_compiler() {
        return;
    }
    static STAGE: AtomicI32 = AtomicI32::new(0);
    let module = compile(
        "extern int stage;\nvoid init (void) { stage = 1; }\nvoid finalize (void) { stage = 2; }",
    )
    .unwrap();
    // SAFETY: `stage` is declared as the `int` that an `AtomicI32` is, and is static.
    unsafe { module.add_symbol("stage", STAGE.as_ptr() as *const c_void) };
    let before_linking = STAGE.load(Ordering::SeqCst);

    // SAFETY: `init` only writes `stage`.
    unsafe { module.link() }.unwrap();
    let after_linking = STAGE.load(Ordering::SeqCst);
    drop(module);

    assert_eq!(before_linking, 0);
    assert_eq!(after_linking, 1);
    assert_eq!(STAGE.load(Ordering::SeqCst), 2);
}

#[test]
fn reports_what_the_compiler_says() {
    if !has_compiler() {
        return;
    }
    let error = compile("int broken (void) { return undeclared; }")
        .err()
        .expect("the source should not compile");

    assert!(error.0.contains("undeclared"), "{error}");
    assert!(compile("int nul = '\0';").is_err());
}

#[test]
fn reports_what_the_linker_says() {
    if !has_compiler() {
        return;
    }
    let module = compile("extern int missing (void);\nint f (void) { return missing (); }")
        .expect("a call to an undefined function compiles");

    // SAFETY: nothing runs: the module has no `init`.
    let error = unsafe { module.link() }.expect_err("the module should not link");

    assert!(error.0.contains("missing"), "{error}");
}

#[test]
fn links_only_once() {
    if !has_compiler() {
        return;
    }
    let module = linked("int one (void) { return 1; }");

    // SAFETY: nothing runs: the module is not linked again.
    let again = unsafe { module.link() };

    assert_eq!(
        again,
        Err(CModuleError("the module is already linked".to_owned()))
    );
}

#[test]
fn keeps_its_code_but_not_its_symbols_when_its_metadata_is_dropped() {
    if !has_compiler() {
        return;
    }
    let module = linked("int add (int a, int b) { return a + b; }");
    let add = module.find_symbol_by_name("add").unwrap();
    // SAFETY: `add` is `int (int, int)`.
    let add: extern "C" fn(i32, i32) -> i32 = unsafe { std::mem::transmute(add.0) };

    module.drop_metadata();
    module.drop_metadata();

    assert_eq!(add(20, 22), 42);
    assert_eq!(module.find_symbol_by_name("add"), None);
    assert!(module.enumerate_symbols().is_empty());
    assert!(module.range().size() > 0);
}

#[test]
fn does_not_link_once_its_metadata_is_dropped() {
    if !has_compiler() {
        return;
    }
    let module = compile("int one (void) { return 1; }").unwrap();
    module.drop_metadata();

    // SAFETY: nothing runs: the module cannot be linked.
    assert!(unsafe { module.link() }.is_err());
}

#[test]
fn lists_the_macros_every_module_has() {
    let defines = CModule::builtin_defines();

    let pointer_size = defines
        .iter()
        .find(|define| define.name == "GLIB_SIZEOF_VOID_P")
        .and_then(|define| define.value.clone());
    assert_eq!(pointer_size, Some(std::mem::size_of::<usize>().to_string()));
    assert!(
        defines
            .iter()
            .any(|define| define.name.starts_with("HAVE_") && define.value.is_none()),
        "the architecture is defined without a value"
    );
}

#[test]
fn lists_the_headers_every_module_can_include() {
    if !has_compiler() {
        return;
    }
    let headers = CModule::builtin_headers();

    let glib = headers
        .iter()
        .find(|header| header.name == "glib.h")
        .expect("glib.h is built in");
    assert_eq!(glib.kind, CHeaderKind::Frida);
    assert!(glib.data.contains("#define"), "{:.80}", glib.data);
    assert!(headers.iter().any(|header| header.kind == CHeaderKind::Tcc));
}

#[test]
fn a_module_can_use_the_built_in_headers() {
    if !has_compiler() {
        return;
    }
    let module = linked("#include <glib.h>\nint size (int a, int b) { return sizeof (gpointer); }");

    assert_eq!(
        call(&module, "size", 0, 0),
        std::mem::size_of::<usize>() as i32
    );
}
