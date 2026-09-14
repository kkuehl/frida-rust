//! Integration tests for the 17.18.0 additions: `Compiler`, `LanguageServer`,
//! and the Barebone config/options wrappers.
//!
//! These exercise the real frida-core runtime. CI runs them via
//! `cargo test --features=auto-download`, which fetches the matching
//! frida-core devkit.

use frida::{
    BareboneConfig, BareboneDeviceOptions, BuildOptions, Compiler, CompilerOptionsBuilder,
    DeviceManager, Frida, JsPlatform, LanguageServer, LanguageServerHandler, SourceMaps,
    TypeCheckMode,
};
use std::io::Write;
use std::sync::{LazyLock, Mutex, MutexGuard};

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

// Frida-core is a process-wide singleton, so all tests that talk to it must
// serialize (same convention as `compile_script.rs`).
static FRIDA_SERIAL: Mutex<()> = Mutex::new(());

fn serial_guard() -> MutexGuard<'static, ()> {
    FRIDA_SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

fn write_project(root: &std::path::Path, entrypoint: &str, source: &str) {
    let path = root.join(entrypoint);
    let mut f = std::fs::File::create(&path).expect("create entrypoint");
    f.write_all(source.as_bytes()).expect("write entrypoint");
    f.sync_all().expect("sync");
}

#[test]
fn compiler_build_emits_non_empty_bundle() {
    let _serial = serial_guard();
    let device_manager = DeviceManager::obtain(&FRIDA);
    let compiler = Compiler::new(&device_manager);

    let dir = tempfile::tempdir().expect("tempdir");
    write_project(
        dir.path(),
        "entry.js",
        "console.log('hello from frida compiler');\n",
    );

    let entry = dir.path().join("entry.js");
    let bundle = compiler
        .build(entry.to_str().expect("utf-8 path"), None)
        .expect("compiler build");

    assert!(
        bundle.contains("hello from frida compiler"),
        "bundle should contain the log message: {bundle}"
    );
}

#[test]
fn compiler_build_respects_options() {
    let _serial = serial_guard();
    let device_manager = DeviceManager::obtain(&FRIDA);
    let compiler = Compiler::new(&device_manager);

    let dir = tempfile::tempdir().expect("tempdir");
    write_project(
        dir.path(),
        "entry.ts",
        "const answer: any = 42;\nconsole.log(answer);\n",
    );

    let opts = BuildOptions::from_builder(
        CompilerOptionsBuilder::default()
            .type_check(TypeCheckMode::None)
            .source_maps(SourceMaps::Omitted)
            .platform(JsPlatform::Gum),
    );

    let entry = dir.path().join("entry.ts");
    let bundle = compiler
        .build(entry.to_str().expect("utf-8 path"), Some(&opts))
        .expect("compiler build with options");

    assert!(!bundle.is_empty(), "bundle should not be empty");
    assert!(
        !bundle.contains("sourceMappingURL"),
        "source maps should be omitted"
    );
}

struct LspHandler {
    inner: std::sync::Arc<Mutex<Vec<String>>>,
}

impl LanguageServerHandler for LspHandler {
    fn on_message(&mut self, json: &str) {
        self.inner.lock().unwrap().push(json.to_string());
    }
}

#[test]
fn language_server_lifecycle() {
    let _serial = serial_guard();

    let dir = tempfile::tempdir().expect("tempdir");
    // Give the LSP something to look at so it doesn't complain about the root.
    write_project(dir.path(), "entry.ts", "export const x: number = 1;\n");

    let mut server = LanguageServer::new(dir.path().to_str().expect("utf-8 path"))
        .expect("construct language server");

    let messages = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
    server
        .handle_message(LspHandler {
            inner: messages.clone(),
        })
        .expect("register handler");

    server.start().expect("language server start");
    server.stop();
}

#[test]
fn barebone_config_and_options_construct_and_drop() {
    let _serial = serial_guard();
    // Ensure the Frida runtime is initialized before touching any GObject
    // constructors from frida-core.
    let _frida = &*FRIDA;
    let _config = BareboneConfig::new();
    let _options = BareboneDeviceOptions::new()
        .id("test-barebone-id")
        .name("test-barebone");
}
