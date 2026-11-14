//! Tests for `Compiler::build_library` and `Compiler::watch_library`, which run the real
//! compiler on a small project in a temporary directory.

use frida::{Compiler, DeviceManager, Error, Frida, LibraryOptions, SourceMaps};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, MutexGuard};

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

// Frida-core is a process-wide singleton, so all tests that talk to it must
// serialize (same convention as `compile_script.rs`).
static FRIDA_SERIAL: Mutex<()> = Mutex::new(());

fn serial_guard() -> MutexGuard<'static, ()> {
    FRIDA_SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

/// A project with one module, and the path of that module.
fn project() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let entrypoint = dir.path().join("greeter.ts");
    std::fs::write(
        &entrypoint,
        "export function greet(name: string): string {\n    return `hello ${name}`;\n}\n",
    )
    .expect("write entrypoint");
    let entrypoint = entrypoint.to_str().expect("utf-8 path").to_owned();
    (dir, entrypoint)
}

/// The names of the files under `dir`, sorted.
fn files_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn output_of(project: &tempfile::TempDir, name: &str) -> (PathBuf, String) {
    let dir = project.path().join(name);
    let path = dir.to_str().expect("utf-8 path").to_owned();
    (dir, path)
}

#[test]
fn library_options_keep_what_they_are_set_to() {
    let _serial = serial_guard();
    let _frida = &*FRIDA;
    let options = LibraryOptions::new();
    let defaults = (options.project_root(), options.source_maps());

    options.set_project_root("/some/project");
    options.set_source_maps(SourceMaps::Omitted);
    options.set_project_root("ignored\0root");

    assert_eq!(defaults, (None, SourceMaps::Included));
    assert_eq!(options.project_root().as_deref(), Some("/some/project"));
    assert_eq!(options.source_maps(), SourceMaps::Omitted);
}

#[test]
fn builds_a_module_and_its_declarations() {
    let _serial = serial_guard();
    let device_manager = DeviceManager::obtain(&FRIDA);
    let compiler = Compiler::new(&device_manager);
    let (project, entrypoint) = project();
    let (output, output_path) = output_of(&project, "dist");

    compiler
        .build_library(&entrypoint, &output_path, None)
        .expect("the library should build");

    let files = files_in(&output);
    let module = std::fs::read_to_string(output.join("greeter.js")).unwrap_or_default();
    let declarations = std::fs::read_to_string(output.join("greeter.d.ts")).unwrap_or_default();
    assert!(module.contains("greet"), "{files:?}: {module}");
    assert!(
        declarations.contains("greet(name: string): string"),
        "{files:?}: {declarations}"
    );
    assert!(
        files.iter().any(|name| name.ends_with(".map")),
        "source maps are emitted unless omitted: {files:?}"
    );
}

#[test]
fn omits_source_maps_when_asked_to() {
    let _serial = serial_guard();
    let device_manager = DeviceManager::obtain(&FRIDA);
    let compiler = Compiler::new(&device_manager);
    let (project, entrypoint) = project();
    let (output, output_path) = output_of(&project, "dist");
    let options = LibraryOptions::new();
    options.set_source_maps(SourceMaps::Omitted);

    compiler
        .build_library(&entrypoint, &output_path, Some(&options))
        .expect("the library should build");

    let files = files_in(&output);
    assert!(files.contains(&"greeter.js".to_owned()), "{files:?}");
    assert!(
        !files.iter().any(|name| name.ends_with(".map")),
        "{files:?}"
    );
}

#[test]
fn reports_what_is_wrong_with_a_library_that_does_not_build() {
    let _serial = serial_guard();
    let device_manager = DeviceManager::obtain(&FRIDA);
    let compiler = Compiler::new(&device_manager);
    let (project, _) = project();
    let (_, output_path) = output_of(&project, "dist");
    let missing = project.path().join("missing.ts");

    let built = compiler.build_library(missing.to_str().unwrap(), &output_path, None);
    let with_nul = compiler.build_library("entry\0point.ts", &output_path, None);

    assert!(
        matches!(&built, Err(Error::CompilerBuildFailed { message, .. }) if !message.is_empty()),
        "{built:?}"
    );
    assert!(
        matches!(with_nul, Err(Error::CStringFailed)),
        "{with_nul:?}"
    );
}

#[test]
fn watching_builds_the_library_once_it_has_started() {
    let _serial = serial_guard();
    let device_manager = DeviceManager::obtain(&FRIDA);
    let compiler = Compiler::new(&device_manager);
    let (project, entrypoint) = project();
    let (output, output_path) = output_of(&project, "watched");

    compiler
        .watch_library(&entrypoint, &output_path, None)
        .expect("the watch should start");
    // The first build finishes after the watch has started. Give it twenty seconds.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut files = files_in(&output);
    while files.len() < 2 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
        files = files_in(&output);
    }
    drop(compiler);

    assert!(files.contains(&"greeter.js".to_owned()), "{files:?}");
    assert!(files.contains(&"greeter.d.ts".to_owned()), "{files:?}");
}
