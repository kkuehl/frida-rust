/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    println!(
        "cargo:rustc-link-search={}",
        env::var("CARGO_MANIFEST_DIR").unwrap()
    );
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_vendor = env::var("CARGO_CFG_TARGET_VENDOR").unwrap();

    #[cfg(feature = "auto-download")]
    let include_dir = {
        use frida_build::download_and_use_devkit;
        download_and_use_devkit("core", include_str!("FRIDA_VERSION").trim())
    };

    #[cfg(not(feature = "auto-download"))]
    println!("cargo:rustc-link-lib=frida-core");

    if target_os == "linux" {
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=resolv");
    }

    if target_vendor == "apple" {
        println!("cargo:rustc-link-lib=bsm");
        println!("cargo:rustc-link-lib=resolv");
        println!("cargo:rustc-link-lib=pthread");
        if target_os == "macos" {
            println!("cargo:rustc-link-lib=framework=AppKit");
            println!("cargo:rustc-link-lib=framework=Security");
            println!("cargo:rustc-link-lib=framework=IOKit");
        }
    }

    if target_os == "android" {
        link_android_compiler_rt_builtins();
    }

    let bindings = bindgen::Builder::default();

    #[cfg(feature = "auto-download")]
    let bindings = bindings.clang_arg(format!("-I{include_dir}"));

    #[cfg(not(feature = "auto-download"))]
    let bindings = if std::env::var("DOCS_RS").is_ok() {
        bindings.clang_arg("-Iinclude")
    } else {
        bindings
    };

    let bindings = bindings
        .formatter(bindgen::Formatter::Prettyplease)
        .header_contents("core.h", "#include \"frida-core.h\"")
        // These libc declarations leak in through the devkit headers and
        // collide with rustc's runtime-symbol lint (`usize` vs `u64`
        // signatures). The wrappers do not use them.
        .blocklist_function("memcmp")
        .blocklist_function("memcpy")
        .blocklist_function("memmove")
        .blocklist_function("memset")
        .blocklist_function("strlen")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate_comments(false)
        .layout_tests(false)
        .generate()
        .unwrap();

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .unwrap();

    if target_os == "windows" {
        for lib in [
            "dnsapi", "iphlpapi", "psapi", "winmm", "ws2_32", "advapi32", "crypt32", "gdi32",
            "kernel32", "ole32", "secur32", "shell32", "shlwapi", "user32", "setupapi",
        ] {
            println!("cargo:rustc-link-lib=dylib={lib}");
        }
    }
}

/// The frida-core devkit bundles frida-gum, whose cache-flush path (gummemory-linux.c) references the
/// compiler-rt builtin `__clear_cache`. Android's bionic does not provide it (it is a static
/// compiler-rt symbol), so on Android an executable fails to link with "undefined symbol:
/// __clear_cache" and a cdylib loads with that symbol unresolved. Link the NDK's clang_rt.builtins
/// for the target arch to provide it. Located via the target compiler's own resource dir, so it is
/// NDK-version independent.
fn link_android_compiler_rt_builtins() {
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default().as_str() {
        "aarch64" => "aarch64",
        "arm" => "arm",
        "x86_64" => "x86_64",
        "x86" => "i686",
        other => {
            println!("cargo:warning=frida-sys: unknown android arch '{other}', not linking compiler-rt builtins");
            return;
        }
    };
    // cargo exposes the target C compiler as CC_<target> (dashes) or CC_<target underscored>;
    // cargo-ndk sets it to the NDK clang. Fall back to CC, then plain clang.
    let target = env::var("TARGET").unwrap_or_default();
    let cc = env::var(format!("CC_{target}"))
        .or_else(|_| env::var(format!("CC_{}", target.replace('-', "_"))))
        .or_else(|_| env::var("CC"))
        .unwrap_or_else(|_| "clang".to_string());
    let resource_dir = std::process::Command::new(&cc)
        .arg("-print-resource-dir")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    match resource_dir {
        Some(dir) if !dir.is_empty() => {
            // builtins live at <resource-dir>/lib/linux/libclang_rt.builtins-<arch>-android.a
            println!("cargo:rustc-link-search=native={dir}/lib/linux");
            println!("cargo:rustc-link-lib=static=clang_rt.builtins-{arch}-android");
        }
        _ => println!(
            "cargo:warning=frida-sys: could not resolve clang resource dir via '{cc}'; __clear_cache may be unresolved on android"
        ),
    }
}
