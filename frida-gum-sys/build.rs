/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_vendor = env::var("CARGO_CFG_TARGET_VENDOR").unwrap();

    let docs = std::env::var("DOCS_RS").is_ok();
    // We always use frida-gumjs.h for docs to not have to ship two big header files in this repo.
    let use_gum_js = cfg!(feature = "js") || (!cfg!(feature = "auto-download") && docs);
    #[cfg(any(
        feature = "event-sink",
        feature = "invocation-listener",
        feature = "stalker-observer",
        feature = "stalker-params"
    ))]
    let use_gum_js_env = if use_gum_js { "1" } else { "0" };

    #[cfg(feature = "event-sink")]
    {
        println!("cargo:rerun-if-changed=event_sink.c");
        println!("cargo:rerun-if-changed=event_sink.h");
    }

    #[cfg(feature = "invocation-listener")]
    {
        println!("cargo:rerun-if-changed=invocation_listener.c");
        println!("cargo:rerun-if-changed=invocation_listener.h");
        println!("cargo:rerun-if-changed=probe_listener.c");
        println!("cargo:rerun-if-changed=probe_listener.h");
    }

    #[cfg(feature = "stalker-observer")]
    {
        println!("cargo:rerun-if-changed=stalker_observer.c");
        println!("cargo:rerun-if-changed=stalker_observer.h");
    }

    #[cfg(feature = "stalker-params")]
    {
        println!("cargo:rerun-if-changed=stalker_params.c");
        println!("cargo:rerun-if-changed=stalker_params.h");
    }

    // Where a devkit placed by hand is looked for. With `auto-download` the downloaded devkit is
    // the only source of the header and the library: a devkit left in the crate directory is a
    // different Frida version, and would otherwise be found first.
    #[cfg(not(feature = "auto-download"))]
    let include_dir = {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        println!("cargo:rustc-link-search={manifest_dir}");
        manifest_dir
    };

    #[cfg(feature = "auto-download")]
    let include_dir = {
        use frida_build::download_and_use_devkit;
        if cfg!(feature = "js") {
            download_and_use_devkit("gumjs", include_str!("FRIDA_VERSION").trim())
        } else {
            download_and_use_devkit("gum", include_str!("FRIDA_VERSION").trim())
        }
    };

    #[cfg(not(feature = "auto-download"))]
    if cfg!(feature = "js") {
        println!("cargo:rustc-link-lib=frida-gumjs");
    } else {
        println!("cargo:rustc-link-lib=frida-gum");
    }

    if target_os != "android" && (target_os == "linux" || target_vendor == "apple") {
        println!("cargo:rustc-link-lib=pthread");
    }

    // The devkit's GIO looks host names up through libresolv, with or without GumJS.
    if target_vendor == "apple" {
        println!("cargo:rustc-link-lib=resolv");
    }

    if target_os == "android" {
        link_android_compiler_rt_builtins();
    }

    let bindings = bindgen::Builder::default()
        .use_core()
        .formatter(bindgen::Formatter::Prettyplease);

    // The devkit header is included with angle brackets here and in the glue headers, so it is
    // taken from these directories and never from beside the file that includes it.
    let bindings = if cfg!(not(feature = "auto-download")) && docs {
        bindings.clang_arg("-Iinclude")
    } else {
        bindings.clang_arg(format!("-I{include_dir}"))
    };

    let bindings = if use_gum_js {
        bindings
            .clang_arg("-DUSE_GUM_JS=1")
            .header_contents("gum.h", "#include <frida-gumjs.h>")
    } else {
        bindings
            .clang_arg("-DUSE_GUM_JS=0")
            .header_contents("gum.h", "#include <frida-gum.h>")
    };

    let bindings = bindings
        .header("event_sink.h")
        .header("invocation_listener.h")
        .header("probe_listener.h")
        .header("stalker_observer.h")
        .header("stalker_params.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // These libc declarations leak in through the devkit headers and
        // collide with rustc's runtime-symbol lint (`usize` vs `u64`
        // signatures). The wrappers do not use them.
        .blocklist_function("memcmp")
        .blocklist_function("memcpy")
        .blocklist_function("memmove")
        .blocklist_function("memset")
        .blocklist_function("strlen")
        .blocklist_type("GumChainedPtr64Rebase")
        .blocklist_type("GumChainedPtrArm64eRebase")
        .blocklist_type("_GumChainedPtr64Rebase")
        .blocklist_type("_GumChainedPtrArm64eRebase")
        .generate_comments(false)
        .layout_tests(false)
        .generate()
        .unwrap();

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .unwrap();

    #[cfg(feature = "event-sink")]
    {
        let mut builder = cc::Build::new();

        let builder = if cfg!(not(feature = "auto-download")) && docs {
            builder.include("include")
        } else {
            builder.include(&include_dir)
        };

        builder
            .file("event_sink.c")
            .opt_level(3)
            .define("USE_GUM_JS", use_gum_js_env)
            .compile("event_sink");
    }

    #[cfg(feature = "invocation-listener")]
    {
        let mut builder = cc::Build::new();

        let builder = if cfg!(not(feature = "auto-download")) && docs {
            builder.include("include")
        } else {
            builder.include(&include_dir)
        };

        builder
            .file("invocation_listener.c")
            .opt_level(3)
            .define("USE_GUM_JS", use_gum_js_env)
            .compile("invocation_listener");

        let mut builder = cc::Build::new();

        let builder = if cfg!(not(feature = "auto-download")) && docs {
            builder.include("include")
        } else {
            builder.include(&include_dir)
        };
        builder
            .file("probe_listener.c")
            .opt_level(3)
            .define("USE_GUM_JS", use_gum_js_env)
            .compile("probe_listener");
    }

    #[cfg(feature = "stalker-observer")]
    {
        let mut builder = cc::Build::new();

        let builder = if cfg!(not(feature = "auto-download")) && docs {
            builder.include("include")
        } else {
            builder.include(&include_dir)
        };

        builder
            .file("stalker_observer.c")
            .opt_level(3)
            .define("USE_GUM_JS", use_gum_js_env)
            .compile("stalker_observer");
    }

    #[cfg(feature = "stalker-params")]
    {
        let mut builder = cc::Build::new();

        let builder = if cfg!(not(feature = "auto-download")) && docs {
            builder.include("include")
        } else {
            builder.include(&include_dir)
        };

        builder
            .file("stalker_params.c")
            .opt_level(3)
            .define("USE_GUM_JS", use_gum_js_env)
            .compile("stalker_params");
    }

    // MSVC compat: prebuilt frida-gumjs may depend on newer __std_* symbols.
    #[cfg(feature = "js")]
    if target_os == "windows" {
        cc::Build::new()
            .file("msvc_compat.c")
            .compile("msvc_compat");
    }

    if target_os == "windows" {
        for lib in [
            "dnsapi", "iphlpapi", "psapi", "winmm", "ws2_32", "advapi32", "crypt32", "gdi32",
            "kernel32", "ole32", "secur32", "shell32", "shlwapi", "user32", "setupapi",
        ] {
            println!("cargo:rustc-link-lib=dylib={lib}");
        }
    }

    /* GUMJS contains v8 for some architectures, thus it needs to link stdc++ */
    #[cfg(feature = "js")]
    match target_os.as_str() {
        "linux" => {
            println!("cargo:rustc-link-lib=dylib=stdc++")
        }
        "android" => {
            println!("cargo:rustc-link-lib=c++")
        }
        _ => {}
    }
}

/// Gum's cache-flush path (gummemory-linux.c) references the compiler-rt builtin `__clear_cache`.
/// Android's bionic does not provide it (it is a static compiler-rt symbol), so on Android an executable fails to link with "undefined symbol:
/// __clear_cache" and a cdylib loads with that symbol unresolved. Link the NDK's clang_rt.builtins
/// for the target arch to provide it. Located via the target compiler's own resource dir, so it is
/// NDK-version independent.
fn link_android_compiler_rt_builtins() {
    let arch = match env::var("CARGO_CFG_TARGET_ARCH")
        .unwrap_or_default()
        .as_str()
    {
        "aarch64" => "aarch64",
        "arm" => "arm",
        "x86_64" => "x86_64",
        "x86" => "i686",
        other => {
            println!(
                "cargo:warning=frida-gum-sys: unknown android arch '{other}', not linking compiler-rt builtins"
            );
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
            "cargo:warning=frida-gum-sys: could not resolve clang resource dir via '{cc}'; __clear_cache may be unresolved on android"
        ),
    }
}
