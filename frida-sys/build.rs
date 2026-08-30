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

        // Remove sqlite3 object files from frida-core.lib to avoid symbol
        // collisions with rusqlite's bundled sqlite3 (LNK2005 on MSVC).
        // frida-core embeds its own sqlite3.c which exports the same symbols.
        strip_sqlite3_from_frida_core();
    }
}

fn strip_sqlite3_from_frida_core() {
    let out_dir = env::var("OUT_DIR").unwrap_or_default();
    let lib_path = PathBuf::from(&out_dir).join("frida-core.lib");
    if !lib_path.exists() {
        return;
    }

    // Find lib.exe — it's in the same directory as the linker (link.exe)
    // which cargo already found for us. Try common locations.
    let lib_exe = find_lib_exe();
    let lib_exe = match lib_exe {
        Some(p) => p,
        None => {
            println!("cargo:warning=lib.exe not found, cannot strip sqlite3 from frida-core");
            return;
        }
    };

    let output = std::process::Command::new(&lib_exe)
        .arg("/LIST")
        .arg(&lib_path)
        .output();

    let sqlite_objs: Vec<String> = match output {
        Ok(ref o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter(|l| l.to_lowercase().contains("sqlite3"))
            .map(|l| l.trim().to_string())
            .collect(),
        _ => return,
    };

    if sqlite_objs.is_empty() {
        return;
    }

    for obj in &sqlite_objs {
        let status = std::process::Command::new(&lib_exe)
            .arg(format!("/REMOVE:{}", obj))
            .arg(&lib_path)
            .arg(format!("/OUT:{}", lib_path.display()))
            .status();
        if let Ok(s) = status {
            if s.success() {
                println!("cargo:warning=stripped {} from frida-core.lib", obj);
            }
        }
    }
}

fn find_lib_exe() -> Option<String> {
    // lib.exe is typically next to cl.exe and link.exe
    if let Ok(output) = std::process::Command::new("where").arg("lib.exe").output() {
        if output.status.success() {
            if let Some(first) = String::from_utf8_lossy(&output.stdout).lines().next() {
                return Some(first.trim().to_string());
            }
        }
    }

    // Try vswhere to find MSVC
    let vswhere = r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe";
    if let Ok(output) = std::process::Command::new(vswhere)
        .args(["-latest", "-property", "installationPath"])
        .output()
    {
        if output.status.success() {
            let vs_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let msvc_dir = PathBuf::from(&vs_path).join("VC").join("Tools").join("MSVC");
            if let Ok(entries) = std::fs::read_dir(&msvc_dir) {
                for entry in entries.flatten() {
                    let candidate = entry
                        .path()
                        .join("bin")
                        .join("Hostx64")
                        .join("x64")
                        .join("lib.exe");
                    if candidate.exists() {
                        return Some(candidate.to_string_lossy().to_string());
                    }
                }
            }
        }
    }

    None
}
