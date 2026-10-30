/*
 * Copyright © 2021 Keegan Saunders
 * Copyright © 2021 S Rubenstein
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use std::{
    env,
    fs::{self, File, remove_file},
    io::{self, Error},
    path::{Path, PathBuf},
};
use tar::Archive;
use xz::read::XzDecoder;

/// Persistent cache directory for downloaded devkits.
///
/// The devkit is extracted into the hash-specific `OUT_DIR`, so without a
/// shared cache the same ~40MB archive is re-downloaded every time the build
/// hash changes (feature set, dependency rev, etc.). Caching the archive in a
/// stable location means it is downloaded once and reused across all build
/// configurations.
fn devkit_cache_dir() -> PathBuf {
    if let Some(dir) = env::var_os("FRIDA_DEVKIT_CACHE") {
        return PathBuf::from(dir);
    }
    let base = env::var_os("LOCALAPPDATA")
        .or_else(|| env::var_os("XDG_CACHE_HOME"))
        .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache").into_os_string()))
        .unwrap_or_else(|| PathBuf::from(".").into_os_string());
    PathBuf::from(base).join("frida").join("devkits")
}

/// private function to retry download in case of error.
fn download_and_use_devkit_internal(
    kind: &str,
    version: &str,
    force_download: bool,
) -> Result<String, Error> {
    let mut target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir_path = Path::new(&out_dir);

    match (os.as_str(), target_arch.as_str()) {
        (_, "aarch64") => {
            target_arch = "arm64".to_string();
        }
        ("linux", "arm") => {
            target_arch = "armhf".to_string();
        }
        (_, "i686") => {
            target_arch = "x86".to_string();
        }
        _ => {}
    }

    let devkit_name = format!("frida-{kind}-devkit-{version}-{os}-{target_arch}",);

    let devkit_path = out_dir_path.join(&devkit_name);
    let devkit_tar = out_dir_path.join(format!("{devkit_name}.tar.xz"));
    let cache_tar = devkit_cache_dir().join(format!("{devkit_name}.tar.xz"));

    if force_download {
        drop(remove_file(&devkit_tar));
        drop(remove_file(&cache_tar));
    }

    if !devkit_path.is_dir() {
        if !devkit_tar.is_file() {
            if cache_tar.is_file() {
                // Reuse the previously-downloaded archive instead of hitting
                // the network again.
                fs::create_dir_all(out_dir_path)?;
                fs::copy(&cache_tar, &devkit_tar)?;
            } else {
                let cdn = env::var("FRIDA_DOWNLOAD_CDN")
                    .unwrap_or("https://github.com/frida/frida/releases/download".to_owned());
                let cdn = cdn.trim_end_matches("/");

                let frida_url = format!("{cdn}/{version}/{devkit_name}.tar.xz",);

                println!(
                    "cargo:warning=Frida {} devkit not found, downloading from {}...",
                    kind, frida_url,
                );
                // Download the devkit into the persistent cache, then copy it
                // into the OUT_DIR for extraction.
                let mut resp =
                    reqwest::blocking::get(&frida_url).expect("devkit download request failed");
                fs::create_dir_all(cache_tar.parent().unwrap())?;
                let mut out = File::create(&cache_tar).expect("failed to create devkit tar file");
                io::copy(&mut resp, &mut out).expect("failed to copy devkit tar content");
                fs::create_dir_all(out_dir_path)?;
                fs::copy(&cache_tar, &devkit_tar)?;
            }
        }
        let tar_xz = File::open(&devkit_tar).expect("failed to open devkit tar.xz for extraction");
        let tar = XzDecoder::new(tar_xz);
        let mut archive = Archive::new(tar);
        archive.unpack(out_dir_path)?;
    }

    println!("cargo:rustc-link-search={}", out_dir.to_string_lossy());
    println!("cargo:rustc-link-lib=static=frida-{kind}");

    Ok(out_dir.to_string_lossy().to_string())
}

#[must_use]
pub fn download_and_use_devkit(kind: &str, version: &str) -> String {
    download_and_use_devkit_internal(kind, version, false)
        .or_else(|e| {
            println!("cargo:warning=Failed to unpack devkit: {e}, retrying download...");
            download_and_use_devkit_internal(kind, version, true)
        })
        .expect("cannot extract the devkit tar.gz")
}
