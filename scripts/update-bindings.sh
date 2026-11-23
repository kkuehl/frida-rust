#!/usr/bin/env bash
#
# Copyright © 2026 Kirby Kuehl
#
# Licence: wxWindows Library Licence, Version 3.1
#
# Regenerate frida/src/gir/generated/ from the GIRs of the release pinned by
# FRIDA_VERSION, with frida_rust/ on top of frida_bindgen_core, the shared core of
# Frida's generated bindings (the frida-bindgen submodule).
#
# The core reads Frida's GIR together with GLib's, GObject's and Gio's:
#
# - frida-core.gir comes from the released core devkits. It is the same on macOS,
#   Linux and Android; the Windows one lacks a few items. So this reads the Linux
#   x86_64 devkit's (the devkit update-headers.sh vendors the header of) and the
#   Windows x86_64 one's, and the generator puts #[cfg(...)] on what only one of
#   them has.
# - GLib-2.0.gir, GObject-2.0.gir and Gio-2.0.gir are the ones frida-core keeps in
#   its repository under src/api/, at the tag of the same release.
#
# Everything downloaded is kept in the cache frida-build downloads devkits to
# ($FRIDA_DEVKIT_CACHE, else ~/.cache/frida/devkits), named by the release, and is
# used from there next time. So regenerating needs python3, curl, tar and, the
# first time for a release, the network.
#
# If the frida-bindgen submodule is not checked out, this checks it out; without
# git, run `git submodule update --init frida-bindgen` in a clone.
#
# Run this after bumping FRIDA_VERSION, and commit the result. Running it twice
# changes nothing. With --fetch-only, it fetches the GIRs, prints their paths in
# the order the generator's options take them, and generates nothing.
set -euo pipefail

fetch_only=0
case "${1:-}" in
  "") ;;
  --fetch-only) fetch_only=1 ;;
  *) echo "usage: $0 [--fetch-only]" >&2; exit 2 ;;
esac

cd "$(dirname "$0")/.."
root=$(pwd)

version=$(cat FRIDA_VERSION)
releases="https://github.com/frida/frida/releases/download/$version"
api="https://raw.githubusercontent.com/frida/frida-core/$version/src/api"
cache="${FRIDA_DEVKIT_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/frida/devkits}"
mkdir -p "$cache"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# download URL PATH: fetches URL to PATH unless PATH exists; never leaves a partial file.
download() {
  local url=$1 path=$2
  if [ -f "$path" ]; then
    return
  fi
  echo "Fetching $url..." >&2
  curl -fsSL -o "$path.part" "$url" || { rm -f "$path.part"; echo "update-bindings.sh: could not fetch $url" >&2; exit 1; }
  mv "$path.part" "$path"
}

# frida_gir PLATFORM: the path of that devkit's frida-core.gir, extracted into the cache.
frida_gir() {
  local platform=$1
  local gir="$cache/frida-core-$version-$platform.gir"
  if [ ! -f "$gir" ]; then
    local archive="$cache/frida-core-devkit-$version-$platform.tar.xz"
    download "$releases/frida-core-devkit-$version-$platform.tar.xz" "$archive"
    mkdir -p "$work/$platform"
    # The member is ./frida-core.gir or frida-core.gir depending on the archive.
    tar -xJf "$archive" -C "$work/$platform" ./frida-core.gir 2>/dev/null \
      || tar -xJf "$archive" -C "$work/$platform" frida-core.gir
    mv "$work/$platform/frida-core.gir" "$gir"
  fi
  echo "$gir"
}

# api_gir NAME: the path of frida-core's src/api/NAME at this release, in the cache.
api_gir() {
  local name=$1
  local gir="$cache/frida-core-$version-$name"
  download "$api/$name" "$gir"
  echo "$gir"
}

unix_gir=$(frida_gir linux-x86_64)
windows_gir=$(frida_gir windows-x86_64)
glib_gir=$(api_gir GLib-2.0.gir)
gobject_gir=$(api_gir GObject-2.0.gir)
gio_gir=$(api_gir Gio-2.0.gir)

if [ "$fetch_only" = 1 ]; then
  printf '%s\n' "$unix_gir" "$windows_gir" "$glib_gir" "$gobject_gir" "$gio_gir"
  exit 0
fi

if [ ! -f frida-bindgen/frida_bindgen_core/__init__.py ]; then
  if command -v git >/dev/null && git rev-parse --git-dir >/dev/null 2>&1; then
    echo "Checking out the frida-bindgen submodule..." >&2
    git submodule update --init frida-bindgen
  else
    echo "update-bindings.sh: frida-bindgen/ is empty; run" \
      "\`git submodule update --init frida-bindgen\` in a git clone" >&2
    exit 1
  fi
elif command -v git >/dev/null && git submodule status frida-bindgen 2>/dev/null | grep -q '^+'; then
  echo "update-bindings.sh: warning: frida-bindgen/ is not at the commit this" \
    "repository pins; \`git submodule update frida-bindgen\` checks that out" >&2
fi

PYTHONPATH="$root/frida-bindgen${PYTHONPATH:+:$PYTHONPATH}" python3 -m frida_rust \
  --gir "$unix_gir" \
  --windows-gir "$windows_gir" \
  --glib-gir "$glib_gir" \
  --gobject-gir "$gobject_gir" \
  --gio-gir "$gio_gir" \
  --output "$root/frida/src/gir/generated" \
  --frida-version "$version"

echo "Formatting and linting the regenerated binding (fmt, clippy --fix, clippy, update, upgrade)..." >&2
cargo fmt --all
cargo clippy --fix --allow-dirty -p frida --lib -- -D warnings
cargo clippy -p frida --lib -- -D warnings
cargo update
cargo upgrade

echo "frida's binding regenerated for Frida $version."
