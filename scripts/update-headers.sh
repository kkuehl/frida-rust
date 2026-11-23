#!/usr/bin/env bash
#
# Refresh the vendored headers from the devkits pinned by FRIDA_VERSION.
#
# frida-sys/include/frida-core.h and frida-gum-sys/include/frida-gumjs.h are
# only used for docs builds (DOCS_RS), where no devkit can be downloaded. They
# must be the Linux x86_64 devkit headers of the release named in
# FRIDA_VERSION, so that they never drift from it.
#
# Run this after bumping FRIDA_VERSION, and commit the result.
set -euo pipefail

cd "$(dirname "$0")/.."

version=$(cat FRIDA_VERSION)
base="https://github.com/frida/frida/releases/download/$version"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "Fetching Frida $version devkit headers..."
curl -fsSL -o "$work/frida-gumjs.tar.xz" "$base/frida-gumjs-devkit-$version-linux-x86_64.tar.xz"
curl -fsSL -o "$work/frida-core.tar.xz" "$base/frida-core-devkit-$version-linux-x86_64.tar.xz"
tar xJf "$work/frida-gumjs.tar.xz" -C "$work"
tar xJf "$work/frida-core.tar.xz" -C "$work"

cp "$work/frida-gumjs.h" frida-gum-sys/include/frida-gumjs.h
cp "$work/frida-core.h" frida-sys/include/frida-core.h

echo "Vendored headers updated to Frida $version."
