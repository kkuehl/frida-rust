#!/usr/bin/env bash
#
# Refresh the vendored headers from the devkits pinned by FRIDA_VERSION.
#
# frida-sys/include/frida-core.h is only used for docs builds (DOCS_RS), where
# no devkit can be downloaded. It must be the Linux x86_64 devkit header of the
# release named in FRIDA_VERSION, so that it never drifts from it.
#
# Run this after bumping FRIDA_VERSION, and commit the result.
set -euo pipefail

cd "$(dirname "$0")/.."

version=$(cat FRIDA_VERSION)
base="https://github.com/frida/frida/releases/download/$version"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "Fetching Frida $version devkit headers..."
curl -fsSL -o "$work/frida-core.tar.xz" "$base/frida-core-devkit-$version-linux-x86_64.tar.xz"
tar xJf "$work/frida-core.tar.xz" -C "$work"

cp "$work/frida-core.h" frida-sys/include/frida-core.h

echo "Vendored headers updated to Frida $version."
