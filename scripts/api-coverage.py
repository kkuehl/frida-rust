#!/usr/bin/env python3
"""List the functions of the pinned Frida devkits that no Rust source here names.

    scripts/api-coverage.py core [--full] [TYPE...]

It reads the bindings bindgen generated in the last build, so build first:

    cargo build -p frida --features auto-download               # for core

Without --full it prints one line per type; with it, every function. Naming types
(e.g. frida_device gum_elf_module) limits the output to those.

A function counts as covered when its name appears anywhere in the crate's Rust sources. Left out
as plumbing a wrapper does not call by name: *_get_type,
*_quark, *_ref, *_unref, *_copy, *_free, and the async half of a call whose *_sync form exists.
The list is for the devkit of the machine it runs on: other targets declare some other functions.
"""
import collections
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LIBRARIES = {
    # name: (function prefix, build directory pattern, marker of the fullest bindings, sources)
    "core": ("frida_", "frida-sys-*", "frida_device_manager_", ["frida/src"]),
}


def newest_bindings(pattern, marker):
    paths = glob.glob(os.path.join(ROOT, "target", "*", "build", pattern, "out", "bindings.rs"))
    paths += glob.glob(os.path.join(ROOT, "target", "*", "*", "build", pattern, "out", "bindings.rs"))
    paths.sort(key=os.path.getmtime, reverse=True)
    for path in paths:
        if marker in open(path, errors="replace").read():
            return path
    return None


def names_used(prefix, directories):
    used = set()
    for directory in directories:
        for extension in ("rs", "c", "h"):
            pattern = os.path.join(ROOT, directory, "**", "*." + extension)
            for path in glob.glob(pattern, recursive=True):
                # The vendored devkit header names every function there is.
                if os.sep + "include" + os.sep in path:
                    continue
                text = open(path, errors="replace").read()
                used.update(re.findall(r"\b(%s[a-z0-9_]+)\b" % re.escape(prefix), text))
    return used


def is_plumbing(name):
    return name.endswith(("_get_type", "_quark", "_ref", "_unref", "_copy", "_free", "_finish"))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    full = "--full" in sys.argv
    if not args or args[0] not in LIBRARIES:
        sys.exit(__doc__)
    prefix, pattern, marker, sources = LIBRARIES[args[0]]
    only = set(args[1:])

    bindings = newest_bindings(pattern, marker)
    if bindings is None:
        sys.exit("no bindings found under target/: build first, as the top of this script says")
    text = open(bindings, errors="replace").read()
    declared = sorted(set(re.findall(r"pub fn (%s[a-z0-9_]+)\s*\(" % re.escape(prefix), text)))
    used = names_used(prefix, sources)

    # A type is whatever has a _get_type or a _new.
    types = set()
    for name in declared:
        for suffix in ("_get_type", "_new"):
            if name.endswith(suffix):
                types.add(name[: -len(suffix)])
    types = sorted(types, key=len, reverse=True)

    def owner(name):
        for candidate in types:
            if name.startswith(candidate + "_"):
                return candidate
        return "_".join(name.split("_")[:2])

    callable_names = [n for n in declared if not is_plumbing(n)]
    declared_set = set(declared)
    missing = []
    async_twins = 0
    for name in callable_names:
        if name in used:
            continue
        if not name.endswith("_sync") and name + "_sync" in declared_set:
            async_twins += 1
            continue
        missing.append(name)

    version = re.search(r'pub const FRIDA_VERSION: &\[u8; \d+\] = b"([0-9.]+)', text)
    print(os.path.relpath(bindings, ROOT) + (f"  (Frida {version.group(1)})" if version else ""))
    print(
        f"{len(callable_names)} callable, {len(callable_names) - len(missing) - async_twins} named in Rust, "
        f"{async_twins} async halves of a *_sync, {len(missing)} not named"
    )
    print()

    totals = collections.Counter(owner(n) for n in callable_names)
    groups = collections.defaultdict(list)
    for name in missing:
        groups[owner(name)].append(name)
    for type_name, names in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0])):
        if only and type_name not in only:
            continue
        state = "nothing bound" if len(names) == totals[type_name] else "partly bound"
        print(f"{len(names):4d} of {totals[type_name]:4d} missing  {state:13s}  {type_name}")
        if full:
            for name in names:
                print(f"            {name}")


if __name__ == "__main__":
    main()
