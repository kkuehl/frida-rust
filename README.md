frida-rust
==========

Rust bindings for [Frida](http://www.frida.re/).

## Install

- Build Frida, or download the devkits for your system (see the `frida` README for version)
- For crate installation:
    - Move the frida-core devkit into `rustc-link-search`, e.g.: `/usr/local/{include, lib}` on Unix
- For local development:
    - Move the frida-core devkit into `frida-sys` and `cargo build` in the root

## The generated core API

`frida::gir` is frida-core's whole API (classes, enumerations, constructors, methods and
properties), generated from the `frida-core.gir` that ships in the core devkit by
`frida_rust/`, a standard-library Python package built, like frida-python's, frida-node's
and frida-swift's generators, on Frida's shared generator core: the `frida-bindgen`
submodule. The output is committed under `frida/src/gir/generated/`, so building needs
neither. After bumping `FRIDA_VERSION`, regenerate it and commit the result:

    scripts/update-bindings.sh

It checks out the submodule if it is missing (`git submodule update --init frida-bindgen`
does the same). The generator's tests run with
`PYTHONPATH=frida-bindgen python3 -m unittest discover -s frida_rust/tests -t .` from the
repository root.
