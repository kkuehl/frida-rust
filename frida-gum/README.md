# frida-gum [![docs.rs](https://docs.rs/frida-gum/badge.svg)](https://docs.rs/frida-gum)

Rust bindings for [Frida Gum](https://github.com/frida/frida-gum).

## Before Installing

- Build Frida or download the [latest supported package](https://github.com/frida/frida/releases/)
- Move `frida-gum.h` and `libfrida-gum.a` into `/usr/local/include` and `/usr/local/lib` (or a more appropriate folder that Rust can detect)

Or: use the `auto-download` feature to install Frida.

See the documentation for usage instructions.

## Verification

Two checkers can be run by hand besides the tests. Neither is part of CI.

[Kani](https://model-checking.github.io/kani/) proves the `#[kani::proof]` functions in `src` for every input they can be given:

```sh
cargo kani -p frida-gum --features auto-download
```

[loom](https://docs.rs/loom) runs the test of the `Gum` singleton under every interleaving of its threads:

```sh
RUSTFLAGS="--cfg loom" cargo test -p frida-gum --features auto-download --lib --release \
    --target "$(rustc -vV | sed -n 's/host: //p')" singleton
```

The target is named so that the flag reaches `frida-gum` and not the build script's dependencies, some of which do not build with it.
