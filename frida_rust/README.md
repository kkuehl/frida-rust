frida_rust
==========

Generates `frida::gir` (`frida/src/gir/generated/`) from Frida's GIR. Standard library
only; Python 3.9 or later.

It is built the way frida-python's, frida-node's and frida-swift's generators are: on
`frida_bindgen_core`, the language-neutral core they share, which this repository mounts
as the `frida-bindgen` submodule at the same commit they pin. The core reads Frida's GIR
with GLib's, GObject's and Gio's; this package adds what Rust needs and writes the Rust.

From a fresh clone, at the repository root:

    git submodule update --init frida-bindgen    # or clone with --recurse-submodules
    scripts/update-bindings.sh

The script fetches the inputs for the release in `FRIDA_VERSION` (`frida-core.gir` from
the Linux and Windows x86_64 core devkits, and `GLib-2.0.gir`, `GObject-2.0.gir` and
`Gio-2.0.gir` from frida-core's `src/api/` at that tag), keeps them in the devkit cache,
and runs:

    PYTHONPATH=frida-bindgen python3 -m frida_rust \
        --gir UNIX.gir --windows-gir WINDOWS.gir \
        --glib-gir GLib-2.0.gir --gobject-gir GObject-2.0.gir --gio-gir Gio-2.0.gir \
        --output frida/src/gir/generated --frida-version 17.27.5

`scripts/update-bindings.sh --fetch-only` prints the paths of the five inputs. The output
is formatted with `rustfmt`, and committed: building the crates needs neither Python nor
the submodule.

- `frida_rust/loader.py` has the core's `compute_model` read the GIRs into the classes in
  `model.py`, once for the Unix GIR and once for the Windows one.
- `frida_rust/model.py` subclasses the core's classes, registered through its `Factory`,
  as frida-swift's `model.py` does: the core makes every class, enumeration, method,
  constructor, property, signal, parameter and return value as one of them, and the code
  generator reads them as it made them. The subclasses read from each member's GIR
  element only what the core leaves out of it (docs, a constructor's return value, an
  array's length argument, a callback's user data and scope), and add Rust's views, such
  as the `_sync` function an async method's wrapper calls, checked against the core's
  view of the method.
- `frida_rust/supplements.py` reads what the core leaves out entirely, and only that:
  methods that take a callback, options getters and properties, namespace functions,
  callback types, virtual methods, records, and what the core's readers cannot read. It
  uses the core's readers and `Factory` for them, and the generator's report counts each
  kind. `tests/test_core_usage.py` shows where every generated item comes from.
- `frida_rust/strict.py` refuses any element, attribute or value in Frida's GIR it does not
  know, before the core reads it: the core passes over what it does not need, and this
  generator must not.
- `frida_rust/platforms.py` merges the Unix and Windows models, marking what only one has
  with `#[cfg(...)]`.
- `frida_rust/codegen.py` writes the Rust. Ownership and nullability come from the core's
  members, as the GIR's `transfer-ownership` and `nullable` give them; anything it has no
  rule for fails. An async method becomes a blocking Rust method of the same name, which
  calls its `_sync` form.
- `frida_rust/naming.py` uses the core's naming functions, but where they cannot serve.
- `frida_rust/customization.py` holds what the GIR cannot say (the element types of
  `GLib.Func` callbacks, the GLib callback types allowed, the Gio handle and enumeration
  types, which classes are `Send`
  and `Sync`, which methods are `unsafe`, the hand-written methods on generated types)
  and the skip table.
- Signals become `connect_*` methods taking a `Send + 'static` closure, as frida-core
  emits them on its own thread; their arguments are lent for the emission.

Every item in the GIR is counted. The generator exits non-zero, writing nothing, if any item
is neither generated nor in the skip table, or if a skip-table entry matches nothing to skip.

Tests, from the repository root:

    PYTHONPATH=frida-bindgen python3 -m unittest discover -s frida_rust/tests -t .
