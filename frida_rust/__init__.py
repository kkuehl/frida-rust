#
# Copyright © 2026 Kirby Kuehl
#
# Licence: wxWindows Library Licence, Version 3.1
#
"""Generates frida-rust's `frida::gir` layer from Frida's GIR.

It is built on frida_bindgen_core (the frida-bindgen submodule), the language-neutral
core Frida's other generated bindings share, the way they build on it:

- `loader` has the core read Frida's GIR with GLib's, GObject's and Gio's, through the
  classes in `model`, which the core's `Factory` makes and which add what Rust needs
  and the core leaves out. It does so for a Unix GIR and a Windows one, and `platforms`
  merges the two.
- `strict` refuses any construct in Frida's GIR this does not know.
- `codegen` turns the model into Rust.
- `customization` holds what the GIR cannot say, and the explicit skip table.
"""
