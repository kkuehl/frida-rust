#
# Copyright © 2026 Kirby Kuehl
#
# Licence: wxWindows Library Licence, Version 3.1
#
"""Turning GIR names into Rust names, with frida_bindgen_core's naming functions.

The core's `to_snake_case` and `to_pascal_case` give every name the generator asks for
today, and this uses them, but for what they get wrong:

- `to_snake_case` never returns on an uppercase letter followed by a character that is
  neither upper nor lower case (`X86Thing`, `A1`), so such a name goes to frida-rust's
  own rule, `_snake`, instead (`x86_thing`, `a1`). No name in Frida's GIR is one today.
- `to_pascal_case` splits only at `_`, where a GIR nick also has `-`, and can begin with
  a digit, which a Rust name cannot.
"""
from __future__ import annotations

import re

from frida_bindgen_core.naming import to_pascal_case, to_snake_case

RUST_KEYWORDS = {
    "as", "async", "await", "box", "break", "const", "continue", "crate", "do", "dyn",
    "else", "enum", "extern", "false", "final", "fn", "for", "gen", "if", "impl", "in",
    "let", "loop", "macro", "match", "mod", "move", "mut", "override", "priv", "pub",
    "ref", "return", "self", "Self", "static", "struct", "super", "trait", "true", "try",
    "type", "typeof", "union", "unsafe", "unsized", "use", "virtual", "where", "while",
    "yield", "abstract", "become",
}


def _core_snake_hangs(name: str) -> bool:
    """Whether the core's `to_snake_case` would loop for ever on `name`: an uppercase
    letter followed by a character that is neither upper nor lower case."""
    return any(
        c.isupper() and not (following.isupper() or following.islower())
        for c, following in zip(name, name[1:])
    )


def snake(name: str) -> str:
    """`DeviceManager` as `device_manager`, `IOStream` as `io_stream`."""
    if _core_snake_hangs(name):
        return _snake(name)
    return to_snake_case(name)


def _snake(name: str) -> str:
    """frida-rust's own rule, for a name `to_snake_case` does not return on."""
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    return s.lower()


def pascal(name: str) -> str:
    """`server_not_running` (or `server-not-running`) as `ServerNotRunning`."""
    result = to_pascal_case(name.replace("-", "_"))
    if not result or not result[0].isalpha():
        result = "V" + result
    return result


def ident(name: str) -> str:
    """A GIR name usable as a Rust parameter or method name."""
    name = name.replace("-", "_")
    if name in RUST_KEYWORDS:
        return name + "_"
    return name
