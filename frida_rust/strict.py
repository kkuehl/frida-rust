#
# Copyright © 2026 Kirby Kuehl
#
# Licence: wxWindows Library Licence, Version 3.1
#
"""Refuses a Frida GIR holding anything this generator does not know.

frida_bindgen_core reads what it needs from a GIR and passes over the rest. That suits a
binding that wraps a chosen part of the API; frida-rust wraps all of it and counts every
item. So before the core reads Frida's GIR, `check` walks the whole file and raises
`UnsupportedConstruct` for any element, attribute or value it has no rule for: a Frida
release that adds a new kind of construct stops the generator instead of being dropped
without a word.

The rules are the element and attribute names, which children each element may have, and
the values that the core's readers, `model` and `supplements` rely on (flags of 0 or 1,
known ownership transfers, directions and scopes, integers where an index is expected, one
type where one is expected). GLib's, GObject's and Gio's GIRs are not checked: frida-rust
takes from them only the types and callback types Frida's refers to, which the core
resolves.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Set, Union

from .model import UnsupportedConstruct

CORE = "http://www.gtk.org/introspection/core/1.0"
C = "http://www.gtk.org/introspection/c/1.0"
GLIB = "http://www.gtk.org/introspection/glib/1.0"
XML = "http://www.w3.org/XML/1998/namespace"

_PREFIXES = {CORE: "", C: "c:", GLIB: "glib:", XML: "xml:"}

_DOC_ATTRS = {"xml:space", "filename", "line"}
_CALLABLE_CHILDREN = {"doc", "parameters", "return-value"}
_TYPED_CHILDREN = {"doc", "type", "array"}

# Each element the GIR may hold: its attributes, and the children it may have.
_RULES: Dict[str, "tuple[Set[str], Set[str]]"] = {
    "repository": ({"version"}, {"include", "package", "c:include", "namespace"}),
    "include": ({"name", "version"}, set()),
    "package": ({"name"}, set()),
    "c:include": ({"name"}, set()),
    "namespace": (
        {"name", "version", "c:prefix", "c:identifier-prefixes", "c:symbol-prefixes"},
        {"class", "interface", "record", "enumeration", "function", "callback"},
    ),
    "class": (
        {
            "name", "c:type", "c:symbol-prefix", "glib:type-name", "glib:get-type",
            "glib:type-struct", "parent", "abstract", "final",
        },
        {"doc", "constructor", "function", "method", "virtual-method", "property", "glib:signal", "implements"},
    ),
    "interface": (
        {"name", "c:type", "c:symbol-prefix", "glib:type-name", "glib:get-type", "glib:type-struct"},
        {"doc", "function", "method", "virtual-method", "property", "glib:signal", "prerequisite"},
    ),
    "record": ({"name", "c:type", "glib:is-gtype-struct-for"}, {"field", "doc"}),
    "field": ({"name", "private", "readable"}, {"type", "callback", "array"}),
    "enumeration": (
        {"name", "c:type", "glib:type-name", "glib:get-type", "glib:error-domain"},
        {"doc", "member"},
    ),
    "member": ({"name", "c:identifier", "value"}, {"doc"}),
    "constructor": ({"name", "c:identifier", "throws"}, _CALLABLE_CHILDREN),
    "function": ({"name", "c:identifier", "throws"}, _CALLABLE_CHILDREN),
    "method": ({"name", "c:identifier", "throws"}, _CALLABLE_CHILDREN),
    "virtual-method": ({"name", "invoker", "throws"}, _CALLABLE_CHILDREN),
    "callback": ({"name", "c:type", "throws"}, _CALLABLE_CHILDREN),
    "glib:signal": ({"name"}, _CALLABLE_CHILDREN),
    "property": ({"name", "writable", "construct-only", "default-value"}, _TYPED_CHILDREN),
    "implements": ({"name"}, set()),
    "prerequisite": ({"name"}, set()),
    "parameters": (set(), {"parameter", "instance-parameter"}),
    "parameter": (
        {"name", "direction", "nullable", "transfer-ownership", "closure", "destroy", "scope"},
        _TYPED_CHILDREN,
    ),
    "instance-parameter": ({"name", "transfer-ownership"}, _TYPED_CHILDREN),
    "return-value": ({"nullable", "transfer-ownership"}, _TYPED_CHILDREN),
    "type": ({"name", "c:type"}, {"type", "array"}),
    "array": ({"c:type", "length", "zero-terminated", "fixed-size"}, {"type", "array"}),
    "doc": (_DOC_ATTRS, set()),
}

_FLAGS = {
    "abstract", "final", "throws", "writable", "construct-only", "nullable",
    "zero-terminated", "private", "readable",
}
_INTEGERS = {"closure", "destroy", "length", "fixed-size", "value"}
_VALUES = {
    "transfer-ownership": {"none", "full", "container"},
    "direction": {"in", "out", "inout"},
    "scope": {"call", "async", "notified", "forever"},
}
# Each namespace-level kind and the table its names must be unique in.
_TABLES = {
    "class": "objects", "interface": "objects", "enumeration": "enumerations",
    "function": "functions", "callback": "callbacks", "record": "records",
}
_REQUIRED = {
    "class": ("c:type", "glib:get-type"),
    "interface": ("c:type", "glib:get-type"),
    "enumeration": ("c:type",),
    "member": ("c:identifier", "value"),
    "constructor": ("c:identifier",),
    "function": ("c:identifier",),
    "method": ("c:identifier",),
    "callback": ("c:type",),
    "type": ("name",),
}


def _short(name: str) -> str:
    """`{uri}local` as `prefix:local`, the way the GIR file spells it."""
    if name.startswith("{"):
        uri, local = name[1:].split("}", 1)
        prefix = _PREFIXES.get(uri)
        if prefix is None:
            raise UnsupportedConstruct(f"unknown XML namespace {uri}")
        return prefix + local
    return name


def check(source: Union[str, Path]) -> None:
    """Raise `UnsupportedConstruct` unless every construct in the GIR at `source` is known."""
    root = ET.parse(str(source)).getroot()
    if _short(root.tag) != "repository":
        raise UnsupportedConstruct("not a GIR repository")
    _walk(root, "repository", None)
    namespaces = [c for c in root if _short(c.tag) == "namespace"]
    if len(namespaces) != 1:
        raise UnsupportedConstruct(f"expected one <namespace>, found {len(namespaces)}")
    ns = namespaces[0]
    name = ns.get("name")
    seen: Dict[str, Set[str]] = {}
    for item in ns:
        table = seen.setdefault(_TABLES[_short(item.tag)], set())
        item_name = item.get("name")
        if item_name in table:
            raise UnsupportedConstruct(f"{name}.{item_name}: defined twice")
        table.add(item_name)
        _check_toplevel(item, f"{name}.{item_name}")


def _walk(element: ET.Element, path: str, parent: Optional[str]) -> str:
    """Checks `element` and everything under it; returns its tag."""
    tag = _short(element.tag)
    rule = _RULES.get(tag)
    if rule is None:
        raise UnsupportedConstruct(f"{path}: unknown element <{tag}>")
    attributes, children = rule
    for key, value in element.attrib.items():
        key = _short(key)
        if key not in attributes:
            raise UnsupportedConstruct(f"{path}: <{tag}> has unknown attribute {key}")
        _check_value(tag, key, value, path)
    for key in _REQUIRED.get(tag, ()):
        if _get(element, key) is None:
            raise UnsupportedConstruct(f"{path}: <{tag}> without {key}")
    name = element.get("name")
    here = path if name is None or tag in ("type", "parameters") else _join(path, tag, name)
    kids: List[str] = []
    for child in element:
        kid = _walk(child, here, tag)
        if kid not in children:
            raise UnsupportedConstruct(f"{here}: <{tag}> has unexpected child <{kid}>")
        kids.append(kid)
    if kids.count("doc") > 1:
        raise UnsupportedConstruct(f"{here}: more than one <doc>")
    if tag == "parameters" and parent == "glib:signal" and "instance-parameter" in kids:
        raise UnsupportedConstruct(f"{here}: a signal with an instance parameter")
    if tag in ("parameter", "instance-parameter", "return-value", "property"):
        typed = [k for k in kids if k in ("type", "array")]
        if len(typed) != 1:
            raise UnsupportedConstruct(f"{here}: expected one type, found {len(typed)}")
    if tag == "array":
        if len(kids) != 1:
            raise UnsupportedConstruct(f"{here}: <array> must hold exactly one element type")
        if kids[0] == "array":
            raise UnsupportedConstruct(f"{here}: arrays of arrays")
    return tag


def _check_toplevel(item: ET.Element, path: str) -> None:
    """What only holds of the namespace's own callables, not of a class struct's fields."""
    tag = _short(item.tag)
    if tag in ("class", "interface"):
        for member in item:
            kind = _short(member.tag)
            if kind in ("constructor", "function", "method", "virtual-method"):
                _check_instance_parameter(member, kind, f"{path}.{member.get('name')}")
    elif tag in ("function", "callback"):
        _check_instance_parameter(item, tag, path)


def _check_instance_parameter(element: ET.Element, kind: str, path: str) -> None:
    params = [p for c in element if _short(c.tag) == "parameters" for p in c]
    tags = [_short(p.tag) for p in params]
    has_instance = "instance-parameter" in tags
    if has_instance and tags.index("instance-parameter") != 0 or tags.count("instance-parameter") > 1:
        raise UnsupportedConstruct(f"{path}: misplaced instance parameter")
    if kind in ("method", "virtual-method") and not has_instance:
        raise UnsupportedConstruct(f"{path}: {kind} without an instance parameter")
    if kind not in ("method", "virtual-method") and has_instance:
        raise UnsupportedConstruct(f"{path}: {kind} with an instance parameter")
    instance = params[0] if has_instance else None
    if instance is not None and instance.get("transfer-ownership", "none") != "none":
        # The core does not model the instance parameter; the wrappers lend `self`.
        raise UnsupportedConstruct(f"{path}: an instance parameter that is not transfer-ownership=none")


def _check_value(tag: str, key: str, value: str, path: str) -> None:
    if key in _FLAGS and value not in ("0", "1"):
        raise UnsupportedConstruct(f"{path}: <{tag}> {key}={value!r} is not 0 or 1")
    if key in _INTEGERS:
        try:
            int(value)
        except ValueError:
            raise UnsupportedConstruct(f"{path}: {key}={value!r} is not an integer") from None
    allowed = _VALUES.get(key)
    if allowed is not None and value not in allowed:
        raise UnsupportedConstruct(f"{path}: {key}={value!r}")


def _get(element: ET.Element, key: str) -> Optional[str]:
    if key.startswith("c:"):
        return element.get(f"{{{C}}}{key[2:]}")
    if key.startswith("glib:"):
        return element.get(f"{{{GLIB}}}{key[5:]}")
    return element.get(key)


def _join(path: str, tag: str, name: str) -> str:
    if tag == "namespace" or path == "repository":
        return name
    if tag == "property":
        return f"{path}:{name}"
    if tag == "glib:signal":
        return f"{path}::{name}"
    if tag in ("parameter", "instance-parameter"):
        return f"{path}({name})"
    return f"{path}.{name}"
