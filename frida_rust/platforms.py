#
# Copyright © 2026 Kirby Kuehl
#
# Licence: wxWindows Library Licence, Version 3.1
#
"""One model for two platforms' GIRs, each item marked with where it exists.

frida-core's GIR is the same on macOS, Linux and Android; the Windows one lacks a few
items. The loader builds a model from each, and `merge` folds the second into the first:
an item only one has gets that side's `cfg`, which the code generator writes as
`#[cfg(...)]`. Nothing here names an item; what differs is found by comparing.

An item both have must have the same shape in both, docs aside, or `merge` raises
`UnsupportedConstruct`: one Rust signature cannot describe it.
"""
from __future__ import annotations

import dataclasses
import xml.etree.ElementTree as ET
from collections import OrderedDict
from typing import Dict, List

from .model import Enumeration, Model, ObjectType, UnsupportedConstruct

# The lists of an object type that are merged item by item, not compared whole.
_OBJECT_LISTS = (
    "constructors", "every_method", "every_property", "signals", "virtual_methods", "uncovered",
)


def merge(primary: Model, other: Model, only_primary: str, only_other: str) -> Model:
    """`primary`, holding `other`'s items too, each marked with where it exists."""
    if _namespace(primary) != _namespace(other):
        raise UnsupportedConstruct("the two GIRs describe different namespaces")
    ns = primary.namespace.name
    sides = (only_primary, only_other)
    primary.frida_object_types = _merge_table(
        primary.frida_object_types, other.frida_object_types, _object_shape, _merge_object, sides, ns
    )
    primary.frida_enumerations = _merge_table(
        primary.frida_enumerations, other.frida_enumerations, _enumeration_shape, _merge_enumeration, sides, ns
    )
    for table in ("functions", "callbacks", "records"):
        setattr(primary, table, _merge_table(
            getattr(primary, table), getattr(other, table), _shape, None, sides, ns
        ))
    return primary


def _namespace(model: Model) -> tuple:
    element = model.namespace.element
    return tuple(sorted(element.attrib.items()))


def _merge_table(primary: Dict, other: Dict, shape, merge_children, sides, path: str) -> "OrderedDict":
    merged = _merge_list(list(primary.values()), list(other.values()), shape, merge_children, sides, path)
    return OrderedDict((item.name, item) for item in merged)


def _merge_list(primary: List, other: List, shape, merge_children, sides, path: str) -> List:
    only_primary, only_other = sides
    others = {_key(item): item for item in other}
    seen = set()
    result = []
    for item in primary:
        seen.add(_key(item))
        twin = others.get(_key(item))
        here = f"{path}.{item.name}"
        if twin is None:
            item.cfg = only_primary
        else:
            if shape(item) != shape(twin):
                raise UnsupportedConstruct(f"{here}: differs between platforms")
            if merge_children is not None:
                merge_children(item, twin, sides, here)
        result.append(item)
    for item in other:
        if _key(item) not in seen:
            item.cfg = only_other
            result.append(item)
    return result


def _key(item) -> str:
    """What matches an item with its twin: its name, and for a `supplements.Unreadable`,
    which can be of any member category, the category too."""
    category = getattr(item, "category", None)
    return item.name if category is None else f"{category} {item.name}"


def _merge_object(primary: ObjectType, other: ObjectType, sides, path: str) -> None:
    for name in _OBJECT_LISTS:
        setattr(primary, name, _merge_list(getattr(primary, name), getattr(other, name), _shape, None, sides, path))


def _merge_enumeration(primary: Enumeration, other: Enumeration, sides, path: str) -> None:
    primary.members = _merge_list(primary.members, other.members, _member_shape, None, sides, path)


def _object_shape(t: ObjectType) -> tuple:
    return (
        t.kind, t.name, t.c_type, t.get_type, t.parent_name, t.abstract, t.final,
        tuple(t.implements), tuple(t.prerequisites),
    )


def _enumeration_shape(e: Enumeration) -> tuple:
    return (e.name, e.c_type, e.get_type, e.error_domain)


def _member_shape(m) -> tuple:
    return (m.name, m.c_identifier, m.value)


# Fields that point back at an item's owner, which `_shape` leaves out.
_OWNERS = ("object_type", "model", "resolve_type", "enumeration")

_DOC = "{http://www.gtk.org/introspection/core/1.0}doc"


def _shape(item) -> object:
    """A member's shape, with its docs, platform and owner left out: the core's fields,
    and the element it was read from, in which the core's readers miss nothing."""
    if isinstance(item, ET.Element):
        return (
            item.tag,
            tuple(sorted(item.attrib.items())),
            tuple(_shape(c) for c in item if c.tag != _DOC),
        )
    if dataclasses.is_dataclass(item) and not isinstance(item, type):
        element = getattr(item, "element", None)
        return (
            type(item).__name__,
            tuple(
                (f.name, _shape(getattr(item, f.name)))
                for f in dataclasses.fields(item)
                if f.name not in ("doc", "cfg") + _OWNERS
            ),
            _shape(element) if isinstance(element, ET.Element) else None,
        )
    if isinstance(item, (list, tuple)):
        return tuple(_shape(i) for i in item)
    return item

