#
# Copyright © 2026 Kirby Kuehl
#
# Licence: wxWindows Library Licence, Version 3.1
#
"""What frida_bindgen_core leaves out of Frida's GIR, read here and counted.

The core models the part of Frida's API that frida-python, frida-node and frida-swift
wrap. frida-rust wraps all of it, so the few kinds of item the core leaves out are read
here, and nowhere else. Where the core has a reader for a piece of an item (its
parameters, a type, a return value), this calls it, and it makes each item through the
core's Factory, as the classes the core makes: the code generator reads them as it reads
the core's, and tells them apart only by `supplement`, which names the kind below.

Each kind is something a change to the core could take over, and the generator's report
counts the items of each.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Dict, List, Optional, Union

import frida_bindgen_core as core
from frida_bindgen_core import model as core_model  # its readers, called through the module

from .model import (
    GIR_ASYNC_CALLBACK,
    Member,
    Parameter,
    ReturnValue,
    attr,
    bind_parameters,
    child,
    flag,
    parameter_elements,
    read_return_value,
    tag,
)

if TYPE_CHECKING:
    from .model import Method, Model, ObjectType, Property

# Each kind of item read here, and why the core does not give it.
KINDS = OrderedDict([
    ("callback-method",
     "methods that take a callback: the core leaves out any method with a `closure` argument "
     "of 1, as the other bindings wrap none"),
    ("options-getter",
     "methods that return a Frida options object: the core leaves them out, as the other "
     "bindings take options but never hand them back"),
    ("options-property",
     "properties of a Frida options type, left out for the same reason"),
    ("function",
     "namespace functions: the core models only classes, interfaces and enumerations"),
    ("callback",
     "callback types, Frida's and GLib's, that the callback methods take: the core does not "
     "model them"),
    ("virtual-method",
     "virtual methods: the core does not model them; counted, and skipped"),
    ("record",
     "records: the core does not model them; Frida's are all class and interface structs, "
     "which the generator checks"),
    ("unreadable",
     "items the core's readers raise on, for a type from a namespace it is not given "
     "(Json, Efni): counted by name, and never generated"),
])


def _supplied(item, kind: str):
    item.supplement = kind
    return item


def position(elements: List[ET.Element], item) -> int:
    """Where `item`'s element is among `elements`, to keep GIR order."""
    return next(i for i, e in enumerate(elements) if e is item.element)


# ---------------------------------------------------------------------------
# options-property


def properties(obj: "ObjectType") -> List["Property"]:
    """The properties the core leaves out of `obj.properties`: those of a Frida options
    type. Each is made as the core's `ObjectType.properties` makes one."""
    covered = {p.name for p in obj.properties}
    out = []
    for element in obj._properties:
        name = attr(element, "name")
        if name in covered:
            continue
        type_ = _type(obj, element)
        if not type_.is_frida_options:
            # Not left out for this reason: the generator counts it as one no one reads.
            continue
        c_name = name.replace("-", "_")
        writable = attr(element, "writable") == "1"
        construct_only = attr(element, "construct-only") == "1"
        prop = obj.model.factory.property_(
            name, c_name, type_, writable, construct_only, f"get_{c_name}",
            f"set_{c_name}" if writable and not construct_only else None, obj,
        )
        out.append(_supplied(prop.bind(element), "options-property"))
    return out


def _type(obj: "ObjectType", element: ET.Element):
    return core_model.extract_type_from_entity(element, obj.resolve_type)


# ---------------------------------------------------------------------------
# callback-method, options-getter


def methods(obj: "ObjectType") -> List["Method"]:
    """The methods the core leaves out of `obj.methods` for taking a callback or returning
    a Frida options object, each made as the core's `ObjectType.methods` makes one, with
    the core's `extract_callable_details`. The `_sync` and `_finish` forms of an async one
    stand with it, as they do with the core's."""
    if obj.methods_error is not None:
        return []
    covered = {m.name for m in obj.methods}
    by_name = {attr(e, "name"): e for e in obj._methods}
    out = []
    for element in obj._methods:
        name = attr(element, "name")
        if name in covered or _is_form(name, by_name):
            continue
        kind = None
        if any(attr(p, "closure") is not None and _type_name(p) != GIR_ASYNC_CALLBACK
               for p in parameter_elements(element)):
            kind = "callback-method"
        else:
            rv = child(element, "return-value")
            type_ = None if rv is None else core_model.extract_type_from_entity(rv, obj.resolve_type)
            if type_ is not None and type_.is_frida_options:
                kind = "options-getter"
        if kind is not None:
            out.append(_supplied(_method(obj, element, by_name), kind))
    return out


def _type_name(element: ET.Element) -> Optional[str]:
    t = child(element, "type")
    return None if t is None else attr(t, "name")


def is_async_element(element: ET.Element) -> bool:
    return any(_type_name(p) == GIR_ASYNC_CALLBACK for p in parameter_elements(element))


def _is_form(name: str, by_name: Dict[str, ET.Element]) -> bool:
    """Whether `name` is the `_finish` or `_sync` form of an async method in `by_name`."""
    for suffix in ("_finish", "_sync"):
        if name.endswith(suffix):
            base = by_name.get(name[: -len(suffix)])
            if base is not None and is_async_element(base):
                return True
    return False


def _method(obj: "ObjectType", element: ET.Element, by_name: Dict[str, ET.Element]) -> "Method":
    name = attr(element, "name")
    finish = by_name.get(name + "_finish", element)
    c_identifier, finish_c_identifier, parameters, _, throws, result = core_model.extract_callable_details(
        element, finish, obj, obj.resolve_type
    )
    return_value = read_return_value(obj, child(result, "return-value"))
    tokens = name.split("_", 1)
    accessor = (
        len(tokens) == 2 and tokens[0] in ("get", "set") and tokens[1] in {p.c_name for p in obj.every_property}
    )
    method = obj.model.factory.method(
        name, c_identifier, finish_c_identifier, parameters, throws, return_value, accessor, obj
    )
    return method.bind(element)


# ---------------------------------------------------------------------------
# function, callback


@dataclass
class NamespaceScope:
    """The namespace, standing in for the object type the core's readers take: they ask it
    for its model's factory and its type resolver, and keep it on each parameter."""

    model: "Model"
    name: str
    resolve_type: Callable


def scope(model: "Model") -> NamespaceScope:
    return NamespaceScope(model, model.namespace.name, model.resolve_type)


@dataclass
class Function(Member, core.Procedure):
    """A namespace function, as the core's `Procedure`, with a return value."""

    return_value: Optional[ReturnValue] = None
    element: Optional[ET.Element] = None

    @property
    def blocking_c_identifier(self) -> str:
        return self.c_identifier


@dataclass
class Callback(Member):
    """A callback type: its arguments as the core reads a signal's, and its result."""

    name: str
    c_type: str
    parameters: List[Parameter]
    return_value: Optional[ReturnValue]
    throws: bool
    element: ET.Element


@dataclass
class Unreadable(Member):
    """An item the generator cannot have from the core's readers: `error` says why."""

    category: str
    name: str
    error: str
    element: ET.Element

    supplement = "unreadable"


class Uncovered(Unreadable):
    """A member element neither the core nor a kind here gives: the generator fails it."""

    supplement = None


# ---------------------------------------------------------------------------
# virtual-method, record


@dataclass
class VirtualMethod(Member):
    """A virtual method, by name: frida-rust counts them, and generates none yet."""

    name: str
    element: ET.Element


@dataclass
class Record(Member):
    """A record. Frida's are all the class and interface structs of its types."""

    name: str
    c_type: Optional[str]
    gtype_struct_for: Optional[str]
    element: ET.Element


def virtual_methods(obj: "ObjectType") -> List[VirtualMethod]:
    return [
        _supplied(VirtualMethod(attr(e, "name"), e), "virtual-method")
        for e in obj.element
        if tag(e) == "virtual-method"
    ]


def records(model: "Model") -> "OrderedDict[str, Record]":
    return OrderedDict(
        (attr(e, "name"), _supplied(Record(attr(e, "name"), attr(e, "c:type"), attr(e, "glib:is-gtype-struct-for"), e), "record"))
        for e in model.namespace.element
        if tag(e) == "record"
    )


def functions(model: "Model") -> "OrderedDict[str, Union[Function, Unreadable]]":
    """The namespace's functions, read with the core's `extract_callable_details`."""
    owner = scope(model)
    out: "OrderedDict[str, Union[Function, Unreadable]]" = OrderedDict()
    for element in model.namespace.element:
        if tag(element) != "function":
            continue
        name = attr(element, "name")
        try:
            c_identifier, _, parameters, _, throws, _ = core_model.extract_callable_details(
                element, element, owner, owner.resolve_type
            )
            return_value = read_return_value(owner, child(element, "return-value"))
        except AssertionError as exc:
            out[name] = Unreadable("function", name, f"frida_bindgen_core: {exc}", element)
            continue
        f = Function(name, c_identifier, None, parameters, throws, return_value, element)
        bind_parameters(element, f.parameters, name)
        if return_value is not None:
            return_value.element = child(element, "return-value")
        out[name] = _supplied(f, "function")
    return out


def callbacks(model: "Model") -> "OrderedDict[str, Callback]":
    """The namespace's callback types."""
    return OrderedDict(
        (attr(e, "name"), callback(model, f"{model.namespace.name}.{attr(e, 'name')}"))
        for e in model.namespace.element
        if tag(e) == "callback"
    )


def callback(model: "Model", name: str) -> Optional[Callback]:
    """The callback type `name`, Frida's or one of GLib's, Gio's and GObject's, which the
    core's resolver finds in their GIRs; None for a type that is no callback."""
    cache = model.__dict__.setdefault("_callbacks", {})
    if name in cache:
        return cache[name]
    owner = scope(model)
    try:
        qualified, element = owner.resolve_type(name)
    except AssertionError:
        return None
    result = None
    if tag(element) == "callback":
        parameters = core_model.extract_parameters(
            parameter_elements(element), nullable_implies_optional=False, object_type=owner,
            resolve_type=owner.resolve_type,
        )
        bind_parameters(element, parameters, qualified)
        rv_element = child(element, "return-value")
        return_value = read_return_value(owner, rv_element)
        if return_value is not None:
            return_value.element = rv_element
        result = _supplied(
            Callback(attr(element, "name"), attr(element, "c:type"), parameters, return_value,
                     flag(element, "throws"), element),
            "callback",
        )
    cache[name] = result
    return result


# ---------------------------------------------------------------------------
# unreadable: and anything no rule here or in the core covers


def uncovered(obj: "ObjectType") -> List[Unreadable]:
    """Each member element of `obj` that neither the core nor a kind above gives: those
    the core raised on, and any the generator would otherwise miss without a word."""
    out = []
    if obj.methods_error is not None:
        for e in obj._methods:
            out.append(Unreadable("method", attr(e, "name"), f"frida_bindgen_core: {obj.methods_error}", e))
    else:
        given = {m.name for m in obj.every_method}
        by_name = {attr(e, "name"): e for e in obj._methods}
        for e in obj._methods:
            name = attr(e, "name")
            if name not in given and not _is_form(name, by_name):
                out.append(Uncovered("method", name, "neither frida_bindgen_core nor frida_rust.supplements gives it", e))
    ctors = {c.element for c in obj.constructors}
    for e in obj._constructors + obj._functions:
        if e not in ctors:
            category = "function" if tag(e) == "function" else "constructor"
            out.append(Uncovered(category, attr(e, "name"), "a constructor or class function the core leaves out", e))
    props = {p.element for p in obj.every_property}
    for e in obj._properties:
        if e not in props:
            out.append(Uncovered("property", attr(e, "name"), "a property the core leaves out", e))
    signals = {s.element for s in obj.signals}
    for e in obj._signals:
        if e not in signals:
            out.append(Uncovered("signal", attr(e, "name"), "a signal the core leaves out", e))
    return out



# ---------------------------------------------------------------------------
# What was read here


def counts(model: "Model") -> "OrderedDict[str, int]":
    """How many items of each kind were read here: the generator's report shows them. A
    callback type counts once it has been looked up, as GLib's are only on demand."""
    out: "OrderedDict[str, int]" = OrderedDict((kind, 0) for kind in KINDS)
    for obj in model.frida_object_types.values():
        for item in obj.every_method + obj.every_property + obj.virtual_methods + obj.uncovered:
            if item.supplement is not None:
                out[item.supplement] += 1
    for f in model.functions.values():
        out[f.supplement] += 1
    out["record"] += len(model.records)
    seen = {id(cb) for cb in model.callbacks.values()}
    seen.update(id(cb) for cb in model.__dict__.get("_callbacks", {}).values() if cb is not None)
    out["callback"] += len(seen)
    return out
