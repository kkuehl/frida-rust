#
# Copyright © 2026 Kirby Kuehl
#
# Licence: wxWindows Library Licence, Version 3.1
#
"""The model the code generator reads: frida_bindgen_core's, with what Rust needs added.

The core parses Frida's GIR together with GLib's, GObject's and Gio's, and gives the
classes, interfaces and enumerations, their hierarchy and the error domain, and each
type's methods, constructors, properties and signals, with their parameters, return
values and types. The classes here subclass the core's and are registered with it
through `FACTORY`, as frida-swift's are, so the core makes every member as one of them,
and the code generator reads them as it made them.

The core does not hand a member its GIR element; `ObjectType` does, from the elements
the core keeps (`bind`). From the element, the subclasses read only what the core leaves
out of a member it gives, each saying what that is: docs, a constructor's return value,
an array's length argument, a callback's user data, destroy notify and scope, a
property's default, and what a signal's handlers return. Rust-specific views are added
on them too, as frida-swift adds its own: `Method.blocking_c_identifier`, the `_sync`
function an async method's wrapper calls, checked against the core's view.

What the core leaves out entirely (methods that take a callback, options getters and
properties, namespace functions, callbacks, virtual methods, records, and what its
readers raise on) is read in `supplements`, and only there. `every_method` and
`every_property` are the core's lists with those added, in GIR order.

`cfg` on an item is `None` when the item exists on every platform, or a Rust `cfg`
predicate (`not(windows)`) when it does not; `platforms.merge` sets it.

`strict.check` has refused anything in the GIR this does not know, so what is read here
trusts its shape.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import OrderedDict
from dataclasses import dataclass, field
from functools import cached_property
from typing import Dict, List, Optional

import frida_bindgen_core as core
from frida_bindgen_core.model import C_NAMESPACE, CORE_NAMESPACE, GLIB_NAMESPACE

# The type of the callback that makes a method async.
GIR_ASYNC_CALLBACK = "Gio.AsyncReadyCallback"


class UnsupportedConstruct(Exception):
    """The GIR holds something this generator does not know how to handle."""


@dataclass
class Customizations:
    """What the core reads of a binding's customizations: the types to drop.

    frida-rust drops none from the model. Its code generator applies the skip table in
    `customization.SKIPS` itself, so that it counts each item it skips."""

    type_customizations: Dict[str, object] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Reading the GIR's elements.

_CORE = f"{{{CORE_NAMESPACE}}}"
_C = f"{{{C_NAMESPACE}}}"
_GLIB = f"{{{GLIB_NAMESPACE}}}"


def tag(element: ET.Element) -> str:
    """The element's name as the GIR file spells it: `class`, `glib:signal`."""
    t = element.tag
    if t.startswith(_CORE):
        return t[len(_CORE):]
    if t.startswith(_GLIB):
        return "glib:" + t[len(_GLIB):]
    if t.startswith(_C):
        return "c:" + t[len(_C):]
    return t


def attr(element: ET.Element, name: str) -> Optional[str]:
    """An attribute by the name the GIR file gives it: `name`, `c:type`, `glib:get-type`."""
    if name.startswith("c:"):
        return element.get(_C + name[2:])
    if name.startswith("glib:"):
        return element.get(_GLIB + name[5:])
    return element.get(name)


def flag(element: ET.Element, name: str) -> bool:
    return attr(element, name) == "1"


def read_doc(element: ET.Element) -> Optional[str]:
    doc = next((c for c in element if tag(c) == "doc"), None)
    return None if doc is None else (doc.text or "")


# ---------------------------------------------------------------------------
# Members: the core's, and what the core leaves out of them.
#
# The core makes each method, constructor, property, signal, parameter and return value
# through FACTORY, as one of the classes below, and the code generator reads them as the
# core made them. The core does not hand these objects their GIR element, so `ObjectType`
# below does (`bind`), from the elements the core keeps. Each property read from the
# element is something the core leaves out, and says so.


def child(element: ET.Element, name: str) -> Optional[ET.Element]:
    """The first child of `element` the GIR names `name`, or None."""
    return next((c for c in element if tag(c) == name), None)


def parameter_elements(callable_element: ET.Element) -> List[ET.Element]:
    """The `<parameter>`s of a callable, without its instance parameter, in order: what
    the GIR's indices (`length`, `closure`, `destroy`) count."""
    holder = child(callable_element, "parameters")
    return [] if holder is None else [p for p in holder if tag(p) == "parameter"]


def _unbound(item: object) -> UnsupportedConstruct:
    return UnsupportedConstruct(f"{type(item).__name__} {getattr(item, 'name', '')}: used before `bind`")


class Parameter(core.Parameter):
    """The core's parameter. It leaves out the docs, and how arguments relate: an array's
    length argument, a callback's user data and destroy notify, and the callback's scope.
    `bind_parameters` links those, as the parameters they name."""

    element: Optional[ET.Element] = None
    length: Optional["Parameter"] = None
    closure: Optional["Parameter"] = None
    destroy: Optional["Parameter"] = None

    def _element(self) -> ET.Element:
        if self.element is None:
            raise _unbound(self)
        return self.element

    @cached_property
    def doc(self) -> Optional[str]:
        """The core leaves out a parameter's docs."""
        return read_doc(self._element())

    @cached_property
    def scope(self) -> Optional[str]:
        """The core leaves out a callback's scope (`call`, `notified`, `async`)."""
        return attr(self._element(), "scope")

    @property
    def is_input(self) -> bool:
        return self.direction == core.Direction.IN

    @property
    def transfer(self) -> str:
        return self.transfer_ownership.name


class ReturnValue(core.ReturnValue):
    """The core's return value. It leaves out the docs, and the out argument that holds an
    array's length (its `Method.out_parameters` knows only to leave that out of a string
    vector's outputs)."""

    element: Optional[ET.Element] = None
    length: Optional[Parameter] = None

    @cached_property
    def doc(self) -> Optional[str]:
        """The core leaves out what the docs say a callable returns."""
        if self.element is None:
            raise _unbound(self)
        return read_doc(self.element)

    @property
    def transfer(self) -> str:
        return self.transfer_ownership.name


def bind_parameters(element: ET.Element, parameters: List[Parameter], where: str) -> None:
    """Hands each of the core's `parameters` its `<parameter>` in `element`, and links each
    to the arguments its GIR indices name. An index may name an argument the core leaves
    out of `parameters` only from an argument it leaves out too (the async callback and its
    user data)."""
    elements = parameter_elements(element)
    by_name = {attr(e, "name"): e for e in elements}
    kept = {p.name: p for p in parameters}
    for p in parameters:
        p.element = by_name.get(p.name)
        if p.element is None:
            raise UnsupportedConstruct(f"{where}: the core's parameter {p.name} is not in the GIR")

    def at(index: Optional[str], what: str, p: Parameter) -> Optional[Parameter]:
        if index is None:
            return None
        i = int(index)
        if not 0 <= i < len(elements):
            raise UnsupportedConstruct(f"{where}: {p.name}'s {what} index {i} is out of range")
        target = kept.get(attr(elements[i], "name"))
        if target is None:
            raise UnsupportedConstruct(f"{where}: {p.name}'s {what} is an argument the core leaves out")
        return target

    for p in parameters:
        array = child(p.element, "array")
        if array is not None:
            p.length = at(attr(array, "length"), "length", p)
        p.closure = at(attr(p.element, "closure"), "closure", p)
        p.destroy = at(attr(p.element, "destroy"), "destroy", p)


def bind_return_value(
    rv: Optional[ReturnValue], result_element: ET.Element, parameters: List[Parameter], where: str
) -> None:
    """Hands `rv` its `<return-value>` in `result_element`, and links an array's length to
    the out argument of `parameters` that holds it."""
    if rv is None:
        return
    rv.element = child(result_element, "return-value")
    array = child(rv.element, "array")
    index = None if array is None else attr(array, "length")
    if index is None:
        return
    elements = parameter_elements(result_element)
    i = int(index)
    if not 0 <= i < len(elements):
        raise UnsupportedConstruct(f"{where}: the return value's length index {i} is out of range")
    name = attr(elements[i], "name")
    rv.length = next((p for p in parameters if p.name == name), None)
    if rv.length is None:
        raise UnsupportedConstruct(f"{where}: the return value's length is an argument the core leaves out")


def read_return_value(owner, element: Optional[ET.Element]) -> Optional[ReturnValue]:
    """A return value read with the core's type reader and made through its Factory, as
    its `ObjectType.methods` makes one. `owner` is the object type it belongs to."""
    if element is None:
        return None
    type_ = core.model.extract_type_from_entity(element, owner.resolve_type)
    if type_ is None:
        return None
    ownership = attr(element, "transfer-ownership")
    return owner.model.factory.return_value(
        type_,
        flag(element, "nullable"),
        core.TransferOwnership[ownership] if ownership is not None else core.TransferOwnership.none,
        owner,
    )


class Member:
    """What the code generator asks of every member, beside the core's fields."""

    cfg: Optional[str] = None
    # The kind of `supplements` that made it, or None for one the core made.
    supplement: Optional[str] = None
    element: ET.Element

    @cached_property
    def doc(self) -> Optional[str]:
        """The core leaves out the docs."""
        return read_doc(self.element)


class Method(Member, core.Method):
    """The core's method: a plain one, or an async one (`is_async`), which stands for its
    `_finish` and `_sync` forms too. frida-rust calls the blocking `_sync` form: see
    `blocking_c_identifier`."""

    def bind(self, element: ET.Element) -> "Method":
        self.element = element
        where = f"{self.object_type.name}.{self.name}"
        bind_parameters(element, self.parameters, where)
        bind_return_value(self.return_value, self.result_element, self.parameters, where)
        return self

    def _sibling(self, name: str) -> Optional[ET.Element]:
        return next((e for e in self.object_type._methods if attr(e, "name") == name), None)

    @cached_property
    def result_element(self) -> ET.Element:
        """The element the core reads the result from: the `_finish` form of an async method."""
        if not self.is_async:
            return self.element
        return self._sibling(self.name + "_finish")

    @cached_property
    def sync_element(self) -> Optional[ET.Element]:
        """The `_sync` form of an async method, which the core leaves out, or None."""
        return self._sibling(self.name + "_sync") if self.is_async else None

    @cached_property
    def blocking_c_identifier(self) -> str:
        """The C function the Rust wrapper calls: the method's own, or for an async method
        its `_sync` form, `<c_identifier>_sync`. That form must be in the GIR, and must take
        what the core says the method takes and give what it gives (`sync_disagreements`)."""
        if not self.is_async:
            return self.c_identifier
        if self.sync_element is None:
            raise UnsupportedConstruct(f"an async method with no `{self.name}_sync` form to call")
        problems = self.sync_disagreements()
        if problems:
            raise UnsupportedConstruct(f"its `{self.name}_sync` form disagrees with the core's view: {'; '.join(problems)}")
        return self.c_identifier + "_sync"

    def sync_disagreements(self) -> List[str]:
        """How the `_sync` form differs from the core's view of the async method: its
        arguments, read with the core's reader, its result and its `throws`."""
        sync = self.sync_element
        owner = self.object_type
        out = []
        expected = self.c_identifier + "_sync"
        if attr(sync, "c:identifier") != expected:
            out.append(f"it is {attr(sync, 'c:identifier')}, not {expected}")
        theirs = core.model.extract_parameters(
            parameter_elements(sync), nullable_implies_optional=True, object_type=owner, resolve_type=owner.resolve_type
        )

        def shape(p: core.Parameter) -> tuple:
            return (p.name, p.type, p.nullable, p.direction, p.transfer_ownership)

        if [shape(p) for p in theirs] != [shape(p) for p in self.parameters]:
            out.append(
                f"it takes ({', '.join(p.name for p in theirs)}), the core's method "
                f"({', '.join(p.name for p in self.parameters)}) or of other types"
            )
        rv = read_return_value(owner, child(sync, "return-value"))
        mine = self.return_value

        def result(r: Optional[core.ReturnValue]) -> Optional[tuple]:
            return None if r is None else (r.type, r.nullable, r.transfer_ownership)

        if result(rv) != result(mine):
            out.append("it returns another type, nullability or ownership")
        if flag(sync, "throws") != self.throws:
            out.append("it throws where the core's does not, or the other way round")
        return out


class Constructor(Member, core.Constructor):
    """The core's constructor: a `<constructor>`, or a class `<function>` that returns the
    class (`is_function`)."""

    def bind(self, element: ET.Element) -> "Constructor":
        self.element = element
        where = f"{self.object_type.name}.{self.name}"
        bind_parameters(element, self.parameters, where)
        bind_return_value(self.return_value, element, self.parameters, where)
        return self

    @property
    def is_function(self) -> bool:
        return tag(self.element) == "function"

    @cached_property
    def return_value(self) -> Optional[ReturnValue]:
        """The core gives a constructor no return value: its ownership and nullability."""
        return read_return_value(self.object_type, child(self.element, "return-value"))

    @property
    def blocking_c_identifier(self) -> str:
        return self.c_identifier


class Property(Member, core.Property):
    """The core's property. It leaves out the docs and the default value."""

    def bind(self, element: ET.Element) -> "Property":
        self.element = element
        return self

    @cached_property
    def default_value(self) -> Optional[str]:
        """The core leaves out a property's default value."""
        return attr(self.element, "default-value")


class Signal(Member, core.Signal):
    """The core's signal. It leaves out the docs, and what a handler returns."""

    def bind(self, element: ET.Element) -> "Signal":
        self.element = element
        bind_parameters(element, self.parameters, f"{self.object_type.name}::{self.name}")
        return self

    @cached_property
    def return_type(self) -> Optional[core.Type]:
        """The core leaves out what a signal's handlers return."""
        rv = child(self.element, "return-value")
        return None if rv is None else core.model.extract_type_from_entity(rv, self.object_type.resolve_type)


# ---------------------------------------------------------------------------
# The core's classes, extended.


class Model(core.Model):
    """The model of Frida's namespace, with GLib, GObject and Gio behind it."""

    def _children(self, kind: str) -> List[ET.Element]:
        return [e for e in self.namespace.element if tag(e) == kind]

    @cached_property
    def frida_object_types(self) -> "OrderedDict[str, ObjectType]":
        """Frida's own classes and interfaces, in the order the GIR declares them.

        The core's `object_types` also holds GObject's `Object`, and lists the
        interfaces after the classes."""
        return OrderedDict(
            (attr(e, "name"), self._object_types[attr(e, "name")])
            for e in self.namespace.element
            if tag(e) in ("class", "interface")
        )

    @cached_property
    def frida_enumerations(self) -> "OrderedDict[str, Enumeration]":
        """Every enumeration, the error domain included, in the order the GIR declares
        them. The core keeps the error domain apart, in `error_domain`."""
        result = OrderedDict()
        for e in self._children("enumeration"):
            name = attr(e, "name")
            enum = self.enumerations.get(name)
            if enum is None and self.error_domain is not None and self.error_domain.name == name:
                enum = self.error_domain
            if enum is None:
                raise UnsupportedConstruct(f"{self.namespace.name}.{name}: a second error domain")
            result[name] = enum
        return result

    @cached_property
    def resolve_type(self):
        """The core's resolver of a type name, in this namespace and those it was given.
        The core hands it only to object types; all of a namespace's share it."""
        first = next(iter(self.frida_object_types.values()), None)
        if first is None:
            raise UnsupportedConstruct(f"{self.namespace.name}: no class or interface to resolve types with")
        return first.resolve_type

    @cached_property
    def functions(self):
        """The namespace's functions, which the core does not model (`supplements`)."""
        from . import supplements

        return supplements.functions(self)

    @cached_property
    def records(self):
        """The namespace's records, which the core does not model (`supplements`)."""
        from . import supplements

        return supplements.records(self)

    # --- lookups by GIR name --------------------------------------------

    def qualify(self, name: str) -> str:
        return name if "." in name else f"{self.namespace.name}.{name}"

    def local(self, name: str) -> Optional[str]:
        """The bare name of a type in this namespace, or None if it is foreign."""
        prefix = self.namespace.name + "."
        if name.startswith(prefix):
            return name[len(prefix):]
        if "." not in name:
            return name
        return None

    def object(self, name: str) -> Optional["ObjectType"]:
        local = self.local(name)
        return self.frida_object_types.get(local) if local is not None else None

    def enumeration(self, name: str) -> Optional["Enumeration"]:
        local = self.local(name)
        return self.frida_enumerations.get(local) if local is not None else None

    @cached_property
    def callbacks(self):
        """The namespace's callback types, which the core does not model (`supplements`)."""
        from . import supplements

        return supplements.callbacks(self)

    def callback(self, name: str):
        """The callback type `name`, Frida's or a dependency's, or None (`supplements`)."""
        from . import supplements

        local = self.local(self.qualify(name))
        if local is not None:
            return self.callbacks.get(local)
        return supplements.callback(self, name)


class ObjectType(core.ObjectType):
    kind = ""
    cfg: Optional[str] = None

    @cached_property
    def element(self) -> ET.Element:
        return self.resolve_type(self.name)[1]

    @property
    def parent_name(self) -> Optional[str]:
        """The parent class's qualified GIR name, or None."""
        return None

    @cached_property
    def abstract(self) -> bool:
        return flag(self.element, "abstract")

    @cached_property
    def final(self) -> bool:
        return flag(self.element, "final")

    @cached_property
    def implements(self) -> List[str]:
        return [attr(e, "name") for e in self.element if tag(e) == "implements"]

    @cached_property
    def prerequisites(self) -> List[str]:
        """Every prerequisite. The core takes the first as an interface's parent."""
        return [attr(e, "name") for e in self.element if tag(e) == "prerequisite"]

    @cached_property
    def doc(self) -> Optional[str]:
        return read_doc(self.element)

    # --- the core's members, each bound to its element -------------------

    _methods_error: Optional[str] = None

    @property
    def methods_error(self) -> Optional[str]:
        """Why the core could not read this type's methods, or None. It raises on a type
        from a namespace it was not given (RpcClient's `Json.Node`)."""
        self.methods
        return self._methods_error

    def _core_members(self, attribute: str):
        """The core's `attribute` list. Should binding them fail, the core's own cached
        list, which is unbound, is dropped with it."""
        try:
            return getattr(super(), attribute)
        except BaseException:
            self.__dict__.pop(attribute, None)
            raise

    def _bind(self, attribute: str, items: list, elements: List[ET.Element]) -> list:
        by_name = {}
        for e in elements:
            by_name.setdefault(attr(e, "name"), e)
        try:
            for item in items:
                element = by_name.get(item.name)
                if element is None:
                    raise UnsupportedConstruct(f"{self.name}: the core's {item.name} is not in the GIR")
                item.bind(element)
        except BaseException:
            self.__dict__.pop(attribute, None)
            raise
        return items

    @cached_property
    def methods(self) -> List["Method"]:
        """The core's methods: the plain ones and the async ones, without their `_finish`
        and `_sync` forms, methods that take a callback, and options getters."""
        try:
            items = self._core_members("methods")
        except AssertionError as exc:
            self._methods_error = str(exc)
            return []
        return self._bind("methods", items, self._methods)

    @cached_property
    def constructors(self) -> List["Constructor"]:
        """The core's constructors: each `<constructor>`, and each class `<function>` that
        returns the class."""
        return self._bind("constructors", self._core_members("constructors"), self._constructors + self._functions)

    @cached_property
    def properties(self) -> List["Property"]:
        """The core's properties, without those of an options type."""
        return self._bind("properties", self._core_members("properties"), self._properties)

    @cached_property
    def signals(self) -> List["Signal"]:
        return self._bind("signals", self._core_members("signals"), self._signals)

    # --- with what the core leaves out (supplements.py) -------------------

    @cached_property
    def every_property(self) -> List["Property"]:
        """The core's properties, with those `supplements` reads, in GIR order: every
        property the generator considers."""
        from . import supplements

        items = self.properties + supplements.properties(self)
        return sorted(items, key=lambda p: supplements.position(self._properties, p))

    @cached_property
    def every_method(self) -> List["Method"]:
        """The core's methods, with those `supplements` reads, in GIR order: every method
        the generator considers. An async one stands for its `_finish` and `_sync` forms."""
        from . import supplements

        items = self.methods + supplements.methods(self)
        return sorted(items, key=lambda m: supplements.position(self._methods, m))

    def method(self, name: str) -> Optional["Method"]:
        """The method `name` of `every_method`, or None."""
        return next((m for m in self.every_method if m.name == name), None)

    @cached_property
    def uncovered(self) -> list:
        """Each member element that neither the core nor `supplements` gives, as a
        `supplements.Unreadable`: the generator fails on each."""
        from . import supplements

        return supplements.uncovered(self)

    @cached_property
    def virtual_methods(self) -> list:
        """The virtual methods, which the core does not model (`supplements`)."""
        from . import supplements

        return supplements.virtual_methods(self)


class ClassObjectType(ObjectType, core.ClassObjectType):
    kind = "class"

    @property
    def parent_name(self) -> Optional[str]:
        return self._parent


class InterfaceObjectType(ObjectType, core.InterfaceObjectType):
    kind = "interface"


class Enumeration(core.Enumeration):
    cfg: Optional[str] = None

    @cached_property
    def element(self) -> ET.Element:
        return self.model.namespace.type_elements[self.name]

    @cached_property
    def error_domain(self) -> Optional[str]:
        return attr(self.element, "glib:error-domain")

    @cached_property
    def doc(self) -> Optional[str]:
        return read_doc(self.element)


class EnumerationMember(core.EnumerationMember):
    cfg: Optional[str] = None

    @cached_property
    def element(self) -> ET.Element:
        return next(e for e in self.enumeration._members if attr(e, "name") == self.name)

    @cached_property
    def value(self) -> int:
        return int(attr(self.element, "value"))

    @cached_property
    def doc(self) -> Optional[str]:
        return read_doc(self.element)


def _object_type(cls):
    def make(**kw) -> ObjectType:
        return cls(
            kw["name"], kw["c_type"], kw["get_type"], kw["type_struct"], kw["parent"],
            kw["constructors"], kw["functions"], kw["methods"], kw["properties"], kw["signals"],
            kw["resolve_type"], kw["model"],
        )

    return make


FACTORY = core.Factory(
    class_object_type=_object_type(ClassObjectType),
    interface_object_type=_object_type(InterfaceObjectType),
    constructor=Constructor,
    method=Method,
    parameter=Parameter,
    return_value=ReturnValue,
    signal=Signal,
    property_=Property,
    enumeration=Enumeration,
    enumeration_member=EnumerationMember,
    model=Model,
)
