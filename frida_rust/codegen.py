#
# Copyright © 2026 Kirby Kuehl
#
# Licence: wxWindows Library Licence, Version 3.1
#
"""The Rust code generator.

It reads a merged `Model` and returns the generated files' text. Every
item it sees is recorded in a `Report`: generated, skipped with a reason, or
failed. An item fails when the generator has no rule for it; the command line
turns any failure into a non-zero exit.

Each class becomes one of three things:

- a *handle*: a reference to a frida-core object, `Send` and `Sync` (see
  `frida/src/gir/runtime.rs`), whose methods call frida-core;
- a *value*: the option and configuration classes, whose state the caller
  writes, as plain Rust structs (and enums, for an abstract class) built into a
  fresh frida-core object for each call that takes one;
- a *list* (`DeviceList` and friends), which is not public: what returns one
  returns a `Vec`.

Ownership follows the GIR exactly:

- `transfer-ownership="full"` on a return value: the wrapper takes the
  reference (objects) or frees the value after copying it (strings, arrays,
  bytes, variants, hash tables).
- `transfer-ownership="none"`: the wrapper takes its own reference (objects)
  or copies (everything else), and frees nothing.
- `transfer-ownership="container"` anywhere, and `full` on an argument other
  than a scalar `out`, are refused: no frida-core call uses them today, and
  guessing would mean a double free or a leak.

Nothing generated panics. A conversion that can fail (a string with a NUL
byte, a value too large for C) and a NULL frida-core returns where its
declaration promises a value make the call return an error.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import frida_bindgen_core as core

from . import customization as custom
from . import supplements
from .docs import one_line, to_rustdoc
from .model import (
    GIR_ASYNC_CALLBACK,
    Enumeration,
    Method,
    Model,
    ObjectType,
    Parameter,
    Property,
    Signal,
    UnsupportedConstruct,
    attr,
    parameter_elements,
)
from .naming import RUST_KEYWORDS, ident, pascal, snake

M = "crate::gir::marshal"
GIR = "crate::gir"
ERR = "crate::gir::Error"

# GIR scalar -> Rust type, which is also the type frida-sys gives it on every
# platform (gsize and gssize are 64-bit wherever frida-core runs).
SCALARS = {
    "gint": "i32",
    "guint": "u32",
    "gint8": "i8",
    "guint8": "u8",
    "gint16": "i16",
    "guint16": "u16",
    "gint32": "i32",
    "guint32": "u32",
    "gint64": "i64",
    "guint64": "u64",
    "gsize": "u64",
    "gssize": "i64",
    "gfloat": "f32",
    "gdouble": "f64",
}


class Unsupported(UnsupportedConstruct):
    pass


# ---------------------------------------------------------------------------
# The report.

CATEGORIES = [
    ("class", "classes"),
    ("interface", "interfaces"),
    ("enumeration", "enumerations"),
    ("constructor", "constructors"),
    ("function", "functions"),
    ("method", "methods"),
    ("property", "properties"),
    ("signal", "signals"),
    ("virtual-method", "virtual methods"),
]


@dataclass
class Entry:
    category: str
    path: str
    status: str  # "generated", "skipped", "failed"
    reason: str = ""
    # What a generated entry was generated from: an object of the core's classes, made by
    # the core or by `supplements`.
    item: object = field(default=None, repr=False, compare=False)


@dataclass
class Report:
    entries: List[Entry] = field(default_factory=list)
    stale_skips: List[str] = field(default_factory=list)
    # Each kind of `supplements` item: (kind, why the core leaves it out, read).
    supplements: List[Tuple[str, str, int]] = field(default_factory=list)

    def add(self, category: str, path: str, status: str, reason: str = "", item: object = None) -> None:
        self.entries.append(Entry(category, path, status, reason, item))

    @property
    def failures(self) -> List[Entry]:
        return [e for e in self.entries if e.status == "failed"]

    def count(self, category: str, status: Optional[str] = None) -> int:
        return sum(1 for e in self.entries if e.category == category and (status is None or e.status == status))

    def render(self) -> str:
        lines = ["", "frida_rust: what frida-core.gir holds, and what was made of it", ""]
        lines.append(f"  {'':18}{'seen':>6}{'generated':>11}{'skipped':>9}{'failed':>8}")
        for key, label in CATEGORIES:
            lines.append(
                f"  {label:18}{self.count(key):6}{self.count(key, 'generated'):11}"
                f"{self.count(key, 'skipped'):9}{self.count(key, 'failed'):8}"
            )
        if self.supplements:
            lines.append("")
            lines.append("What frida_bindgen_core leaves out, read by frida_rust.supplements:")
            lines.append(f"  {'':18}{'read':>6}{'generated':>11}")
            for kind, why, read in self.supplements:
                generated = sum(
                    1 for e in self.entries
                    if e.status == "generated" and getattr(e.item, "supplement", None) == kind
                )
                lines.append(f"  {kind:18}{read:6}{generated:11}  {why}")
        skipped = [e for e in self.entries if e.status == "skipped"]
        if skipped:
            lines.append("")
            lines.append(f"Skipped ({len(skipped)}):")
            by_reason: Dict[str, List[Entry]] = OrderedDict()
            for e in skipped:
                by_reason.setdefault(e.reason, []).append(e)
            for reason, entries in by_reason.items():
                lines.append(f"  {reason} ({len(entries)}):")
                for e in entries:
                    lines.append(f"    {e.category} {e.path}")
        if self.failures:
            lines.append("")
            lines.append(f"FAILED ({len(self.failures)}), neither generated nor in the skip table:")
            for e in self.failures:
                lines.append(f"  {e.category} {e.path}: {e.reason}")
        for path in self.stale_skips:
            lines.append(f"FAILED: table entry {path} matches nothing it could apply to")
        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Small helpers.

def cfg_join(*cfgs: Optional[str]) -> Optional[str]:
    unique = []
    for c in cfgs:
        if c is not None and c not in unique:
            unique.append(c)
    if not unique:
        return None
    if len(unique) == 1:
        return unique[0]
    return "all(" + ", ".join(unique) + ")"


def cfg_attr(cfg: Optional[str]) -> str:
    return f"#[cfg({cfg})]\n" if cfg else ""


def doc_comment(lines: List[str]) -> str:
    return "".join(f"///{(' ' + l) if l else ''}\n" for l in lines)


def c_pointer_type(c_type: str) -> str:
    """A C type from the GIR as the Rust type bindgen gave it."""
    c = c_type.strip()
    const = c.startswith("const ")
    if const:
        c = c[len("const "):].strip()
    stars = c.count("*")
    base = c.replace("*", "").strip()
    rust = f"frida_sys::{base}"
    for i in range(stars):
        rust = ("*const " if const and i == stars - 1 else "*mut ") + rust
    return rust


def index_of(params: List[Parameter], p: Parameter) -> int:
    """Where `p` is among `params`, by identity: the core's objects compare by value."""
    return next(i for i, q in enumerate(params) if q is p)


def words(name: str) -> List[str]:
    return [w for w in snake(name).split("_") if w]


def variant_name(parent: str, child: str) -> str:
    """`BarebonePhysicalAllocatorConfig` under `BareboneAllocatorConfig` as `Physical`:
    the child's words that are not the parent's, in order."""
    pw = words(parent)
    out = []
    i = 0
    for w in words(child):
        if i < len(pw) and w == pw[i]:
            i += 1
            continue
        while i < len(pw) and pw[i] != w and w not in pw[i:]:
            i += 1
        if i < len(pw) and w == pw[i]:
            i += 1
            continue
        out.append(w)
    return pascal("_".join(out)) if out else pascal(snake(child))


RETURN_SAFETY = (
    "// SAFETY: what the call returned, of the type and with the ownership its GIR\n"
    "// declaration gives.\n"
)


def hoist(conv: str, var: str) -> Tuple[str, str]:
    """`conv` with its `unsafe { .. }` block moved into a statement binding `var`, so that
    the block has its SAFETY comment: (the statement, or "", and what is left)."""
    start = conv.find("unsafe {")
    if start < 0:
        return "", conv
    depth = 0
    i = start + len("unsafe ")
    while i < len(conv):
        if conv[i] == "{":
            depth += 1
        elif conv[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    block = conv[start:i + 1]
    return f"{RETURN_SAFETY}let {var} = {block};\n", conv[:start] + var + conv[i + 1:]


@dataclass
class Kind:
    """How one GIR type crosses the boundary."""

    tag: str
    rust: str = ""  # the Rust type of an owned value
    c: str = ""  # the frida-sys C type, for objects and enums
    gir: str = ""  # the GIR name, for objects, values, lists and enums
    elem: Optional["Kind"] = None  # for lists


@dataclass
class ParamPlan:
    """How one Rust argument turns into C arguments."""

    decl: Optional[str] = None
    name: Optional[str] = None
    generics: List[str] = field(default_factory=list)
    pre: List[str] = field(default_factory=list)
    post: List[str] = field(default_factory=list)
    items: List[str] = field(default_factory=list)
    doc: Optional[str] = None
    fallible: bool = False


@dataclass
class ReturnPlan:
    rust_type: str
    convert: Optional[str]  # expression over `raw_ret`, or None when there is nothing
    fallible: bool = False  # `convert` is a Result
    discard: Optional[str] = None  # what to do with `raw_ret` when an error is set


@dataclass
class Generated:
    """A generated callable, for owners' explicit releases."""

    rust_name: str
    decls: List[str]
    names: List[str]
    rust_ret: str
    doc: str


# ---------------------------------------------------------------------------


class Generator:
    def __init__(self, model: Model, version: str, source: str = "frida-core.gir"):
        self.model = model
        self.version = version
        self.source = source
        self.report = Report()
        self.skips_used: Set[str] = set()
        self.method_names: Dict[Tuple[Optional[str], str], str] = {}
        self.ctor_names: Dict[Tuple[str, str], str] = {}
        self.stale_tables: List[str] = []
        self.used_keys: Set[str] = set()
        self.generated_callables: Dict[str, Generated] = {}
        self.acquired_seen: Set[str] = set()

    # --- names ---------------------------------------------------------

    def path(self, *parts: str) -> str:
        return ".".join((self.model.namespace.name,) + parts)

    def rust_type_name(self, gir_name: str) -> str:
        q = self.model.qualify(gir_name)
        if q in custom.TYPE_RENAMES:
            return custom.TYPE_RENAMES[q]
        if q in custom.FOREIGN_OBJECTS:
            return custom.FOREIGN_OBJECTS[q][0]
        return self.model.local(q) or q.split(".")[-1]

    def object_info(self, name: str) -> Optional[Tuple[str, str, Optional[str]]]:
        """(Rust type, C struct type, cfg) of an object type, or None."""
        q = self.model.qualify(name)
        if q in custom.FOREIGN_OBJECTS:
            rust, c = custom.FOREIGN_OBJECTS[q]
            return (f"{GIR}::{rust}", c, None)
        obj = self.model.object(q)
        if obj is not None:
            return (f"{GIR}::{self.rust_type_name(q)}", obj.c_type, obj.cfg)
        return None

    def enum_info(self, name: str) -> Optional[Tuple[str, str]]:
        """(Rust path, C type) of an enumeration, ours or a foreign one."""
        q = self.model.qualify(name)
        if q in custom.FOREIGN_ENUMS:
            rust, c = custom.FOREIGN_ENUMS[q]
            return (f"{GIR}::{rust}", c)
        e = self.model.enumeration(q)
        if e is None or e.error_domain is not None:
            return None
        return (f"{GIR}::{self.rust_type_name(q)}", e.c_type)

    def boundary(self, key: str) -> Optional[str]:
        kind = custom.BOUNDARY_TYPES.get(key)
        if kind is not None:
            self.used_keys.add(key)
        return kind

    # --- docs ----------------------------------------------------------

    def resolve_link(self, kind: str, target: str) -> str:
        ns = self.model.namespace.name + "."
        bare = target[len(ns):] if target.startswith(ns) else target
        if kind in ("class", "iface", "enum", "error", "struct"):
            q = self.model.qualify(bare)
            if (self.model.object(q) is not None and q not in self.lists and q not in self.skipped_classes) or (
                self.model.enumeration(q) is not None
            ):
                name = self.rust_type_name(q)
                return f"[`{name}`]({GIR}::{name})"
            return f"`{bare}`"
        if kind in ("method", "ctor"):
            if "." in bare:
                owner, member = bare.split(".", 1)
                table = self.method_names if kind == "method" else self.ctor_names
                rust = table.get((owner, member))
                if rust is not None and self.path(owner) not in self.values:
                    tname = self.rust_type_name(owner)
                    return f"[`{tname}::{rust}`]({GIR}::{tname}::{rust})"
            return f"`{bare}`"
        if kind == "func":
            if bare in self.model.functions and (None, bare) in self.method_names:
                return f"[`{bare}`]({GIR}::{bare})"
            return f"`{bare}`"
        return f"`{bare}`"

    def doc_lines(self, text: Optional[str]) -> List[str]:
        return to_rustdoc(text, self.resolve_link)

    def callable_doc(self, c, plans: List[ParamPlan], fallback: str, extra_doc: Optional[str] = None) -> List[str]:
        """Docs of a callable: its own (or `extra_doc`), its arguments, what it returns."""
        text = c.doc if c.doc else extra_doc
        lines = self.doc_lines(text)
        if not lines and fallback:
            lines = [fallback]
        args = [(p.name, p.doc) for p in plans if p.decl is not None and p.doc]
        if args:
            lines += ["", "# Arguments", ""]
            lines += [f"- `{name}`: {one_line(d, self.resolve_link)}" for name, d in args]
        rv = c.return_value.doc if c.return_value is not None else None
        if rv:
            lines += ["", "Returns " + one_line(rv, self.resolve_link)]
        lines += (["", ""] if lines else [""])[:-1] + [f"Calls `{c.blocking_c_identifier}`."]
        return lines

    # --- the entry point -------------------------------------------------

    def generate(self) -> "OrderedDict[str, str]":
        files: "OrderedDict[str, str]" = OrderedDict()
        self.plan_classes()
        self.plan_names()
        modules: List[Tuple[str, Optional[str]]] = []

        files["enums.rs"] = self.gen_enums()
        modules.append(("enums", None))

        for obj in self.model.frida_object_types.values():
            path = self.path(obj.name)
            if path in self.skipped_classes:
                self.skip_class(obj)
                continue
            try:
                files[snake(obj.name) + ".rs"] = self.gen_class(obj)
            except Unsupported as exc:
                self.fail(obj.kind, path, str(exc))
                continue
            self.report.add(obj.kind, path, "generated")
            modules.append((snake(obj.name), obj.cfg))

        files["functions.rs"] = self.gen_functions()
        modules.append(("functions", None))

        for record in self.model.records.values():
            if record.gtype_struct_for is None:
                self.fail("record", self.path(record.name), "records other than class structs are not supported")

        self.report.supplements = [
            (kind, supplements.KINDS[kind], read) for kind, read in supplements.counts(self.model).items()
        ]
        for path in custom.SKIPS:
            if path not in self.skips_used:
                self.report.stale_skips.append(path)
        self.report.stale_skips.extend(self.stale_tables)
        for table in (custom.BOUNDARY_TYPES,):
            for key in table:
                if key not in self.used_keys:
                    self.report.stale_skips.append(key)
        for path in custom.EXTENSIONS:
            if self.model.object(path) is None:
                self.report.stale_skips.append(path)
        for table in (custom.EXAMPLES, custom.ALLOWS, custom.ON_FRIDA_THREAD, custom.MUTABLE_GETTERS, custom.THREAD_SAFE_METHODS,
                      custom.IMMUTABLE, custom.OWNERS, custom.VALUE_COLLECTIONS, custom.MEMBER_RENAMES):
            for key in table:
                if key not in self.used_keys:
                    self.report.stale_skips.append(key)
        for _, acquirers in custom.OWNERS.values():
            for a in acquirers:
                if a not in self.acquired_seen:
                    self.report.stale_skips.append(a)

        mod = [self.header(), "//! The generated half of `frida::gir`: one module per class.\n\n"]
        for name, cfg in modules:
            vis = "pub(crate) " if name in self.list_modules else ""
            mod.append(f"{cfg_attr(cfg)}mod {name};\n{cfg_attr(cfg)}{vis}use {name}::*;\n" if vis else
                       f"{cfg_attr(cfg)}mod {name};\n{cfg_attr(cfg)}pub use {name}::*;\n")
        files["mod.rs"] = "".join(mod)
        return files

    def header(self) -> str:
        return (
            f"// Generated by frida_rust from {self.source} of Frida {self.version}. Do not edit.\n"
            "//\n"
            "// Licence: wxWindows Library Licence, Version 3.1\n\n"
        )

    def file(self, body: str) -> str:
        return f"{self.header()}{body}"

    def fail(self, category: str, path: str, reason: str) -> None:
        if path in custom.SKIPS:
            self.skips_used.add(path)
            self.report.add(category, path, "skipped", custom.SKIPS[path])
        else:
            self.report.add(category, path, "failed", reason)

    def skip_listed(self, category: str, path: str) -> bool:
        if path in custom.SKIPS:
            self.skips_used.add(path)
            self.report.add(category, path, "skipped", custom.SKIPS[path])
            return True
        return False

    def skip_class(self, obj: ObjectType) -> None:
        """A class in the skip table, counted with everything in it."""
        path = self.path(obj.name)
        reason = custom.SKIPS[path]
        self.skips_used.add(path)
        self.report.add(obj.kind, path, "skipped", reason)
        # Nothing of it is generated, so each member the GIR declares is counted by name,
        # whether or not the core can read it (it cannot read RpcClient's methods).
        for e in obj._constructors:
            self.report.add("constructor", f"{path}.{attr(e, 'name')}", "skipped", reason)
        for e in obj._functions:
            self.report.add("function", f"{path}.{attr(e, 'name')}", "skipped", reason)
        for e in obj._methods:
            self.report.add("method", f"{path}.{attr(e, 'name')}", "skipped", reason)
        for e in obj._properties:
            self.report.add("property", f"{path}:{attr(e, 'name')}", "skipped", reason)
        for e in obj._signals:
            self.report.add("signal", f"{path}::{attr(e, 'name')}", "skipped", reason)
        for v in obj.virtual_methods:
            self.report.add("virtual-method", f"{path}.{v.name}", "skipped", reason)

    # --- method classification -------------------------------------------

    def report_forms(self, obj: ObjectType, m: Method) -> None:
        """Counts the `_finish` and `_sync` forms an async method stands for: the core folds
        them into it, and its wrapper calls the `_sync` one."""
        if not m.is_async:
            return
        path = self.path(obj.name)
        self.report.add("method", f"{path}.{m.name}_finish", "skipped", custom.PHASE_SKIPS["finish"])
        if m.sync_element is not None:
            self.report.add("method", f"{path}.{m.name}_sync", "skipped", custom.PHASE_SKIPS["sync"])

    def report_uncovered(self, obj: ObjectType) -> None:
        """Fails each member that neither the core nor `supplements` gives."""
        path = self.path(obj.name)
        sep = {"property": ":", "signal": "::"}
        for u in obj.uncovered:
            self.fail(u.category, f"{path}{sep.get(u.category, '.')}{u.name}", u.error)

    @staticmethod
    def gir_method_names(obj: ObjectType) -> Set[str]:
        """Each method name the GIR declares for `obj`, the forms of async ones included."""
        names = set()
        for m in obj.every_method:
            names.add(m.name)
            if m.is_async:
                names.update((m.name + "_finish", m.name + "_sync"))
        return names

    def accessors(self, obj: ObjectType) -> Dict[str, Tuple[Property, str]]:
        result = {}
        for prop in obj.every_property:
            result[prop.getter] = (prop, "get")
            result["set_" + prop.c_name] = (prop, "set")
        return result

    # --- classes -----------------------------------------------------------

    def parent_local(self, obj: ObjectType) -> Optional[str]:
        if obj.parent_name is None:
            return None
        local = self.model.local(self.model.qualify(obj.parent_name))
        return local if local in self.model.frida_object_types else None

    def children(self, name: str) -> List[ObjectType]:
        return [o for o in self.model.frida_object_types.values() if self.parent_local(o) == name]

    def plan_classes(self) -> None:
        """Which classes are values, lists, skipped; and the value families."""
        self.skipped_classes: Set[str] = {self.path(o.name) for o in self.model.frida_object_types.values() if self.path(o.name) in custom.SKIPS}
        self.lists: Set[str] = set()
        self.list_modules: Set[str] = set()
        for o in self.model.frida_object_types.values():
            if o.name.endswith("List") and o.method("size") is not None and o.method("get") is not None:
                self.lists.add(self.path(o.name))
                self.list_modules.add(snake(o.name))
        seeds = set()
        for o in self.model.frida_object_types.values():
            p = self.path(o.name)
            if p in custom.NOT_VALUES:
                self.used_keys.add(p)
                continue
            if o.kind == "class" and any(pr.writable and not pr.construct_only for pr in o.every_property):
                seeds.add(o.name)
        family = set()

        def add_down(name: str) -> None:
            family.add(name)
            for child in self.children(name):
                add_down(child.name)

        for name in seeds:
            top = name
            while self.parent_local(self.model.frida_object_types[top]) is not None:
                top = self.parent_local(self.model.frida_object_types[top])
            add_down(top)
        self.values: Set[str] = {self.path(n) for n in family if self.path(n) not in self.skipped_classes}
        for key in custom.NOT_VALUES:
            if self.model.object(key) is None:
                self.stale_tables.append(key)

    def is_value(self, name: str) -> bool:
        return self.model.qualify(name) in self.values

    def is_value_enum(self, name: str) -> bool:
        obj = self.model.object(name)
        return obj is not None and self.is_value(name) and not obj.constructors and bool(self.children(obj.name))

    def is_list(self, name: str) -> bool:
        return self.model.qualify(name) in self.lists

    def plan_names(self) -> None:
        """Decide every method's Rust name up front, so docs can link to any of them."""
        self.rust_method_names: Dict[str, Dict[str, str]] = {}
        self.property_of: Dict[Tuple[str, str], Tuple[Property, str]] = {}
        for obj in self.model.frida_object_types.values():
            names: Dict[str, str] = {}
            gir_names = self.gir_method_names(obj)
            accessor = self.accessors(obj)
            for m in obj.every_method:
                if m.is_async:
                    rust = ident(m.name)
                elif m.name in accessor and accessor[m.name][1] == "get":
                    prop = accessor[m.name][0]
                    self.property_of[(obj.name, m.name)] = accessor[m.name]
                    rust = self.getter_name(obj, prop, m, gir_names)
                else:
                    if m.name in accessor:
                        self.property_of[(obj.name, m.name)] = accessor[m.name]
                    rust = ident(m.name)
                names[m.name] = rust
            for m in obj.every_method:
                self.method_names[(obj.name, m.name)] = names[m.name]
                if m.is_async:
                    # Docs may link the blocking form by its own name.
                    self.method_names[(obj.name, m.name + "_sync")] = names[m.name]
            for c in obj.constructors:
                if not c.is_function:
                    self.ctor_names[(obj.name, c.name)] = ident(c.name)
                self.method_names[(obj.name, c.name)] = ident(c.name)
            self.rust_method_names[obj.name] = names
        for f in self.model.functions.values():
            self.method_names[(None, f.name)] = ident(f.name)

    def getter_name(self, obj: ObjectType, prop: Property, m: Method, gir_names: Set[str]) -> str:
        key = f"{self.path(obj.name)}:{prop.name}"
        if key in custom.MEMBER_RENAMES:
            self.used_keys.add(key)
            return custom.MEMBER_RENAMES[key]
        stripped = m.name[len("get_"):]
        rt = m.return_value.type if m.return_value is not None else None
        if rt is not None and rt.name == "gboolean" and not stripped.startswith(("is_", "has_")):
            stripped = "is_" + stripped
        if stripped in RUST_KEYWORDS or stripped in gir_names:
            return m.name
        return stripped

    # --- enums -----------------------------------------------------------

    def gen_enums(self) -> str:
        parts = []
        for e in self.model.frida_enumerations.values():
            path = self.path(e.name)
            try:
                parts.append(self.gen_error_kind(e) if e.error_domain is not None else self.gen_enum(e))
                self.report.add("enumeration", path, "generated")
            except Unsupported as exc:
                self.fail("enumeration", path, str(exc))
        return self.file("\n".join(parts))

    def gen_enum(self, e: Enumeration) -> str:
        name = self.rust_type_name(e.name)
        raw = f"frida_sys::{e.c_type}"
        variants = []
        seen_values: Dict[int, str] = {}
        from_arms = []
        into_arms = []
        nick_arms = []
        parse_arms = []
        used = set()
        for member in e.members:
            v = pascal(member.name)
            if v in used or v == "Unknown":
                raise Unsupported(f"member {member.name} has a Rust name that is taken")
            used.add(v)
            const = f"frida_sys::{e.c_type}_{member.c_identifier}"
            doc = self.doc_lines(member.doc) or [f"`{member.c_identifier}`."]
            cfg = cfg_attr(member.cfg)
            nick = member.name.replace("_", "-")
            variants.append(f"{doc_comment(doc)}{cfg}{v},\n")
            into_arms.append(f"{cfg}Self::{v} => {const},\n")
            nick_arms.append(f'{cfg}Self::{v} => "{nick}",\n')
            parse_arms.append(f'{cfg}"{nick}" => Ok(Self::{v}),\n')
            if member.value not in seen_values:
                seen_values[member.value] = v
                from_arms.append(f"{cfg}{const} => Self::{v},\n")
        doc = self.doc_lines(e.doc) or [f"The `{e.c_type}` enumeration."]
        doc += [
            "",
            "Raw values this version has no variant for convert to [`Self::Unknown`]. It",
            "displays as, and parses from, frida-core's name for it (its nick).",
        ]
        cfg = cfg_attr(e.cfg)
        return (
            f"{doc_comment(doc)}{cfg}"
            "#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]\n#[non_exhaustive]\n"
            f"pub enum {name} {{\n{''.join(variants)}"
            "/// A raw value this version of the bindings has no name for.\nUnknown(i64),\n}\n\n"
            f"{cfg}impl {name} {{\n"
            f"/// The variant for `raw`. Never fails: an unknown value becomes [`Self::Unknown`].\n"
            f"#[must_use]\npub fn from_raw(raw: {raw}) -> Self {{\nmatch raw {{\n"
            f"{''.join(from_arms)}other => Self::Unknown(i64::from(other)),\n}}\n}}\n\n"
            f"/// The raw `{e.c_type}` value.\n"
            f"#[must_use]\npub fn into_raw(self) -> {raw} {{\nmatch self {{\n{''.join(into_arms)}"
            "// A value from `from_raw`, so it fits, unless made by hand, when it wraps.\n"
            f"Self::Unknown(raw) => raw as {raw},\n}}\n}}\n\n"
            "/// frida-core's name for it, its nick, such as `local`; `unknown` for\n"
            "/// [`Self::Unknown`].\n"
            f"#[must_use]\npub fn nick(self) -> &'static str {{\nmatch self {{\n{''.join(nick_arms)}"
            'Self::Unknown(_) => "unknown",\n}\n}\n}\n\n'
            f"{cfg}impl From<{raw}> for {name} {{\nfn from(raw: {raw}) -> Self {{\nSelf::from_raw(raw)\n}}\n}}\n\n"
            f"{cfg}impl From<{name}> for {raw} {{\nfn from(value: {name}) -> Self {{\nvalue.into_raw()\n}}\n}}\n\n"
            f"{cfg}impl std::fmt::Display for {name} {{\n"
            "/// The nick.\n"
            "fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\nf.write_str(self.nick())\n}\n}\n\n"
            f"{cfg}impl std::str::FromStr for {name} {{\ntype Err = {ERR};\n\n"
            "/// The variant whose nick is `text`.\n"
            f"fn from_str(text: &str) -> Result<Self, Self::Err> {{\nmatch text {{\n{''.join(parse_arms)}"
            f'_ => Err({ERR}::invalid_argument(format!("{{text:?}} is not a {name}"))),\n}}\n}}\n}}\n'
        )

    def gen_error_kind(self, e: Enumeration) -> str:
        """The error domain: the kinds of `frida::Error`, frida-core's codes and the
        bindings' own."""
        name = self.rust_type_name(e.name)
        variants = []
        code_arms = []
        text_arms = []
        for member in e.members:
            v = pascal(member.name)
            doc = self.doc_lines(member.doc) or [f"`{member.c_identifier}`."]
            first = (member.doc or member.name.replace("_", " ")).strip().split("\n")[0].rstrip(".")
            text = first[:1].lower() + first[1:]
            variants.append(f"{doc_comment(doc)}{v},\n")
            code_arms.append(f"{member.value} => Self::{v},\n")
            text_arms.append(f'Self::{v} => "{text}",\n')
        for v, text, doc in custom.ERROR_KINDS_EXTRA:
            variants.append(f"{doc_comment([doc])}{v},\n")
            text_arms.append(f'Self::{v} => "{text}",\n')
        doc = self.doc_lines(e.doc) or ["What went wrong."]
        doc += [
            "",
            f"The kind of a [`crate::gir::Error`]: the codes of frida-core's `{e.error_domain}`",
            "error domain, then those the bindings report themselves. New kinds may be added.",
        ]
        return (
            f"{doc_comment(doc)}#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]\n#[non_exhaustive]\n"
            f"pub enum {name} {{\n{''.join(variants)}}}\n\n"
            f"impl {name} {{\n/// The kind of a `{e.c_type}` code: [`Self::Other`] for one this version\n"
            "/// does not know.\n"
            f"pub(crate) fn from_code(code: i32) -> Self {{\nmatch code {{\n{''.join(code_arms)}_ => Self::Other,\n}}\n}}\n}}\n\n"
            f"impl std::fmt::Display for {name} {{\n"
            "/// A description, such as `process not found`.\n"
            f"fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{\nf.write_str(match self {{\n{''.join(text_arms)}}})\n}}\n}}\n"
        )

    # --- kinds ---------------------------------------------------------------

    def kind(self, t: core.Type, key: Optional[str], where: str, length: Optional[Parameter] = None) -> Kind:
        """How the type `t` crosses, `key` naming the parameter or property, and `length`
        the argument holding an array's length, if any."""
        b = self.boundary(key) if key else None
        if t.name.endswith("[]"):
            # The core names an array by its element: utf8[], uint8[], char[], Value[].
            el = t.name[:-2]
            if el == "utf8":
                if b == "env":
                    return Kind("env", "Vec<(String, String)>")
                return Kind("strv", "Vec<String>")
            if el in ("uint8", "char") and length is not None:
                return Kind("u8array", "Vec<u8>")
            raise Unsupported(f"{where}: array of {el}")
        n = t.name
        if b == "timeout-ms":
            if n != "gint":
                raise Unsupported(f"{where}: a timeout-ms of type {n}")
            return Kind("timeout-ms", "Option<std::time::Duration>")
        if b == "seconds":
            if n not in ("guint", "gint"):
                raise Unsupported(f"{where}: seconds of type {n}")
            return Kind("seconds", "std::time::Duration", c=SCALARS[n])
        if b == "interval-s":
            if n != "gint":
                raise Unsupported(f"{where}: an interval of type {n}")
            return Kind("interval-s", "Option<std::time::Duration>")
        if b == "path":
            if n != "utf8":
                raise Unsupported(f"{where}: a path of type {n}")
            return Kind("path", "std::path::PathBuf")
        if b == "gfile":
            if n != "Gio.File":
                raise Unsupported(f"{where}: a gfile of type {n}")
            return Kind("gfile", "std::path::PathBuf")
        if b is not None:
            raise Unsupported(f"{where}: boundary type {b} does not apply to {n}")
        if n in SCALARS:
            return Kind("scalar", SCALARS[n])
        if n == "gboolean":
            return Kind("bool", "bool")
        if n in ("utf8", "filename"):
            return Kind("str", "String")
        if n == "GLib.Bytes":
            return Kind("bytes", "Vec<u8>")
        if n == "GLib.Variant":
            return Kind("variant", "crate::Variant")
        if n == "GLib.HashTable":
            # The core reads only GLib.HashTable<utf8, GLib.Variant>, and refuses others.
            if t.nick != "vardict":
                raise Unsupported(f"{where}: a GLib.HashTable other than <utf8, GLib.Variant>")
            return Kind("vardict", "std::collections::HashMap<String, crate::Variant>")
        q = self.model.qualify(n)
        if q in self.skipped_classes:
            raise Unsupported(f"{where}: {n} is skipped")
        if self.is_list(q):
            obj = self.model.object(q)
            get = obj.method("get")
            el = self.kind(get.return_value.type, None, where, get.return_value.length)
            if el.tag != "handle":
                raise Unsupported(f"{where}: a list of {get.return_value.type.name}")
            return Kind("list", f"Vec<{el.rust}>", c=obj.c_type, gir=q, elem=el)
        if self.is_value(q):
            return Kind("value", f"{GIR}::{self.rust_type_name(q)}", gir=q)
        info = self.object_info(n)
        if info is not None:
            return Kind("handle", info[0], c=info[1], gir=q)
        enum = self.enum_info(n)
        if enum is not None:
            return Kind("enum", enum[0], c=enum[1], gir=q)
        raise Unsupported(f"{where}: no rule for type {n}")

    # --- handles -------------------------------------------------------------

    def ancestors(self, obj: ObjectType) -> List[str]:
        """Rust paths of every class above `obj`, nearest first, then its interfaces."""
        result = []
        parent = obj.parent_name
        seen = set()
        while parent is not None:
            q = self.model.qualify(parent)
            if q in seen:
                raise Unsupported(f"{obj.name}: inheritance cycle")
            seen.add(q)
            info = self.object_info(q)
            if info is None:
                raise Unsupported(f"{obj.name}: unknown parent {parent}")
            if q != "GObject.Object":
                result.append(info[0])
            parent_obj = self.model.object(q)
            parent = parent_obj.parent_name if parent_obj is not None else None
        if obj.kind == "interface":
            for pre in obj.prerequisites:
                if self.model.qualify(pre) != "GObject.Object":
                    raise Unsupported(f"{obj.name}: prerequisite {pre} other than GObject.Object")
        result.append(f"{GIR}::Object")
        interfaces = []
        o = obj
        while o is not None:
            for iface in o.implements:
                if self.model.qualify(iface) in self.skipped_classes:
                    continue
                info = self.object_info(iface)
                if info is None:
                    raise Unsupported(f"{obj.name}: unknown interface {iface}")
                if info[0] not in interfaces:
                    interfaces.append(info[0])
            o = self.model.object(o.parent_name) if o.parent_name else None
        return result + interfaces

    def gen_class(self, obj: ObjectType) -> str:
        path = self.path(obj.name)
        self.report_uncovered(obj)
        if path in self.lists:
            return self.gen_list(obj)
        if path in self.values:
            return self.gen_value(obj)
        return self.gen_handle(obj)

    def method_thread(self, obj: ObjectType, m: Method) -> str:
        """"direct" or "frida" (run on frida-core's thread), by the rules in runtime.rs."""
        mpath = f"{self.path(obj.name)}.{m.name}"
        if m.is_async:
            # Its blocking `_sync` form runs the work on frida-core's thread itself.
            return "direct"
        if mpath in custom.ON_FRIDA_THREAD:
            self.used_keys.add(mpath)
            return "frida"
        if mpath in custom.MUTABLE_GETTERS:
            self.used_keys.add(mpath)
            return "frida"
        if mpath in custom.THREAD_SAFE_METHODS:
            self.used_keys.add(mpath)
            return "direct"
        prop = self.property_of.get((obj.name, m.name))
        if prop is not None and prop[1] == "get":
            owner = self.declaring(obj, prop[0])
            if self.path(owner.name) in custom.IMMUTABLE:
                self.used_keys.add(self.path(owner.name))
                return "direct"
            raise Unsupported(
                f"{m.name}: a getter of {owner.name}, which is in neither customization.IMMUTABLE nor "
                "MUTABLE_GETTERS"
            )
        raise Unsupported(
            f"{m.name}: a plain method in neither customization.THREAD_SAFE_METHODS nor ON_FRIDA_THREAD"
        )

    def declaring(self, obj: ObjectType, prop: Property) -> ObjectType:
        o = obj
        while o is not None:
            if any(p is prop for p in o.every_property):
                return o
            parent = self.parent_local(o)
            o = self.model.frida_object_types[parent] if parent else None
        return obj

    def gen_handle(self, obj: ObjectType) -> str:
        path = self.path(obj.name)
        name = self.rust_type_name(obj.name)
        ancestors = self.ancestors(obj)
        parent = ancestors[0]
        doc = self.doc_lines(obj.doc) or [f"The `{obj.c_type}` {obj.kind}."]
        if obj.kind == "interface":
            doc += [
                "",
                "An interface: a handle to any object that implements it. Implementing it",
                "from Rust is a later phase.",
            ]
        owner = custom.OWNERS.get(path)
        if owner is not None:
            self.used_keys.add(path)
            doc += [
                "",
                f"What acquires one returns an [`Owned<{name}>`]({GIR}::Owned), which calls",
                f"`{owner[0]}` when dropped; a `{name}` itself is a handle, and dropping one",
                "releases nothing.",
            ]
        doc += ["", "A handle: cloning it takes another reference to the same object. It is `Send` and `Sync`."]
        doc += self.example(path)
        extension = custom.EXTENSIONS.get(path)
        if extension is not None:
            file, added = extension
            links = ", ".join(f"[`{m}`](Self::{m})" for m in added)
            doc += ["", f"Written by hand on top of it, in `src/gir/{file}`: {links}."]
        body = [
            f"{GIR}::runtime::object_type! {{\n{doc_comment(doc)}"
            f"pub struct {name}: frida_sys::{obj.c_type} = frida_sys::{obj.get_type};\n"
            f"parent: {parent};\nancestors: [{', '.join(ancestors)}];\n}}\n\n",
            f"{cfg_attr(obj.cfg)}// SAFETY: what Rust can call on it is safe from any thread, or runs on\n"
            "// frida-core's: see the rules in `frida/src/gir/runtime.rs`.\n"
            f"unsafe impl Send for {name} {{}}\n"
            f"{cfg_attr(obj.cfg)}// SAFETY: as for Send.\nunsafe impl Sync for {name} {{}}\n\n",
        ]
        items = []
        # The core's constructors: the <constructor>s, then the class functions that
        # return the class, which are generated as functions.
        for c in obj.constructors:
            category = "function" if c.is_function else "constructor"
            cpath = f"{path}.{c.name}"
            if self.skip_listed(category, cpath):
                continue
            try:
                items.append(self.gen_callable(obj, c, ident(c.name), category))
                self.report.add(category, cpath, "generated", item=c)
            except Unsupported as exc:
                self.fail(category, cpath, str(exc))

        names = self.rust_method_names[obj.name]
        taken: Dict[str, str] = {}
        generated_methods: Set[str] = set()
        debug_fields: List[str] = []
        for m in obj.every_method:
            mpath = f"{path}.{m.name}"
            self.gen_method(obj, m, names[m.name], taken, items, generated_methods, debug_fields)
            self.report_forms(obj, m)

        self.count_properties(obj, generated_methods)

        for sig in obj.signals:
            spath = f"{path}::{sig.name}"
            if self.skip_listed("signal", spath):
                continue
            rust = "connect_" + snake(sig.name.replace("-", "_"))
            if rust in taken:
                self.fail("signal", spath, f"Rust name {rust} is also that of {taken[rust]}")
                continue
            taken[rust] = sig.name
            try:
                items.append(self.gen_signal(obj, sig, rust))
                self.report.add("signal", spath, "generated", item=sig)
            except Unsupported as exc:
                self.fail("signal", spath, str(exc))
        if extension is not None:
            for m in extension[1]:
                if m in taken:
                    self.fail("method", f"{path}.{m}", f"the hand-written {m} in {extension[0]} has a generated twin")
        for v in obj.virtual_methods:
            self.report.add("virtual-method", f"{path}.{v.name}", "skipped", custom.PHASE_SKIPS["virtual-method"])

        if items:
            body.append(f"impl {name} {{\n" + "\n".join(items) + "}\n\n")
        body.append(self.gen_debug(obj, name, debug_fields))
        if owner is not None:
            body.append(self.gen_owner(obj, name, owner))
        return self.file("".join(body))

    def gen_method(
        self, obj: ObjectType, m: Method, rust: str, taken: Dict[str, str], items: List[str],
        generated_methods: Set[str], debug_fields: List[str],
    ) -> None:
        """A handle's method, plain or async, with what makes it a field of `Debug`."""
        path = self.path(obj.name)
        mpath = f"{path}.{m.name}"
        if self.skip_listed("method", mpath):
            return
        if rust in taken:
            self.fail("method", mpath, f"Rust name {rust} is also that of {taken[rust]}")
            return
        taken[rust] = m.name
        try:
            thread = self.method_thread(obj, m)
            items.append(self.gen_callable(obj, m, rust, "method", thread=thread))
        except UnsupportedConstruct as exc:
            self.fail("method", mpath, str(exc))
            return
        self.report.add("method", mpath, "generated", item=m)
        generated_methods.add(m.name)
        gen = self.generated_callables[mpath]
        if thread == "direct" and gen.decls == ["&self"] and not gen.rust_ret.startswith(("Result", "Option<crate::gir", f"{GIR}")) and (
            (obj.name, m.name) in self.property_of or (m.name.startswith("is_") and gen.rust_ret == "bool")
        ):
            debug_fields.append(rust)

    def count_properties(self, obj: ObjectType, generated_methods: Set[str]) -> None:
        path = self.path(obj.name)
        for prop in obj.every_property:
            ppath = f"{path}:{prop.name}"
            if self.skip_listed("property", ppath):
                continue
            needed = [prop.getter] + ([prop.setter] if prop.setter else [])
            missing = [n for n in needed if obj.method(n) is None]
            if missing:
                self.fail("property", ppath, f"no accessor method {', '.join(missing)}")
            elif all(n in generated_methods for n in needed):
                self.report.add("property", ppath, "generated", item=prop)
            else:
                self.fail("property", ppath, "its accessor methods were not generated")

    def gen_debug(self, obj: ObjectType, name: str, fields: List[str]) -> str:
        cfg = cfg_attr(obj.cfg)
        if not fields:
            return (
                f"{cfg}impl std::fmt::Debug for {name} {{\n"
                "fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n"
                f'f.debug_tuple("{name}").field(&{GIR}::ObjectType::as_object(self).as_ptr()).finish()\n}}\n}}\n\n'
            )
        chain = "".join(f'.field("{f}", &self.{f}())' for f in fields)
        return (
            f"{cfg}impl std::fmt::Debug for {name} {{\n"
            "/// Its properties, as frida-core holds them.\n"
            "fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n"
            f'f.debug_struct("{name}"){chain}.finish()\n}}\n}}\n\n'
        )

    def gen_owner(self, obj: ObjectType, name: str, owner: Tuple[str, List[str]]) -> str:
        """`Release` for the class, and the explicit release on its owner."""
        release, acquirers = owner
        path = self.path(obj.name)
        m = obj.method(release)
        if m is not None and m.is_async:
            # Dropping starts the async form, with no cancellable and no callback: the
            # core's arguments, then the callback and its user data, which it leaves out
            # and which come last.
            args = ["object.cast()"]
            for p in m.parameters:
                if p.type.name != "Gio.Cancellable":
                    raise Unsupported(f"{release}: an argument {p.name} the release has no value for")
                args.append("std::ptr::null_mut()")
            tail = [attr(child, "name") for child in parameter_elements(m.element)[len(m.parameters):]]
            types = [self.element_type_name(e) for e in parameter_elements(m.element)[len(m.parameters):]]
            if types != [GIR_ASYNC_CALLBACK, "gpointer"]:
                raise Unsupported(f"{release}: its async form does not end in a callback and its user data: {tail}")
            args += ["None", "std::ptr::null_mut()"]
            start = f"frida_sys::{m.c_identifier}({', '.join(args)})"
        else:
            if m is None or m.parameters or m.throws:
                raise Unsupported(f"{release}: no release method without arguments")
            start = f"frida_sys::{m.c_identifier}(object.cast())"
        gen = self.generated_callables.get(f"{path}.{release}")
        if gen is None:
            raise Unsupported(f"{release}: the release method was not generated")
        decls = ["self"] + gen.decls[1:]
        call_args = ", ".join(gen.names)
        doc = gen.doc + doc_comment([
            "",
            "Consumes the owner, and returns the error that dropping it would discard. Unlike",
            "dropping it, this waits for the release to finish.",
        ])
        return (
            f"crate::gir::owned::release!({name}, |object| {{\n"
            f"// SAFETY: on frida-core's thread, with an instance of {name}; the async form\n"
            "// with no callback starts the release and frees its own state when done.\n"
            f"unsafe {{ {start}; }}\n}});\n\n"
            f"impl {GIR}::Owned<{name}> {{\n{doc}"
            f"pub fn {gen.rust_name}({', '.join(decls)}){'' if gen.rust_ret == '()' else ' -> ' + gen.rust_ret} {{\n"
            f"self.keep().{gen.rust_name}({call_args}){';' if gen.rust_ret == '()' else ''}\n}}\n}}\n\n"
        )

    @staticmethod
    def element_type_name(element) -> Optional[str]:
        t = next((c for c in element if c.tag.endswith("}type")), None)
        return None if t is None else attr(t, "name")

    # --- lists ---------------------------------------------------------------

    def gen_list(self, obj: ObjectType) -> str:
        """The conversion of a list class into a `Vec`; the class itself is not public."""
        path = self.path(obj.name)
        size = obj.method("size")
        get = obj.method("get")
        ok = (
            not size.parameters and len(get.parameters) == 1
            and size.return_value is not None and size.return_value.type.name == "gint"
            and get.parameters[0].type.name == "gint"
            and get.return_value is not None and self.object_info(get.return_value.type.name) is not None
            and not get.return_value.nullable
        )
        if not ok:
            raise Unsupported(f"{obj.name}: a list class without size() and get(gint)")
        for m in obj.every_method:
            mpath = f"{path}.{m.name}"
            if m.name in ("size", "get"):
                self.report.add("method", mpath, "generated", item=m)
            elif self.skip_listed("method", mpath):
                pass
            else:
                self.fail("method", mpath, "a list class's method other than size and get")
            self.report_forms(obj, m)
        for c in obj.constructors:
            self.fail("function" if c.is_function else "constructor", f"{path}.{c.name}", "a list class's constructor")
        element, _, _ = self.object_info(get.return_value.type.name)
        fn = "from_glib_full" if get.return_value.transfer == "full" else "from_glib_none"
        name = snake(obj.name)
        return self.file(
            f"/// The elements of a `{obj.c_type}`, in order, which this unrefs when `full`.\n"
            f"/// A NULL list, or element, which its declaration rules out, is an error.\n"
            "///\n/// # Safety\n///\n"
            f"/// `list` must be null or a `{obj.c_type}`; when `full`, one the caller holds a\n"
            "/// reference to.\n"
            f"pub(crate) unsafe fn {name}_to_vec(\nlist: *mut frida_sys::{obj.c_type},\nfull: bool,\nfunction: &str,\n) -> Result<Vec<{element}>, {ERR}> {{\n"
            f"if list.is_null() {{\nreturn Err({ERR}::unexpected_null(function));\n}}\n"
            f"// SAFETY: a live list, as the caller promises.\n"
            f"let size = unsafe {{ frida_sys::{size.c_identifier}(list) }};\n"
            f"let items = (0..size)\n.map(|i| {{\n"
            f"// SAFETY: an index below the list's size.\n"
            f"let raw = unsafe {{ frida_sys::{get.c_identifier}(list, i) }};\n"
            f"// SAFETY: the list's element type, with the reference get hands over.\n"
            f'{M}::non_null(unsafe {{ <{element} as {GIR}::ObjectType>::{fn}(raw.cast()) }}, "{get.c_identifier}")\n'
            f"}})\n.collect();\n"
            f"if full {{\n// SAFETY: the caller's reference, given back on frida-core's thread.\n"
            f"unsafe {{ frida_sys::frida_unref(list.cast()) }};\n}}\nitems\n}}\n"
        )

    # --- values --------------------------------------------------------------

    def value_family_props(self, obj: ObjectType) -> List[Tuple[ObjectType, Property]]:
        chain = []
        o = obj
        while o is not None:
            chain.append(o)
            parent = self.parent_local(o)
            o = self.model.frida_object_types[parent] if parent else None
        out = []
        for o in reversed(chain):
            for p in o.every_property:
                out.append((o, p))
        return out

    def gen_value(self, obj: ObjectType) -> str:
        path = self.path(obj.name)
        if obj.signals:
            raise Unsupported(f"{obj.name}: a value class with signals")
        if obj.implements:
            raise Unsupported(f"{obj.name}: a value class that implements an interface")
        if self.is_value_enum(obj.name):
            text = self.gen_value_enum(obj)
        else:
            text = self.gen_value_struct(obj)
        for v in obj.virtual_methods:
            self.report.add("virtual-method", f"{path}.{v.name}", "skipped", custom.PHASE_SKIPS["virtual-method"])
        return self.file(text)

    def value_methods(self, obj: ObjectType) -> Tuple[List[Tuple[str, str, Method]], List[Method]]:
        """A value class's collections (field, gir method, add method), and its other
        methods (such as `check`). Every method is accounted for in the report."""
        path = self.path(obj.name)
        accessor = self.accessors(obj)
        collections = []
        others = []
        enumerates = {}
        for m in obj.every_method:
            key = f"{path}.{m.name}"
            if key in custom.VALUE_COLLECTIONS:
                self.used_keys.add(key)
                field_name, enum_m = custom.VALUE_COLLECTIONS[key]
                collections.append((field_name, m.name, m))
                if enum_m is not None:
                    enumerates[enum_m] = field_name
        for m in obj.every_method:
            mpath = f"{path}.{m.name}"
            self.report_forms(obj, m)
            if self.skip_listed("method", mpath):
                continue
            if m.is_async:
                self.fail("method", mpath, "a value class's async method")
                continue
            if m.name in accessor or mpath in custom.VALUE_COLLECTIONS:
                self.report.add("method", mpath, "generated", item=m)
            elif m.name in enumerates or m.name in custom.VALUE_COLLECTION_HELPERS:
                self.report.add("method", mpath, "generated", item=m)
            elif m.name == "check":
                others.append(m)
                self.report.add("method", mpath, "generated", item=m)
            else:
                self.fail("method", mpath, "a value class's method that is neither an accessor, a collection nor check")
        return collections, others

    def value_doc(self, obj: ObjectType) -> List[str]:
        doc = self.doc_lines(obj.doc) or [f"The `{obj.c_type}` options."]
        return doc

    def example(self, path: str) -> List[str]:
        """The class's example from the table, compiled but not run (it needs a device)."""
        code = custom.EXAMPLES.get(path)
        if code is None:
            return []
        self.used_keys.add(path)
        body = [f"# {line}" if False else line for line in code.rstrip("\n").split("\n")]
        return (
            ["", "# Example", "", "```no_run", "# fn main() -> Result<(), frida::Error> {"]
            + body
            + ["# Ok(())", "# }", "```"]
        )

    def gen_value_enum(self, obj: ObjectType) -> str:
        path = self.path(obj.name)
        name = self.rust_type_name(obj.name)
        _, others = self.value_methods(obj)
        for prop in obj.every_property:
            # Each kind below has it as a field of its own.
            self.report.add("property", f"{path}:{prop.name}", "generated", item=prop)
        variants = []
        arms = []
        froms = []
        children = [c for c in self.children(obj.name) if self.path(c.name) not in self.skipped_classes]
        for child in children:
            v = variant_name(obj.name, child.name)
            cname = self.rust_type_name(child.name)
            cdoc = self.doc_lines(child.doc)
            cdoc = cdoc[:1] if cdoc else [f"A [`{cname}`]({GIR}::{cname})."]
            variants.append(f"{doc_comment(cdoc)}{v}({GIR}::{cname}),\n")
            arms.append(f"Self::{v}(value) => value.to_object(),\n")
            froms.append(
                f"impl From<{GIR}::{cname}> for {name} {{\nfn from(value: {GIR}::{cname}) -> Self {{\nSelf::{v}(value)\n}}\n}}\n\n"
            )
            # Leaves further down convert too, through their own enum.
            for leaf in self.value_leaves(child):
                if leaf is child:
                    continue
                lname = self.rust_type_name(leaf.name)
                froms.append(
                    f"impl From<{GIR}::{lname}> for {name} {{\nfn from(value: {GIR}::{lname}) -> Self {{\n"
                    f"Self::{v}(value.into())\n}}\n}}\n\n"
                )
        doc = self.value_doc(obj) + [
            "",
            "A value: one of the kinds below, each a plain struct that converts into this",
            "with `From`. It is built into a new frida-core object for each call that takes it.",
        ]
        methods = "".join(self.gen_value_method(obj, m, name) for m in others)
        return (
            f"{doc_comment(doc)}{cfg_attr(obj.cfg)}#[derive(Debug, Clone, PartialEq)]\n#[non_exhaustive]\n"
            f"pub enum {name} {{\n{''.join(variants)}}}\n\n"
            f"impl {name} {{\n"
            f"/// A new frida-core object holding this value: what a call taking it builds. For\n/// calling `frida-sys` directly; its [`as_ptr`]({GIR}::Object::as_ptr) is the C object.\n///\n/// # Errors\n///\n/// [`ErrorKind::InvalidArgument`]({GIR}::ErrorKind::InvalidArgument) for a field that\n/// cannot be passed to C, and\n/// [`ErrorKind::InvalidOperation`]({GIR}::ErrorKind::InvalidOperation) once frida-core\n/// has been deinitialized.\npub fn to_object(&self) -> Result<{GIR}::Object, {ERR}> {{\nmatch self {{\n{''.join(arms)}}}\n}}\n{methods}}}\n\n"
            + "".join(froms)
        )

    def value_leaves(self, obj: ObjectType) -> List[ObjectType]:
        if self.path(obj.name) in self.skipped_classes:
            return []
        kids = self.children(obj.name)
        if not kids or obj.constructors:
            return [obj]
        out = []
        for k in kids:
            out.extend(self.value_leaves(k))
        return out

    def gen_value_method(self, obj: ObjectType, m: Method, name: str) -> str:
        """A method of a value, such as `check`: run on a frida-core object built from it."""
        if m.parameters or m.return_value is not None or not m.throws:
            raise Unsupported(f"{m.name}: a value's method other than a check that takes and returns nothing")
        doc = self.callable_doc(m, [], "")
        doc += [
            "", "Builds the frida-core object this value stands for, and checks that.", "", "# Errors", "",
            "frida-core's, for a configuration it cannot use; and "
            f"[`ErrorKind::InvalidArgument`]({GIR}::ErrorKind::InvalidArgument) for a field that "
            "cannot be passed to C.",
        ]
        return (
            f"\n{doc_comment(doc)}pub fn {ident(m.name)}(&self) -> Result<(), {ERR}> {{\n"
            "let object = self.to_object()?;\n"
            "let mut raw_error: *mut frida_sys::GError = std::ptr::null_mut();\n"
            f"// SAFETY: a live object of this value's class, or one below it.\n"
            f"unsafe {{ frida_sys::{m.c_identifier}(object.as_ptr().cast(), &raw mut raw_error); }}\n"
            f"// SAFETY: the error the call set, if any, which this now owns.\n"
            f"unsafe {{ {M}::take_error(raw_error) }}.map_or(Ok(()), Err)\n}}\n"
        )

    def value_field(self, owner: ObjectType, prop: Property) -> Dict[str, str]:
        """How one property is a field of a value: its type, default, setter, and the
        statements that set it on the frida-core object `raw`."""
        key = f"{self.path(owner.name)}:{prop.name}"
        getter = owner.method(prop.getter)
        if getter is None:
            raise Unsupported(f"{prop.name}: no getter")
        nullable = getter.return_value.nullable
        k = self.kind(prop.type, key, f"{owner.name}:{prop.name}")
        fname = ident(prop.c_name)
        default = prop.default_value
        info = {"name": fname, "kind": k.tag}
        inner = k.rust
        unset_doc = "`None` leaves frida-core's default."
        if k.tag in ("timeout-ms", "interval-s", "seconds"):
            if default is None:
                raise Unsupported(f"{prop.name}: a {k.tag} property with no default")
            if k.tag == "timeout-ms":
                d = "None" if int(default) < 0 else f"Some(std::time::Duration::from_millis({int(default)}))"
            elif k.tag == "interval-s":
                d = "None" if int(default) < 0 else f"Some(std::time::Duration::from_secs({int(default)}))"
            else:
                d = f"std::time::Duration::from_secs({int(default)})"
            info.update(type=inner, default=d, option=False, doc_extra={
                "timeout-ms": "`None` waits for ever, and [`Duration::ZERO`](std::time::Duration::ZERO) does not wait.",
                "interval-s": "`None` disables it.",
                "seconds": "",
            }[k.tag])
        elif default is not None and k.tag in ("scalar", "bool", "str"):
            if k.tag == "bool":
                d = "true" if default in ("true", "TRUE", "1") else "false"
            elif k.tag == "scalar":
                d = default
            else:
                d = f'"{default}".to_string()'
            info.update(type=inner, default=d, option=False, doc_extra=f"By default `{default}`, as in frida-core.")
        elif k.tag == "vardict":
            info.update(type=inner, default="std::collections::HashMap::new()", option=False, doc_extra="Empty by default.")
        else:
            info.update(type=f"Option<{inner}>", default="None", option=True,
                        doc_extra="" if nullable else unset_doc)
        # The setter's C function, on the class that declares the property.
        setter = owner.method(prop.setter) if prop.setter else None
        if setter is None and not prop.construct_only:
            raise Unsupported(f"{prop.name}: no setter")
        info["setter"] = setter.c_identifier if setter else None
        info["c_self"] = owner.c_type
        info["k"] = k
        info["prop"] = prop
        info["doc"] = self.doc_lines(prop.doc or getter.doc) or [f"The `{prop.name}` property."]
        return info

    def builder(self, f: Dict[str, str]) -> Tuple[str, str]:
        """(parameter declaration, the expression stored) of a field's fluent setter."""
        k: Kind = f["k"]
        n = f["name"]
        if k.tag == "str":
            decl, value = f"{n}: impl Into<String>", f"{n}.into()"
        elif k.tag in ("path", "gfile"):
            decl, value = f"{n}: impl Into<std::path::PathBuf>", f"{n}.into()"
        elif k.tag == "strv":
            decl, value = f"{n}: impl IntoIterator<Item = impl Into<String>>", f"{n}.into_iter().map(Into::into).collect()"
        elif k.tag == "env":
            decl = f"{n}: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>"
            value = f"{n}.into_iter().map(|(name, value)| (name.into(), value.into())).collect()"
        elif k.tag in ("bytes", "u8array"):
            decl, value = f"{n}: impl Into<Vec<u8>>", f"{n}.into()"
        elif k.tag == "handle":
            decl, value = f"{n}: &{k.rust}", f"{n}.clone()"
        elif k.tag == "value":
            decl, value = f"{n}: impl Into<{k.rust}>", f"{n}.into()"
        elif k.tag in ("timeout-ms", "interval-s"):
            decl, value = f"{n}: Option<std::time::Duration>", n
        elif k.tag == "seconds":
            decl, value = f"{n}: std::time::Duration", n
        else:
            decl, value = f"{n}: {k.rust}", n
        if f["option"]:
            value = f"Some({value})"
        return decl, value

    def set_stmts(self, f: Dict[str, str], value: str, raw: str) -> str:
        """Statements setting `value` (a reference to the field's inner value) on `raw`."""
        k: Kind = f["k"]
        setter = f"frida_sys::{f['setter']}"
        target = f"{raw}.cast()"
        safety = "// SAFETY: a live object of the class that declares the property.\n"
        if k.tag == "str":
            return f"let value_raw = {M}::cstring({value})?;\n{safety}unsafe {{ {setter}({target}, value_raw.as_ptr()); }}\n"
        if k.tag == "path":
            return f"let value_raw = {M}::path({value})?;\n{safety}unsafe {{ {setter}({target}, value_raw.as_ptr()); }}\n"
        if k.tag == "gfile":
            return (
                f"let value_raw = {GIR}::File::for_path({value})?;\n"
                f"{safety}unsafe {{ {setter}({target}, {GIR}::ObjectType::as_raw(&value_raw)); }}\n"
            )
        if k.tag == "strv":
            return f"let value_raw = {M}::StrArray::new({value})?;\n{safety}unsafe {{ {setter}({target}, value_raw.as_ptr(), value_raw.len()); }}\n"
        if k.tag == "env":
            return (
                f"let entries = {M}::env_entries({value})?;\nlet value_raw = {M}::StrArray::new(&entries)?;\n"
                f"{safety}unsafe {{ {setter}({target}, value_raw.as_ptr(), value_raw.len()); }}\n"
            )
        if k.tag == "bytes":
            return f"let value_raw = {M}::BytesIn::new({value})?;\n{safety}unsafe {{ {setter}({target}, value_raw.as_ptr()); }}\n"
        if k.tag == "variant":
            return f"let value_raw = {M}::VariantIn::new({value})?;\n{safety}unsafe {{ {setter}({target}, value_raw.as_ptr()); }}\n"
        if k.tag == "vardict":
            return f"let value_raw = {M}::VarDictIn::new({value})?;\n{safety}unsafe {{ {setter}({target}, value_raw.as_ptr()); }}\n"
        if k.tag == "scalar":
            return f"{safety}unsafe {{ {setter}({target}, *{value}); }}\n"
        if k.tag == "bool":
            return f"{safety}unsafe {{ {setter}({target}, frida_sys::gboolean::from(*{value})); }}\n"
        if k.tag == "enum":
            return f"{safety}unsafe {{ {setter}({target}, {value}.into_raw()); }}\n"
        if k.tag == "timeout-ms":
            return f"let value_raw = {M}::timeout_ms(*{value})?;\n{safety}unsafe {{ {setter}({target}, value_raw); }}\n"
        if k.tag == "interval-s":
            return f"let value_raw = {M}::interval_s(*{value})?;\n{safety}unsafe {{ {setter}({target}, value_raw); }}\n"
        if k.tag == "seconds":
            return f"let value_raw = {M}::seconds::<{k.c}>(*{value})?;\n{safety}unsafe {{ {setter}({target}, value_raw); }}\n"
        if k.tag == "handle":
            return f"{safety}unsafe {{ {setter}({target}, {GIR}::ObjectType::as_raw({value}).cast()); }}\n"
        if k.tag == "value":
            return f"let value_raw = {value}.to_object()?;\n{safety}unsafe {{ {setter}({target}, value_raw.as_ptr().cast()); }}\n"
        raise Unsupported(f"no rule to set a {k.tag}")

    def ctor_arg(self, k: Kind, value: str, nullable: bool, i: int) -> Tuple[str, str]:
        """(statements, C argument) passing the field `value` to a constructor."""
        v = f"arg{i}"
        if k.tag == "str":
            if nullable:
                return f"let {v} = {M}::opt_cstring({value}.as_deref())?;\n", f"{M}::opt_cstring_ptr({v}.as_ref())"
            return f"let {v} = {M}::cstring(&{value})?;\n", f"{v}.as_ptr()"
        if k.tag == "gfile":
            if nullable:
                return (
                    f"let {v} = {value}.as_deref().map({GIR}::File::for_path).transpose()?;\n",
                    f"{v}.as_ref().map_or(std::ptr::null_mut(), {GIR}::ObjectType::as_raw)",
                )
            return f"let {v} = {GIR}::File::for_path(&{value})?;\n", f"{GIR}::ObjectType::as_raw(&{v})"
        if k.tag == "bytes":
            if nullable:
                return f"let {v} = {M}::BytesIn::new_opt({value}.as_deref())?;\n", f"{v}.as_ptr()"
            return f"let {v} = {M}::BytesIn::new(&{value})?;\n", f"{v}.as_ptr()"
        if k.tag == "handle":
            if nullable:
                return "", f"{value}.as_ref().map_or(std::ptr::null_mut(), |v| {GIR}::ObjectType::as_raw(v).cast())"
            return "", f"{GIR}::ObjectType::as_raw(&{value}).cast()"
        if k.tag == "value":
            if nullable:
                return (
                    f"let {v} = {value}.as_ref().map(|v| v.to_object()).transpose()?;\n",
                    f"{v}.as_ref().map_or(std::ptr::null_mut(), |o| o.as_ptr().cast())",
                )
            return f"let {v} = {value}.to_object()?;\n", f"{v}.as_ptr().cast()"
        if k.tag == "scalar" and not nullable:
            return "", value
        if k.tag == "enum" and not nullable:
            return "", f"{value}.into_raw()"
        raise Unsupported(f"no rule to pass a {k.tag} to a constructor")

    def gen_value_struct(self, obj: ObjectType) -> str:
        path = self.path(obj.name)
        name = self.rust_type_name(obj.name)
        collections, others = self.value_methods(obj)
        # Collections of the classes above, flattened in too.
        o = obj
        inherited_collections = []
        parent = self.parent_local(o)
        while parent is not None:
            pobj = self.model.frida_object_types[parent]
            for m in pobj.every_method:
                key = f"{self.path(pobj.name)}.{m.name}"
                if key in custom.VALUE_COLLECTIONS:
                    self.used_keys.add(key)
                    inherited_collections.append((custom.VALUE_COLLECTIONS[key][0], m.name, m))
            parent = self.parent_local(pobj)
        collections = inherited_collections + collections

        ctor = next((c for c in obj.constructors if c.name == "new" and not c.is_function), None)
        if ctor is None:
            raise Unsupported(f"{obj.name}: a value class without a `new` constructor")
        if ctor.throws:
            raise Unsupported(f"{obj.name}: a value class whose constructor throws")
        fields = []
        by_name = {}
        for owner, prop in self.value_family_props(obj):
            f = self.value_field(owner, prop)
            fields.append(f)
            by_name[prop.c_name] = f
            if owner is obj:
                self.report.add("property", f"{path}:{prop.name}", "generated", item=prop)
        ctor_fields = []
        for p in ctor.parameters:
            f = by_name.get(p.name)
            if f is None:
                raise Unsupported(f"{obj.name}.new: parameter {p.name} is no property")
            ctor_fields.append((f, p))
        for f in fields:
            if f["prop"].construct_only and not any(cf is f for cf, _ in ctor_fields):
                raise Unsupported(f"{obj.name}: construct-only {f['prop'].name} is not an argument of `new`")
        required = []
        for f, p in ctor_fields:
            if not p.nullable and f["option"]:
                # A required argument: no default to leave it at.
                f["option"] = False
                f["type"] = f["k"].rust
                f["default"] = None
                f["doc_extra"] = ""
                required.append(f)

        example = self.example(path)
        doc = self.value_doc(obj) + [
            "",
            "A value: build it in one expression with "
            + (f"[`new`](Self::new)" if not required else f"[`new`](Self::new)")
            + " and the setters named after its fields, which",
            "consume and return it. A field left at its default leaves frida-core's default.",
            "It is built into a new frida-core object for each call that takes it.",
        ] + example
        # Fields.
        field_lines = []
        for f in fields:
            fdoc = list(f["doc"])
            if f.get("doc_extra"):
                fdoc += ["", f["doc_extra"]]
            field_lines.append(f"{doc_comment(fdoc)}pub {f['name']}: {f['type']},\n")
        for cname, mname, m in collections:
            elem = self.collection_elem(m)
            cdoc = self.doc_lines(m.doc) or [f"What `{mname}` adds."]
            field_lines.append(f"{doc_comment(cdoc + ['', f'Added to with [`{mname}`](Self::{mname}).'])}pub {cname}: Vec<{elem[0]}>,\n")
        # Constructor and setters.
        new_params = [self.builder(f)[0] for f in required]
        new_body_fields = []
        for f in fields:
            if f in required:
                stored = self.builder(f)[1]
                new_body_fields.append(f"{f['name']},\n" if stored == f["name"] else f"{f['name']}: {stored},\n")
            else:
                new_body_fields.append(f"{f['name']}: {f['default']},\n")
        for cname, _, _ in collections:
            new_body_fields.append(f"{cname}: Vec::new(),\n")
        new_doc = ["Options with every field at its default."] if not required else [
            "A value with the arguments it cannot do without, and every other field at its default."
        ]
        methods = [
            f"{doc_comment(new_doc)}#[must_use]\npub fn new({', '.join(new_params)}) -> Self {{\nSelf {{\n{''.join(new_body_fields)}}}\n}}\n"
        ]
        for f in fields:
            if f in required:
                continue
            decl, value = self.builder(f)
            fdoc = [f"Sets [`{f['name']}`](Self::{f['name']})."]
            methods.append(
                f"\n{doc_comment(fdoc)}#[must_use]\npub fn {f['name']}(mut self, {decl}) -> Self {{\nself.{f['name']} = {value};\nself\n}}\n"
                if f["kind"] != "vardict" else
                f"\n/// Adds the entry `key` to [`{f['name']}`](Self::{f['name']}), replacing any of the same key.\n"
                f"#[must_use]\npub fn {f['name']}(mut self, key: impl Into<String>, value: crate::Variant) -> Self {{\n"
                f"self.{f['name']}.insert(key.into(), value);\nself\n}}\n"
            )
        for cname, mname, m in collections:
            elem = self.collection_elem(m)
            mdoc = self.doc_lines(m.doc) or [f"Adds to [`{cname}`](Self::{cname})."]
            methods.append(
                f"\n{doc_comment(mdoc)}#[must_use]\npub fn {mname}(mut self, {elem[1]}) -> Self {{\n"
                f"self.{cname}.push({elem[2]});\nself\n}}\n"
            )
        # to_object.
        body = [f"let _lease = {GIR}::runtime::Lease::new()?;\n"]
        args = []
        for i, (f, p) in enumerate(ctor_fields):
            stmts, arg = self.ctor_arg(f["k"], f"self.{f['name']}", f["option"], i)
            body.append(stmts)
            args.append(arg)
        body.append(
            f"// SAFETY: frida-core is initialized (the lease), and the arguments are valid.\n"
            f"let raw_new = unsafe {{ frida_sys::{ctor.c_identifier}({', '.join(args)}) }};\n"
            f"let object = {M}::non_null(\n// SAFETY: a new instance, whose reference this takes.\n"
            f"unsafe {{ <{GIR}::Object as {GIR}::ObjectType>::from_glib_full(raw_new.cast()) }},\n\"{ctor.c_identifier}\",\n)?;\n"
        )
        set_body = []
        ctor_set = {id(f) for f, _ in ctor_fields}
        for f in fields:
            if id(f) in ctor_set:
                continue
            if f["prop"].construct_only:
                continue
            stmts = self.set_stmts(f, "value", "raw")
            if f["option"]:
                set_body.append(f"if let Some(value) = &self.{f['name']} {{\n{stmts}}}\n")
            elif f["kind"] == "vardict":
                set_body.append(f"if !self.{f['name']}.is_empty() {{\nlet value = &self.{f['name']};\n{stmts}}}\n")
            else:
                set_body.append(f"{{\nlet value = &self.{f['name']};\n{stmts}}}\n")
        for cname, mname, m in collections:
            set_body.append(self.collection_add(m, cname))
        if set_body:
            body.append("let raw = object.as_ptr();\n")
            body.extend(set_body)
        body.append("Ok(object)\n")
        methods.append(
            f"\n/// A new frida-core object holding this value: what a call taking it builds. For\n/// calling `frida-sys` directly; its [`as_ptr`]({GIR}::Object::as_ptr) is the C object.\n///\n/// # Errors\n///\n/// [`ErrorKind::InvalidArgument`]({GIR}::ErrorKind::InvalidArgument) for a field that\n/// cannot be passed to C, and\n/// [`ErrorKind::InvalidOperation`]({GIR}::ErrorKind::InvalidOperation) once frida-core\n/// has been deinitialized.\n"
            f"pub fn to_object(&self) -> Result<{GIR}::Object, {ERR}> {{\n{''.join(body)}}}\n"
        )
        if path in self.returned_values():
            methods.append(self.gen_from_object(obj, fields, collections, self.returned_values()[path]))
        for m in others:
            methods.append(self.gen_value_method(obj, m, name))
        for c in obj.constructors:
            cpath = f"{path}.{c.name}"
            if c.is_function:
                self.fail("function", cpath, "a value class's function")
                continue
            if c is ctor:
                self.report.add("constructor", cpath, "generated", item=c)
                continue
            if self.skip_listed("constructor", cpath):
                continue
            methods.append(self.gen_value_ctor(obj, c, by_name, fields, collections))
            self.report.add("constructor", cpath, "generated", item=c)
        default = ""
        if not required:
            default = (
                f"impl Default for {name} {{\n/// The same as [`{name}::new`].\nfn default() -> Self {{\nSelf::new()\n}}\n}}\n\n"
            )
        return (
            f"{doc_comment(doc)}{cfg_attr(obj.cfg)}#[derive(Debug, Clone, PartialEq)]\n#[non_exhaustive]\n"
            f"pub struct {name} {{\n{''.join(field_lines)}}}\n\n"
            f"impl {name} {{\n{''.join(methods)}}}\n\n{default}"
        )

    def gen_value_ctor(self, obj: ObjectType, c, by_name, fields, collections) -> str:
        """A constructor other than `new` whose arguments are all properties: the same
        value, made in Rust."""
        if c.throws:
            raise Unsupported(f"{obj.name}.{c.name}: a value constructor that throws")
        params = []
        sets = []
        for p in c.parameters:
            f = by_name.get(p.name)
            if f is None:
                raise Unsupported(f"{obj.name}.{c.name}: parameter {p.name} is no property")
            decl, value = self.builder(f)
            params.append(decl)
            sets.append(f"{f['name']}: {value},\n")
        doc = self.doc_lines(c.doc) or [f"A value made the way `{c.c_identifier}` makes one."]
        return (
            f"\n{doc_comment(doc)}#[must_use]\npub fn {ident(c.name)}({', '.join(params)}) -> Self {{\n"
            f"Self {{\n{''.join(sets)}..Self::new()\n}}\n}}\n"
        )

    def returned_values(self) -> Dict[str, Set[bool]]:
        """The value classes something returns, which need converting back, and whether
        as nullable, non-null, or both."""
        if hasattr(self, "_returned"):
            return self._returned
        out: Dict[str, Set[bool]] = {}
        for o in self.model.frida_object_types.values():
            if self.path(o.name) in self.values:
                continue
            for m in o.every_method:
                rt = m.return_value.type if m.return_value is not None else None
                if rt is not None and self.is_value(rt.name):
                    out.setdefault(self.model.qualify(rt.name), set()).add(m.return_value.nullable)
        self._returned = out
        return out

    def gen_from_object(self, obj: ObjectType, fields, collections, forms: Set[bool]) -> str:
        if collections:
            raise Unsupported(f"{obj.name}: a returned value with collections")
        name = self.rust_type_name(obj.name)
        lines = []
        for f in fields:
            prop = f["prop"]
            owner = self.declaring(obj, prop)
            getter = owner.method(prop.getter)
            rp = self.return_plan_of(getter, f["k"], "getter")
            hoisted, conv = hoist(rp.convert.replace("raw_ret", "raw_value"), "converted")
            if rp.fallible:
                conv += "?"
            if f["option"] and not rp.rust_type.startswith("Option<"):
                conv = f"Some({conv})"
            if not f["option"] and rp.rust_type.startswith("Option<") and f["k"].tag not in ("timeout-ms", "interval-s"):
                conv = f"{conv}.unwrap_or_default()"
            call = f"unsafe {{ frida_sys::{getter.c_identifier}(raw.cast()) }}"
            if conv == "raw_value":
                lines.append(f"// SAFETY: a live {owner.c_type}.\n{f['name']}: {call},\n")
            else:
                if conv == "converted":
                    hoisted, conv = "", hoisted.replace("let converted = ", "", 1).rstrip().rstrip(";")
                lines.append(
                    f"{f['name']}: {{\n// SAFETY: a live {owner.c_type}.\n"
                    f"let raw_value = {call};\n{hoisted}{conv}\n}},\n"
                )
        return (
            f"\n/// The value the frida-core object at `raw` holds; an error for a NULL, which\n"
            f"/// `function`'s declaration rules out.\n///\n/// # Safety\n///\n"
            f"/// `raw` must be null or a live `{obj.c_type}`.\n"
            f"pub(crate) unsafe fn from_object(raw: *mut frida_sys::{obj.c_type}, function: &str) -> Result<Self, {ERR}> {{\n"
            f"if raw.is_null() {{\nreturn Err({ERR}::unexpected_null(function));\n}}\n"
            f"Ok(Self {{\n{''.join(lines)}}})\n}}\n"
        ) + (
            "\n/// As `from_object`, with `None` for a NULL.\n///\n/// # Safety\n///\n"
            f"/// `raw` must be null or a live `{obj.c_type}`.\n"
            f"pub(crate) unsafe fn from_nullable_object(raw: *mut frida_sys::{obj.c_type}) -> Result<Option<Self>, {ERR}> {{\n"
            "if raw.is_null() {\nreturn Ok(None);\n}\n"
            "// SAFETY: a live object, as the caller promises.\n"
            'unsafe { Self::from_object(raw, "") }.map(Some)\n}\n'
            if True in forms else ""
        )

    def collection_elem(self, m: Method) -> Tuple[str, str, str]:
        """(element type, setter parameters, element expression) of a collection's add."""
        kinds = []
        for p in m.parameters:
            kinds.append((ident(p.name), self.kind(p.type, None, m.name)))
        def one(n: str, k: Kind) -> Tuple[str, str, str]:
            if k.tag == "str":
                return "String", f"{n}: impl Into<String>", f"{n}.into()"
            if k.tag == "handle":
                return k.rust, f"{n}: &{k.rust}", f"{n}.clone()"
            if k.tag in ("scalar", "enum"):
                return k.rust, f"{n}: {k.rust}", n
            raise Unsupported(f"{m.name}: a collection of {k.tag}")
        parts = [one(n, k) for n, k in kinds]
        if len(parts) == 1:
            return parts[0]
        return (
            "(" + ", ".join(p[0] for p in parts) + ")",
            ", ".join(p[1] for p in parts),
            "(" + ", ".join(p[2] for p in parts) + ")",
        )

    def collection_add(self, m: Method, cname: str) -> str:
        kinds = [(ident(p.name), self.kind(p.type, None, m.name)) for p in m.parameters]
        pre = []
        args = []
        for i, (n, k) in enumerate(kinds):
            item = "item" if len(kinds) == 1 else f"item.{i}"
            if k.tag == "str":
                pre.append(f"let arg{i} = {M}::cstring({item if len(kinds) == 1 else '&' + item})?;\n")
                args.append(f"arg{i}.as_ptr()")
            elif k.tag == "handle":
                args.append(f"{GIR}::ObjectType::as_raw({'item' if len(kinds) == 1 else '&' + item}).cast()")
            elif k.tag == "scalar":
                args.append(f"*{item}" if len(kinds) == 1 else item)
            elif k.tag == "enum":
                args.append(f"{item}.into_raw()")
            else:
                raise Unsupported(f"{m.name}: a collection of {k.tag}")
        return (
            f"for item in &self.{cname} {{\n{''.join(pre)}"
            f"// SAFETY: a live object of the class that declares `{m.name}`.\n"
            f"unsafe {{ frida_sys::{m.c_identifier}(raw.cast(), {', '.join(args)}); }}\n}}\n"
        )

    # --- namespace functions ---------------------------------------------

    def gen_functions(self) -> str:
        items = []
        for f in self.model.functions.values():
            fpath = self.path(f.name)
            if f.supplement == "unreadable":
                self.fail("function", fpath, f.error)
                continue
            if self.skip_listed("function", fpath):
                continue
            try:
                items.append(self.gen_callable(None, f, ident(f.name), "function"))
                self.report.add("function", fpath, "generated", item=f)
            except Unsupported as exc:
                self.fail("function", fpath, str(exc))
        return self.file("\n".join(items))

    # --- callables ---------------------------------------------------------

    def type_cfg(self, t) -> Optional[str]:
        if t is None:
            return None
        # The core's types of arrays and hash tables name none of Frida's types.
        obj = self.model.object(t.name)
        enum = self.model.enumeration(t.name)
        return obj.cfg if obj is not None else (enum.cfg if enum is not None else None)

    def gen_callable(self, owner: Optional[ObjectType], c, rust_name: str, kind: str, thread: str = "direct") -> str:
        """A Rust function calling `c`: a method, constructor or function, as the core
        made it or `supplements` did. An async method calls its blocking `_sync` form."""
        where = f"{owner.name}.{c.name}" if owner else c.name
        gir_path = self.path(where)
        # A blocking `_sync` form runs its work, callbacks included, on frida-core's thread.
        self.current_runs_elsewhere = c.is_async or thread == "frida"
        c_function = c.blocking_c_identifier
        params = c.parameters
        consumed: Dict[int, str] = {}
        for p in params:
            if p.length is not None:
                consumed[index_of(params, p.length)] = "length"
            if p.closure is not None and self.callback_def(p.type) is not None:
                consumed[index_of(params, p.closure)] = "closure"
            if p.destroy is not None:
                consumed[index_of(params, p.destroy)] = "destroy"
        rv = c.return_value
        if rv is not None and rv.length is not None:
            j = index_of(params, rv.length)
            if params[j].is_input:
                raise Unsupported("return array length is not an out parameter")
            consumed[j] = "return-length"

        cfg = c.cfg
        arg_exprs: List[Optional[str]] = [None] * len(params)
        plans: List[ParamPlan] = []
        outs: List[Tuple[int, Parameter]] = []
        for i, p in enumerate(params):
            cfg = cfg_join(cfg, self.type_cfg(p.type))
            role = consumed.get(i)
            if role in ("closure", "destroy"):
                continue
            if role == "return-length":
                if p.type.name != "gint":
                    raise Unsupported(f"{p.name}: array length of type other than gint")
                arg_exprs[i] = "&raw mut raw_ret_length"
                continue
            if role == "length":
                continue
            if not p.is_input:
                outs.append((i, p))
                continue
            plan = self.in_param(p, i, params, arg_exprs, f"{gir_path}.{p.name}")
            plans.append(plan)

        ret = self.return_plan(c, outs, params, arg_exprs, where, gir_path)
        cfg = cfg_join(cfg, self.type_cfg(rv.type if rv is not None else None))
        if any(a is None for a in arg_exprs):
            missing = [params[i].name for i, a in enumerate(arg_exprs) if a is None]
            raise Unsupported(f"no rule for parameter(s) {', '.join(missing)}")

        # Owners.
        owned = None
        if kind in ("constructor", "function", "method"):
            for cls, (_, acquirers) in custom.OWNERS.items():
                if gir_path in acquirers:
                    owned = cls
                    self.acquired_seen.add(gir_path)
        if kind == "constructor":
            value_type = "Self"
        else:
            value_type = ret.rust_type
        if owned is not None:
            oname = self.rust_type_name(owned)
            if kind == "constructor":
                value_type = f"{GIR}::Owned<Self>"
            elif value_type.endswith(f"::{oname}"):
                value_type = f"{GIR}::Owned<{value_type}>"
            else:
                raise Unsupported(f"an acquirer of {owned} that returns {value_type}")
        fallible = (
            c.throws
            or kind in ("constructor", "function")
            or ret.fallible
            or any(p.fallible for p in plans)
        )

        # The signature.
        generics = [g for p in plans for g in p.generics]
        decls = [p.decl for p in plans if p.decl is not None]
        names = [p.name for p in plans if p.decl is not None]
        if owner is not None and kind == "method":
            decls.insert(0, "&self")
        rust_ret = f"Result<{value_type}, {ERR}>" if fallible else value_type
        sig = f"pub fn {rust_name}"
        if generics:
            sig += "<" + ", ".join(generics) + ">"
        sig += "(" + ", ".join(decls) + ")"
        if rust_ret != "()":
            sig += f" -> {rust_ret}"

        # The body.
        body: List[str] = []
        if kind in ("constructor", "function"):
            body.append(f"let _lease = {GIR}::runtime::Lease::new()?;\n")
        for p in plans:
            body.extend(p.items)
        for p in plans:
            body.extend(p.pre)
        if any("raw_ret_length" in (a or "") for a in arg_exprs):
            body.append("let mut raw_ret_length: frida_sys::gint = 0;\n")
        for i, p in outs:
            body.append(self.out_local(p, i))
        args = []
        if owner is not None and kind == "method":
            args.append(f"{GIR}::ObjectType::as_raw(self)")
        args.extend(arg_exprs)
        if c.throws:
            body.append("let mut raw_error: *mut frida_sys::GError = std::ptr::null_mut();\n")
            args.append("&raw mut raw_error")
        call = f"frida_sys::{c_function}({', '.join(args)})"
        safety = "// SAFETY: the handle and the arguments are valid for the call, as the GIR declares it.\n"
        if thread == "frida":
            end = ";" if c.return_value is None else ""
            lead = (
                f"let on_frida_thread = || {{\n{safety}unsafe {{ {call}{end} }}\n}};\n"
                "// SAFETY: the pointers stay valid while this waits for the call on frida-core's thread.\n"
            )
            call = f"unsafe {{ {GIR}::runtime::run_on_frida_thread_raw(on_frida_thread) }}"
        else:
            lead = safety
            call = f"unsafe {{ {call} }}"
        if c.return_value is not None:
            body.append(f"{lead}let raw_ret = {call};\n")
        elif thread == "frida":
            body.append(f"{lead}{call};\n")
        else:
            body.append(f"{lead}{call[:-1].rstrip()}; }}\n")
        for p in plans:
            body.extend(p.post)
        if c.throws:
            discard = f"{RETURN_SAFETY}{ret.discard};\n" if ret.discard else ""
            body.append(
                f"// SAFETY: the error the call set, if any, which this now owns.\n"
                f"if let Some(error) = unsafe {{ {M}::take_error(raw_error) }} {{\n{discard}return Err(error);\n}}\n"
            )
        value = ret.convert
        if value is not None:
            stmt, value = hoist(value, "raw_value")
            if stmt:
                body.append(stmt)
        if value is not None and ret.fallible and (owned is not None or not fallible):
            value += "?"
        if owned is not None:
            value = f"{GIR}::Owned::new({value})"
        if value == "raw_ret" and body[-1].startswith(f"{lead}let raw_ret = ") and not fallible:
            # The call's result is the value: no binding to return.
            body[-1] = body[-1].replace("let raw_ret = ", "", 1).rstrip().rstrip(";") + "\n"
        elif fallible and ret.fallible and owned is None:
            if value == "raw_value" and body[-1].startswith(RETURN_SAFETY):
                # The conversion is the value: the block itself is the tail.
                body[-1] = body[-1].replace("let raw_value = ", "", 1).rstrip().rstrip(";") + "\n"
            else:
                body.append(f"{value}\n")
        elif fallible:
            body.append(f"Ok({value if value else '()'})\n")
        elif value == "raw_value" and body[-1].startswith(RETURN_SAFETY):
            body[-1] = body[-1].replace("let raw_value = ", "", 1).rstrip().rstrip(";") + "\n"
        elif value:
            body.append(f"{value}\n")

        fallback = f"Creates a new `{owner.c_type}`." if kind == "constructor" and owner else ""
        extra_doc = None
        if owner is not None and kind == "method" and not c.doc:
            prop = self.property_of.get((owner.name, c.name))
            if prop is not None:
                extra_doc = prop[0].doc
        doc_lines = self.callable_doc(c, plans, fallback, extra_doc)
        if owned is not None:
            oname = self.rust_type_name(owned)
            release = custom.OWNERS[owned][0]
            doc_lines += [
                "",
                f"The result owns what this acquires: dropping it calls [`{release}`]({GIR}::{oname}::{release}).",
            ]
        if thread == "frida":
            doc_lines += ["", "Runs on frida-core's thread, and waits for it there."]
        if fallible:
            doc_lines += ["", "# Errors", ""] + self.errors_doc(c, kind, plans, ret)
        doc = doc_comment(doc_lines)
        must_use = "" if fallible or rust_ret == "()" or owned else "#[must_use]\n"
        allow = custom.ALLOWS.get(gir_path)
        if allow is not None:
            self.used_keys.add(gir_path)
            must_use += f'#[allow({allow[0]}, reason = "{allow[1]}")]\n'
        self.generated_callables[gir_path] = Generated(rust_name, decls, names, rust_ret, doc)
        return f"{doc}{cfg_attr(cfg)}{must_use}{sig} {{\n{''.join(body)}}}\n"

    def errors_doc(self, c, kind: str, plans: List[ParamPlan], ret: ReturnPlan) -> List[str]:
        """Why a call can fail, as a list."""
        kinds = f"{GIR}::ErrorKind"
        out = []
        if c.throws:
            out.append("- frida-core's error, if the call fails.")
            if any(p.name == "cancellable" for p in plans):
                out.append(f"- [`ErrorKind::Cancelled`]({kinds}::Cancelled), if `cancellable` is cancelled.")
        bad = [p.name for p in plans if p.fallible]
        if bad:
            names = ", ".join(f"`{n}`" for n in bad)
            out.append(
                f"- [`ErrorKind::InvalidArgument`]({kinds}::InvalidArgument), if {names} cannot be "
                "passed to C: a string holding a NUL byte, a path that is not UTF-8, or a value too "
                "large for its C type."
            )
        if kind in ("constructor", "function"):
            out.append(
                f"- [`ErrorKind::InvalidOperation`]({kinds}::InvalidOperation), once frida-core has "
                f"been deinitialized ([`deinit`]({GIR}::deinit))."
            )
        if ret.fallible:
            out.append(
                f"- [`ErrorKind::Unexpected`]({kinds}::Unexpected), if frida-core returns NULL, which "
                "its declaration rules out."
            )
        return out

    # --- signals ---------------------------------------------------------

    def gen_signal(self, obj: ObjectType, sig: Signal, rust: str) -> str:
        """A `connect_*` method: a Rust closure as the handler of a GObject signal.

        The handler runs on frida-core's thread, so it is `Send + 'static`, and so is
        every object it is lent (every handle is). Arguments are borrowed for the
        emission: the GIR marks every one of frida-core's signal arguments
        transfer-ownership="none", and anything else is refused.
        """
        if sig.return_type is not None:
            raise Unsupported("a signal whose handlers return a value")
        c_types = [f"*mut frida_sys::{obj.c_type}"]
        c_params = [f"_instance: {c_types[0]}"]
        rust_args: List[str] = []
        conversions: List[str] = []
        call_args: List[str] = []
        arg_docs: List[Tuple[str, str]] = []
        cfg = sig.cfg
        for p in sig.parameters:
            name = ident(p.name)
            if not p.is_input or p.transfer != "none":
                raise Unsupported(f"{p.name}: a signal argument that is not a borrowed input")
            t = p.type
            if t.name.endswith("[]"):
                raise Unsupported(f"{p.name}: an array signal argument")
            cfg = cfg_join(cfg, self.type_cfg(t))
            opt = p.nullable
            n = t.name
            # A non-null argument that arrives NULL after all is not delivered.
            skip = "else {\nreturn;\n};\n"
            if n in ("utf8", "filename"):
                c = "*const std::os::raw::c_char"
                if opt:
                    rust_args.append("Option<&str>")
                    conversions.append(f"let {name} = {M}::str_arg({name});\n")
                    call_args.append(f"{name}.as_deref()")
                else:
                    rust_args.append("&str")
                    conversions.append(f"let {name} = {M}::str_arg({name}).unwrap_or_default();\n")
                    call_args.append(f"&{name}")
            elif n == "GLib.Bytes":
                c = "*mut frida_sys::GBytes"
                rust_args.append("Option<&[u8]>" if opt else "&[u8]")
                conversions.append(f"let {name} = {M}::bytes_arg({name});\n")
                call_args.append(name if opt else f"{name}.unwrap_or_default()")
            elif n == "GLib.Variant":
                c = "*mut frida_sys::GVariant"
                if opt:
                    rust_args.append("Option<&crate::Variant>")
                    conversions.append(f"let {name} = {M}::variant({name}, false);\n")
                    call_args.append(f"{name}.as_ref()")
                else:
                    rust_args.append("&crate::Variant")
                    conversions.append(f"let Some({name}) = {M}::variant({name}, false) {skip}")
                    call_args.append(f"&{name}")
            elif n in SCALARS:
                c = SCALARS[n]
                rust_args.append(SCALARS[n])
                call_args.append(name)
            elif n == "gboolean":
                c = "frida_sys::gboolean"
                rust_args.append("bool")
                call_args.append(f"{name} != 0")
            elif self.enum_info(n) is not None:
                if opt:
                    raise Unsupported(f"{p.name}: a nullable enumeration")
                rust_enum, c_enum = self.enum_info(n)
                c = f"frida_sys::{c_enum}"
                rust_args.append(rust_enum)
                call_args.append(f"{rust_enum}::from_raw({name})")
            elif self.object_info(n) is not None and not self.is_value(n) and not self.is_list(n):
                rust_obj, c_obj, _ = self.object_info(n)
                c = f"*mut frida_sys::{c_obj}"
                borrow = f"{GIR}::runtime::borrow::<{rust_obj}>({name}.cast())"
                if opt:
                    rust_args.append(f"Option<&{rust_obj}>")
                    conversions.append(f"let {name} = {borrow};\n")
                    call_args.append(f"{name}.as_deref()")
                else:
                    rust_args.append(f"&{rust_obj}")
                    conversions.append(f"let Some({name}) = {borrow} {skip}")
                    call_args.append(f"&{name}")
            else:
                raise Unsupported(f"{p.name}: no rule for a signal argument of type {n}")
            c_types.append(c)
            c_params.append(f"{name}: {c}")
            if p.doc:
                arg_docs.append((name, p.doc))
        c_types.append("frida_sys::gpointer")
        c_params.append("user_data: frida_sys::gpointer")
        bound = f"FnMut({', '.join(rust_args)}) + Send + 'static"
        fn_type = f"unsafe extern \"C\" fn({', '.join(c_types)})"

        lines = self.doc_lines(sig.doc) or [f"The `{sig.name}` signal."]
        if arg_docs:
            lines += ["", "# Arguments", ""]
            lines += [f"- `{a}`: {one_line(d, self.resolve_link)}" for a, d in arg_docs]
        lines += [
            "",
            "`handler` runs on frida-core's thread. Dropping the returned",
            f"[`SignalHandler`]({GIR}::SignalHandler) disconnects it, and its",
            f"[`keep`]({GIR}::SignalHandler::keep) leaves it connected for the life of the object;",
            f"the [`signal`]({GIR}::signal) module has the details.",
            "",
            f"Connects to the `{sig.name}` signal.",
        ]
        invocation = f"f({', '.join(call_args)})"
        body = (
            f"unsafe extern \"C\" fn trampoline<F: {bound}>({', '.join(c_params)}) {{\n"
            f"// SAFETY: GLib calls this with the data `connect` gave it, and arguments that live\n"
            f"// for the emission.\n"
            f"unsafe {{ {GIR}::signal::emit::<F>(user_data, |f| {{\n{''.join(conversions)}{invocation};\n}}); }}\n}}\n"
            f"let trampoline: {fn_type} = trampoline::<F>;\n"
            f"// SAFETY: the trampoline has the C signature of the signal's handlers, and hands\n"
            f"// the user data to `emit`; `{sig.name}` is a signal of this class.\n"
            f"unsafe {{\n{GIR}::signal::connect(\n{GIR}::ObjectType::as_object(self),\nc\"{sig.name}\",\n"
            f"std::mem::transmute::<{fn_type}, unsafe extern \"C\" fn()>(trampoline),\nhandler,\n)\n}}\n"
        )
        return (
            f"{doc_comment(lines)}{cfg_attr(cfg)}pub fn {rust}<F: {bound}>(&self, handler: F) -> {GIR}::SignalHandler {{\n"
            f"{body}}}\n"
        )

    # --- arguments -------------------------------------------------------

    def callback_def(self, t: core.Type):
        """The callback type `t` names: Frida's, or one of GLib's in
        `customization.FOREIGN_CALLBACKS`, read from GLib's GIR; or None."""
        if t.nick in ("strv", "bytearray", "chararray", "valuearray") or t.name in core.model.PRIMITIVE_GIR_TYPES:
            return None
        q = self.model.qualify(t.name)
        if self.model.local(q) is None and q not in custom.FOREIGN_CALLBACKS:
            return None
        return self.model.callback(q)

    def in_param(self, p: Parameter, index: int, params: List[Parameter], args: List[Optional[str]], key: str) -> ParamPlan:
        name = ident(p.name)
        plan = ParamPlan(doc=p.doc, name=name)
        t = p.type
        opt = p.nullable

        def wrap(rust: str) -> str:
            return f"Option<{rust}>" if opt else rust

        if p.transfer != "none":
            raise Unsupported(f"{p.name}: transfer-ownership={p.transfer} on an argument")

        cb = self.callback_def(t)
        if cb is not None:
            return self.callback_param(p, index, params, args, cb, key.rsplit(".", 1)[0])
        k = self.kind(t, key, key, p.length)
        if k.tag == "strv":
            if opt:
                # No frida-core call takes one today; add the rule with its first user.
                raise Unsupported(f"{p.name}: a nullable string array argument")
            plan.decl = f"{name}: &[impl AsRef<str>]"
            plan.pre.append(f"let {name}_raw = {M}::StrArray::new({name})?;\n")
            plan.fallible = True
            args[index] = f"{name}_raw.as_ptr()"
            if p.length is not None:
                args[index_of(params, p.length)] = f"{name}_raw.len()"
            return plan
        if k.tag == "u8array":
            plan.decl = f"{name}: {wrap('&[u8]')}"
            plan.fallible = True
            if opt:
                plan.pre.append(f"let {name}_len = {M}::length({name}.map_or(0, <[u8]>::len))?;\n")
                args[index] = f"{name}.map_or(std::ptr::null_mut(), |b| b.as_ptr().cast_mut())"
            else:
                plan.pre.append(f"let {name}_len = {M}::length({name}.len())?;\n")
                args[index] = f"{name}.as_ptr().cast_mut()"
            args[index_of(params, p.length)] = f"{name}_len"
            return plan
        if k.tag == "timeout-ms":
            plan.decl = f"{name}: Option<std::time::Duration>"
            plan.pre.append(f"let {name}_raw = {M}::timeout_ms({name})?;\n")
            plan.fallible = True
            plan.doc = (p.doc + " " if p.doc else "") + "`None` waits for ever."
            plan.doc = plan.doc.replace("milliseconds to wait", "how long to wait").replace("or 0 to not wait", "or zero not to wait")
            args[index] = f"{name}_raw"
            return plan
        if k.tag == "scalar":
            plan.decl = f"{name}: {k.rust}"
            args[index] = name
            return plan
        if k.tag == "bool":
            plan.decl = f"{name}: bool"
            args[index] = f"frida_sys::gboolean::from({name})"
            return plan
        if k.tag in ("str", "path"):
            rust = "&str" if k.tag == "str" else "&std::path::Path"
            fn = "cstring" if k.tag == "str" else "path"
            plan.decl = f"{name}: {wrap(rust)}"
            plan.fallible = True
            if opt:
                plan.pre.append(f"let {name}_raw = {M}::opt_{fn}({name})?;\n")
                args[index] = f"{M}::opt_cstring_ptr({name}_raw.as_ref())"
            else:
                plan.pre.append(f"let {name}_raw = {M}::{fn}({name})?;\n")
                args[index] = f"{name}_raw.as_ptr().cast_mut()"
            return plan
        if k.tag == "gfile":
            plan.decl = f"{name}: {wrap('&std::path::Path')}"
            plan.fallible = True
            if opt:
                plan.pre.append(f"let {name}_raw = {name}.map({GIR}::File::for_path).transpose()?;\n")
                args[index] = f"{name}_raw.as_ref().map_or(std::ptr::null_mut(), {GIR}::ObjectType::as_raw)"
            else:
                plan.pre.append(f"let {name}_raw = {GIR}::File::for_path({name})?;\n")
                args[index] = f"{GIR}::ObjectType::as_raw(&{name}_raw)"
            return plan
        if k.tag == "bytes":
            plan.decl = f"{name}: {wrap('&[u8]')}"
            plan.fallible = True
            plan.pre.append(f"let {name}_raw = {M}::BytesIn::new{'_opt' if opt else ''}({name})?;\n")
            args[index] = f"{name}_raw.as_ptr()"
            return plan
        if k.tag == "variant":
            if opt:
                # No frida-core call takes one today; add the rule with its first user.
                raise Unsupported(f"{p.name}: a nullable variant argument")
            plan.decl = f"{name}: &crate::Variant"
            plan.fallible = True
            plan.pre.append(f"let {name}_raw = {M}::VariantIn::new({name})?;\n")
            args[index] = f"{name}_raw.as_ptr()"
            return plan
        if k.tag == "vardict":
            if opt:
                raise Unsupported(f"{p.name}: a nullable GLib.HashTable argument")
            plan.decl = f"{name}: &std::collections::HashMap<String, crate::Variant>"
            plan.fallible = True
            plan.pre.append(f"let {name}_raw = {M}::VarDictIn::new({name})?;\n")
            args[index] = f"{name}_raw.as_ptr()"
            return plan
        if k.tag == "value":
            plan.decl = f"{name}: {wrap('&' + k.rust)}"
            plan.fallible = True
            if opt:
                plan.pre.append(f"let {name}_raw = {name}.map({k.rust}::to_object).transpose()?;\n")
                args[index] = f"{name}_raw.as_ref().map_or(std::ptr::null_mut(), |o| o.as_ptr().cast())"
            else:
                plan.pre.append(f"let {name}_raw = {name}.to_object()?;\n")
                args[index] = f"{name}_raw.as_ptr().cast()"
            return plan
        if k.tag == "handle":
            plan.decl = f"{name}: {wrap('&' + k.rust)}"
            if opt:
                args[index] = f"{name}.map_or(std::ptr::null_mut(), |o| {GIR}::ObjectType::as_raw(o).cast())"
            else:
                args[index] = f"{GIR}::ObjectType::as_raw({name}).cast()"
            return plan
        if k.tag == "enum":
            if opt:
                raise Unsupported(f"{p.name}: a nullable enumeration")
            plan.decl = f"{name}: {k.rust}"
            args[index] = f"{name}.into_raw()"
            return plan
        raise Unsupported(f"{p.name}: no rule for an argument of kind {k.tag}")

    def callback_param(
        self, p: Parameter, index: int, params: List[Parameter], args: List[Optional[str]], cb, where: str
    ) -> ParamPlan:
        """A Rust closure in place of a C callback and its user data."""
        name = ident(p.name)
        plan = ParamPlan(doc=p.doc, name=name)
        if p.scope not in ("call", "notified"):
            raise Unsupported(f"{p.name}: callback scope {p.scope}")
        if p.closure is None:
            raise Unsupported(f"{p.name}: callback without user data")
        if cb.throws:
            raise Unsupported(f"{p.name}: a callback that throws")
        if p.scope == "notified" and p.destroy is None:
            raise Unsupported(f"{p.name}: notified callback without a destroy notify")
        if p.scope == "call" and p.destroy is not None:
            raise Unsupported(f"{p.name}: call-scoped callback with a destroy notify")
        if p.nullable:
            raise Unsupported(f"{p.name}: a nullable callback")
        user = [i for i, cp in enumerate(cb.parameters) if cp.closure is cp]
        if len(user) != 1:
            raise Unsupported(f"{p.name}: callback type {cb.name} has no single user-data argument")
        user_index = user[0]
        overrides = custom.CALLBACK_ARGUMENTS.get(where, {})
        generic = f"F{index}"
        rt = cb.return_value.type if cb.return_value is not None else None
        if rt is None:
            rust_ret, c_ret, finish, default = "", "", "", "()"
        elif rt.name == "gboolean":
            rust_ret, c_ret, finish, default = " -> bool", " -> frida_sys::gboolean", "frida_sys::gboolean::from", "false"
        else:
            raise Unsupported(f"{p.name}: callback returning {getattr(rt, 'name', rt)}")
        skip = f"else {{\nreturn {default};\n}};\n" if default != "()" else "else {\nreturn;\n};\n"

        c_params = []
        rust_args = []
        conversions = []
        call_args = []
        for i, cp in enumerate(cb.parameters):
            pname = ident(cp.name)
            if i == user_index:
                c_params.append(f"{pname}: frida_sys::gpointer")
                continue
            if not cp.is_input or cp.transfer != "none":
                raise Unsupported(f"{p.name}: callback argument {cp.name} is not a borrowed input")
            if cp.type.name.endswith("[]"):
                raise Unsupported(f"{p.name}: callback argument {cp.name} is an array")
            ctype = c_pointer_type(cp.type.c)
            c_params.append(f"{pname}: {ctype}")
            kind = cp.type.name
            if kind == "gpointer":
                kind = overrides.get(cp.name)
                if kind is None:
                    raise Unsupported(
                        f"{p.name}: callback argument {cp.name} is an untyped gpointer and "
                        "customization.CALLBACK_ARGUMENTS does not say what it is"
                    )
            if kind == "utf8":
                rust_args.append("&str")
                conversions.append(
                    f"let {pname} = {M}::str_arg({pname} as *const std::os::raw::c_char).unwrap_or_default();\n"
                )
                call_args.append(f"&{pname}")
            elif kind == "guint-in-pointer":
                rust_args.append("u32")
                call_args.append(f"{pname} as usize as u32")
            elif kind == "guint64-pointer":
                rust_args.append("Option<u64>")
                call_args.append(f"({pname} as *const u64).as_ref().copied()")
            elif kind in SCALARS:
                rust_args.append(SCALARS[kind])
                call_args.append(pname)
            elif kind == "gboolean":
                rust_args.append("bool")
                call_args.append(f"{pname} != 0")
            else:
                info = self.object_info(kind)
                if info is None or self.is_value(kind) or self.is_list(kind):
                    raise Unsupported(f"{p.name}: callback argument {cp.name} of type {kind}")
                rust_args.append(f"&{info[0]}")
                conversions.append(f"let Some({pname}) = {GIR}::runtime::borrow::<{info[0]}>({pname}.cast()) {skip}")
                call_args.append(f"&{pname}")
        bound = f"FnMut({', '.join(rust_args)}){rust_ret}"
        if p.scope == "notified":
            bound += " + Send + 'static"
        elif self.current_runs_elsewhere:
            bound += " + Send"
        if self.current_runs_elsewhere:
            plan.doc = (p.doc + " " if p.doc else "") + "(Called on frida-core's thread, while this call waits.)"
        plan.generics.append(f"{generic}: {bound}")
        plan.decl = f"{name}: {generic}"
        tramp = f"{name}_trampoline"
        user_name = ident(cb.parameters[user_index].name)
        invocation = f"f({', '.join(call_args)})"
        fn = "invoke" if p.scope == "call" else "invoke_notified"
        inner = (
            f"// SAFETY: frida-core calls this with the user data it was given, during the call\n"
            f"// (or until the destroy notify), and arguments that live for the callback.\n"
            f"unsafe {{ {M}::{fn}::<{generic}, _>({user_name}, |f| {{\n{''.join(conversions)}{invocation}{';' if not rust_ret else ''}\n}}) }}"
        )
        if finish:
            inner = f"let result = {{ {inner} }};\n{finish}(result)"
        plan.items.append(
            f"unsafe extern \"C\" fn {tramp}<{generic}: {bound}>({', '.join(c_params)}){c_ret} {{\n{inner}\n}}\n"
        )
        args[index] = f"Some({tramp}::<{generic}>)"
        if p.scope == "call":
            plan.pre.append(f"let mut {name}_state = {M}::CallState::new({name});\n")
            args[index_of(params, p.closure)] = f"{name}_state.as_ptr()"
            plan.post.append(f"{name}_state.finish();\n")
        else:
            plan.pre.append(f"let {name}_data = {M}::NotifiedState::into_raw({name});\n")
            args[index_of(params, p.closure)] = f"{name}_data"
            args[index_of(params, p.destroy)] = f"Some({M}::drop_boxed::<{generic}>)"
        return plan

    # --- return values -----------------------------------------------------

    def out_local(self, p: Parameter, index: int) -> str:
        n = p.type.name
        return f"let mut raw_out_{index}: frida_sys::{n} = Default::default();\n"

    def return_plan(
        self, c, outs: List[Tuple[int, Parameter]], params: List[Parameter], args: List[Optional[str]],
        where: str, gir_path: str,
    ) -> ReturnPlan:
        rv = c.return_value
        if rv is not None and rv.transfer == "container":
            raise Unsupported("transfer-ownership=container on the return value")
        if outs:
            # The core's one value a gboolean method hands back through a pointer.
            out = getattr(c, "optional_out_parameter", None)
            if len(outs) != 1 or out is None or outs[0][1] is not out:
                raise Unsupported("out parameters other than one beside a gboolean return")
            i, p = outs[0]
            if p.type.name not in SCALARS:
                raise Unsupported(f"{p.name}: out parameter of type {p.type.name}")
            args[i] = f"&raw mut raw_out_{i}"
            rust = SCALARS[p.type.name]
            return ReturnPlan(f"Option<{rust}>", f"(raw_ret != 0).then_some(raw_out_{i})")
        if rv is None:
            return ReturnPlan("()", None)
        t = rv.type
        # A property getter's boundary type is the property's.
        key = None
        owner_name = where.split(".")[0] if "." in where else None
        if owner_name is not None:
            prop = self.property_of.get((owner_name, c.name))
            if prop is not None:
                key = f"{self.path(owner_name)}:{prop[0].name}"
        k = self.kind(t, key, where, rv.length)
        return self.return_plan_of(c, k, gir_path)

    def return_plan_of(self, c, k: Kind, gir_path: str) -> ReturnPlan:
        return self.return_plan_inner(c, k, gir_path)

    def return_plan_inner(self, c, k: Kind, gir_path: str) -> ReturnPlan:
        rv = c.return_value
        full = "true" if rv.transfer == "full" else "false"
        ident_ = c.blocking_c_identifier
        if k.tag == "scalar":
            return ReturnPlan(k.rust, "raw_ret")
        if k.tag == "bool":
            return ReturnPlan("bool", "raw_ret != 0")
        if k.tag == "enum":
            return ReturnPlan(k.rust, f"{k.rust}::from_raw(raw_ret)")
        if k.tag == "timeout-ms":
            return ReturnPlan(k.rust, f"{M}::timeout_from_ms(raw_ret)")
        if k.tag == "interval-s":
            return ReturnPlan(k.rust, f"{M}::interval_from_s(raw_ret)")
        if k.tag == "seconds":
            return ReturnPlan(k.rust, f"{M}::from_seconds(u64::from(raw_ret))")
        if k.tag in ("strv", "env"):
            if rv.length is None:
                raise Unsupported("return value: array of utf8 without a length parameter")
            conv = f"unsafe {{ {M}::string_array(raw_ret, raw_ret_length, {full}) }}"
            rust = "Vec<String>"
            if k.tag == "env":
                conv = f"{conv}.map({M}::env_pairs)"
                rust = "Vec<(String, String)>"
            return self.finish_pointer(rv, rust, conv)
        if k.tag == "str":
            return self.finish_pointer(rv, "String", f"unsafe {{ {M}::string(raw_ret, {full}) }}")
        if k.tag == "path":
            return self.finish_pointer(
                rv, "std::path::PathBuf", f"unsafe {{ {M}::string(raw_ret, {full}) }}.map({M}::path_buf)"
            )
        if k.tag == "gfile":
            fn = "from_glib_full" if rv.transfer == "full" else "from_glib_none"
            conv = f"unsafe {{ <{GIR}::File as {GIR}::ObjectType>::{fn}(raw_ret) }}.and_then(|file| file.path())"
            return self.finish_pointer(rv, "std::path::PathBuf", conv)
        if k.tag == "bytes":
            return self.finish_pointer(rv, "Vec<u8>", f"unsafe {{ {M}::bytes(raw_ret, {full}) }}")
        if k.tag == "vardict":
            return self.finish_pointer(rv, k.rust, f"unsafe {{ {M}::vardict(raw_ret, {full}) }}")
        if k.tag == "variant":
            return self.finish_object(rv, "crate::Variant", f"unsafe {{ {M}::variant(raw_ret, {full}) }}", ident_)
        if k.tag == "handle":
            fn = "from_glib_full" if rv.transfer == "full" else "from_glib_none"
            conv = f"unsafe {{ <{k.rust} as {GIR}::ObjectType>::{fn}(raw_ret.cast()) }}"
            return self.finish_object(rv, k.rust, conv, ident_)
        if k.tag == "list":
            if rv.nullable:
                raise Unsupported("a nullable list")
            fn = f"{GIR}::generated::{snake(self.model.local(k.gir))}_to_vec"
            return ReturnPlan(
                k.rust, f'unsafe {{ {fn}(raw_ret, {full}, "{ident_}") }}', fallible=True,
                discard=f'drop(unsafe {{ {fn}(raw_ret, {full}, "{ident_}") }})' if rv.transfer == "full" else None,
            )
        if k.tag == "value":
            if self.is_value_enum(k.gir):
                raise Unsupported("an abstract value class returned")
            if rv.transfer == "full":
                raise Unsupported("a value class returned with transfer full")
            if rv.nullable:
                return ReturnPlan(f"Option<{k.rust}>", f"unsafe {{ {k.rust}::from_nullable_object(raw_ret) }}", fallible=True)
            return ReturnPlan(k.rust, f'unsafe {{ {k.rust}::from_object(raw_ret, "{ident_}") }}', fallible=True)
        raise Unsupported(f"no rule for a return value of kind {k.tag}")

    def finish_pointer(self, rv, rust: str, conv: str) -> ReturnPlan:
        """A pointer return with an empty value: `Option` when nullable, else the value,
        empty for a NULL (a string or collection frida-core never set reads as empty)."""
        discard = f"drop({conv})" if rv.transfer == "full" else None
        if rv.nullable:
            return ReturnPlan(f"Option<{rust}>", conv, discard=discard)
        return ReturnPlan(rust, f"{conv}.unwrap_or_default()", discard=discard)

    def finish_object(self, rv, rust: str, conv: str, ident_: str) -> ReturnPlan:
        """A pointer return with no empty value: `Option` when nullable, else an error for
        a NULL, which its declaration rules out."""
        discard = f"drop({conv})" if rv.transfer == "full" else None
        if rv.nullable:
            return ReturnPlan(f"Option<{rust}>", conv, discard=discard)
        return ReturnPlan(rust, f'{M}::non_null({conv}, "{ident_}")', fallible=True, discard=discard)

