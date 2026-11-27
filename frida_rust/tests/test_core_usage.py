#
# Copyright © 2026 Kirby Kuehl
#
# Licence: wxWindows Library Licence, Version 3.1
#
"""Where each generated item comes from: frida_bindgen_core's model, or frida_rust's
supplements of what it leaves out.

This instruments the core, runs a full generation from the GIRs of the release in
FRIDA_VERSION, and sorts every generated method, constructor, function, property,
signal and parameter by where its object was made: by the core (in `ObjectType.methods`,
`constructors`, `properties` or `signals`), or by `supplements`, by kind. It also counts
the calls into the core's readers.

Run it as a script for the table:

    scripts/update-bindings.sh --fetch-only    # once, to fetch the GIRs
    PYTHONPATH=frida-bindgen python3 -m frida_rust.tests.test_core_usage

As a test, it checks that every generated item comes from one or the other, that an
item from the supplements is one the core leaves out, and that the core's members are
what the generator reads. It is skipped when the GIRs are not in the devkit cache.
"""
from __future__ import annotations

import os
import sys
import unittest
from collections import Counter, OrderedDict
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterator, List, Optional

import frida_bindgen_core as core
from frida_bindgen_core import model as core_model

from frida_rust import loader, supplements
from frida_rust.codegen import Generator

ROOT = Path(__file__).resolve().parents[2]

# The core's member lists, whose results are recorded as the core's.
MEMBER_LISTS = ("methods", "constructors", "properties", "signals")

# The core's readers, whose calls are counted.
READERS = (
    "parse_gir", "extract_callable_details", "extract_parameters", "parse_type",
    "extract_type_from_entity",
)

CATEGORIES = OrderedDict([
    ("method", "methods"), ("constructor", "constructors"), ("function", "functions"),
    ("property", "properties"), ("signal", "signals"), ("parameter", "parameters"),
])


def gir_paths() -> Optional[List[Path]]:
    """The five GIRs scripts/update-bindings.sh fetches, from the devkit cache, or None."""
    version = (ROOT / "FRIDA_VERSION").read_text().strip()
    cache = Path(os.environ.get("FRIDA_DEVKIT_CACHE") or
                 Path(os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
                 / "frida" / "devkits")
    names = ["linux-x86_64.gir", "windows-x86_64.gir", "GLib-2.0.gir", "GObject-2.0.gir", "Gio-2.0.gir"]
    paths = [cache / f"frida-core-{version}-{n}" for n in names]
    return paths if all(p.is_file() for p in paths) else None


class Instrumentation:
    """What the core made and how often its readers were called, during a `with`."""

    def __init__(self) -> None:
        self.made_by_core: Dict[int, object] = {}
        self.calls: Counter = Counter()

    def _record(self, items) -> None:
        for item in items:
            self.made_by_core[id(item)] = item
            for p in getattr(item, "parameters", []):
                self.made_by_core[id(p)] = p
            rv = getattr(item, "return_value", None)
            if rv is not None:
                self.made_by_core[id(rv)] = rv

    def is_cores(self, item) -> bool:
        return self.made_by_core.get(id(item)) is item

    @contextmanager
    def active(self) -> Iterator["Instrumentation"]:
        saved = []
        for name in MEMBER_LISTS:
            prop = core.ObjectType.__dict__[name]
            original = prop.func

            def wrapped(obj, _original=original, _name=name):
                self.calls[f"ObjectType.{_name}"] += 1
                items = _original(obj)
                self._record(items)
                return items

            prop.func = wrapped
            saved.append((prop, "func", original))
        members = core.Enumeration.__dict__["members"]
        original_members = members.func

        def counted_members(enum):
            self.calls["Enumeration.members"] += 1
            return original_members(enum)

        members.func = counted_members
        saved.append((members, "func", original_members))
        for name in READERS:
            original = getattr(core_model, name)

            def counted(*args, _original=original, _name=name, **kwargs):
                self.calls[_name] += 1
                return _original(*args, **kwargs)

            setattr(core_model, name, counted)
            saved.append((core_model, name, original))
            # The core's loader holds its own reference to parse_gir.
            if getattr(core.loader, name, None) is original:
                setattr(core.loader, name, counted)
                saved.append((core.loader, name, original))
        try:
            yield self
        finally:
            for target, attribute, original in reversed(saved):
                setattr(target, attribute, original)


def measure(paths: List[Path]):
    """A full generation under the instrumentation: (the table by category, as
    OrderedDict of category -> Counter of source, the calls into the core, the report,
    the model)."""
    instrumentation = Instrumentation()
    with instrumentation.active():
        model = loader.load(*paths)
        generator = Generator(model, "measure")
        generator.generate()
    table: "OrderedDict[str, Counter]" = OrderedDict((c, Counter()) for c in CATEGORIES)
    table["parameter"] = Counter()

    def source(item, owner=None) -> str:
        """Where `item` was made; a parameter the core did not make is its owner's."""
        if instrumentation.is_cores(item):
            return "core"
        kind = getattr(owner if owner is not None else item, "supplement", None)
        return f"supplement:{kind}" if kind in supplements.KINDS else "neither"

    for entry in generator.report.entries:
        if entry.status != "generated" or entry.category not in table:
            continue
        item = entry.item
        table[entry.category][source(item)] += 1
        for p in getattr(item, "parameters", []):
            table["parameter"][source(p, item)] += 1
    return table, instrumentation.calls, generator.report, model


def render(table, calls) -> str:
    lines = [f"{'generated':14}{'total':>7}{'core':>7}{'supplements':>13}  by kind"]
    for category, sources in table.items():
        total = sum(sources.values())
        sup = {k.split(":", 1)[1]: v for k, v in sources.items() if k.startswith("supplement:")}
        kinds = ", ".join(f"{k} {v}" for k, v in sup.items())
        neither = sources.get("neither", 0)
        lines.append(
            f"{CATEGORIES[category]:14}{total:7}{sources.get('core', 0):7}{sum(sup.values()):13}  {kinds}"
            + (f"  NEITHER {neither}" if neither else "")
        )
    lines.append("")
    lines.append("calls into frida_bindgen_core:")
    for name, n in sorted(calls.items()):
        lines.append(f"  {name:28}{n:7}")
    return "\n".join(lines)


PATHS = gir_paths()


@unittest.skipIf(PATHS is None, "the GIRs are not in the devkit cache: run scripts/update-bindings.sh --fetch-only")
class CoreUsageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.table, cls.calls, cls.report, cls.model = measure(PATHS)

    def test_every_generated_item_is_the_cores_or_a_supplements(self):
        for category, sources in self.table.items():
            self.assertNotIn("neither", sources, category)
            self.assertGreater(sources["core"], 0, category)

    def test_what_the_core_models_comes_from_the_core(self):
        # A supplement item is one the core's lists leave out, by name.
        for entry in self.report.entries:
            item = entry.item
            if entry.status != "generated" or getattr(item, "supplement", None) is None:
                continue
            owner = getattr(item, "object_type", None)
            if owner is None:
                self.assertEqual(item.supplement, "function", entry.path)
                continue
            core_names = {x.name for x in owner.methods + owner.properties + owner.constructors + owner.signals}
            self.assertNotIn(item.name, core_names, entry.path)

    def test_the_cores_member_model_is_read(self):
        for name in MEMBER_LISTS:
            self.assertGreater(self.calls[f"ObjectType.{name}"], 0, name)
        for name in READERS:
            self.assertGreater(self.calls[name], 0, name)

    def test_the_supplements_are_few(self):
        supplied = sum(v for s in self.table.values() for k, v in s.items() if k != "core")
        core_made = sum(s["core"] for s in self.table.values())
        self.assertLess(supplied * 20, core_made)


def main() -> int:
    if PATHS is None:
        print("The GIRs are not in the devkit cache: run scripts/update-bindings.sh --fetch-only", file=sys.stderr)
        return 1
    table, calls, _, _ = measure(PATHS)
    print(render(table, calls))
    return 0


if __name__ == "__main__":
    sys.exit(main())
