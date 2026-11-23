#
# Copyright © 2026 Kirby Kuehl
#
# Licence: wxWindows Library Licence, Version 3.1
#
"""Reads Frida's GIR, with GLib's, GObject's and Gio's, through frida_bindgen_core."""
from __future__ import annotations

from pathlib import Path

import frida_bindgen_core as core

from . import platforms, strict
from .model import FACTORY, Customizations, Model, UnsupportedConstruct

# frida-rust maps the few GLib, GObject and Gio types Frida's API uses by hand
# (customization.FOREIGN_OBJECTS and FOREIGN_ENUMS), so it pulls none into the model.
INCLUDED_GIO_OBJECT_TYPES: list = []
INCLUDED_GIO_ENUMERATIONS: list = []


def compute_model(frida_gir: Path, glib_gir: Path, gobject_gir: Path, gio_gir: Path) -> Model:
    """The model of one Frida GIR, refused if it holds anything `strict` does not know."""
    strict.check(frida_gir)
    try:
        return core.compute_model(
            frida_gir,
            glib_gir,
            gobject_gir,
            gio_gir,
            Customizations(),
            FACTORY,
            INCLUDED_GIO_OBJECT_TYPES,
            INCLUDED_GIO_ENUMERATIONS,
            seed_object_first=False,
        )
    except AssertionError as exc:
        raise UnsupportedConstruct(f"frida_bindgen_core: {exc}") from exc


def load(unix_gir: Path, windows_gir: Path, glib_gir: Path, gobject_gir: Path, gio_gir: Path) -> Model:
    """One model of a Unix GIR (macOS, Linux, Android) and a Windows one, each item that
    only one of them has marked with `cfg`."""
    unix = compute_model(unix_gir, glib_gir, gobject_gir, gio_gir)
    windows = compute_model(windows_gir, glib_gir, gobject_gir, gio_gir)
    return platforms.merge(unix, windows, only_primary="not(windows)", only_other="windows")
