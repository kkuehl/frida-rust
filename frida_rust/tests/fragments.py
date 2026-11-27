#
# Copyright © 2026 Kirby Kuehl
#
# Licence: wxWindows Library Licence, Version 3.1
#
"""Small GIR fragments, in the shape frida-core.gir has, and stand-ins for GLib's,
GObject's and Gio's GIRs that frida_bindgen_core reads them with."""
import tempfile
from pathlib import Path
from typing import Optional

from frida_rust import loader

HEAD = b"""<?xml version="1.0"?>
<repository xmlns="http://www.gtk.org/introspection/core/1.0"
            xmlns:c="http://www.gtk.org/introspection/c/1.0"
            xmlns:glib="http://www.gtk.org/introspection/glib/1.0" version="1.2">
  <include name="Gio" version="2.0" />
  <package name="frida-core" />
  <c:include name="frida-core.h" />
  <namespace name="Frida" version="1.0" c:prefix="Frida" c:identifier-prefixes="Frida" c:symbol-prefixes="frida">
"""
TAIL = b"""
  </namespace>
</repository>
"""

THING = b"""
    <class name="Thing" c:type="FridaThing" glib:type-name="FridaThing" glib:get-type="frida_thing_get_type"
           glib:type-struct="ThingClass" parent="GObject.Object" final="1">
      <doc xml:space="preserve">A thing, see [class@Frida.Thing].</doc>
      <constructor name="new" c:identifier="frida_thing_new">
        <return-value transfer-ownership="full">
          <type name="Frida.Thing" c:type="FridaThing*" />
        </return-value>
      </constructor>
      <method name="get_label" c:identifier="frida_thing_get_label">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.Thing" c:type="FridaThing*" />
          </instance-parameter>
        </parameters>
        <return-value transfer-ownership="none" nullable="1">
          <type name="utf8" c:type="const gchar*" />
        </return-value>
      </method>
      <method name="set_label" c:identifier="frida_thing_set_label">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.Thing" c:type="FridaThing*" />
          </instance-parameter>
          <parameter name="value" transfer-ownership="none" nullable="1">
            <type name="utf8" c:type="const gchar*" />
          </parameter>
        </parameters>
        <return-value transfer-ownership="none">
          <type name="none" c:type="void" />
        </return-value>
      </method>
      <method name="get_names" c:identifier="frida_thing_get_names">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.Thing" c:type="FridaThing*" />
          </instance-parameter>
          <parameter name="result_length1" direction="out" transfer-ownership="none">
            <type name="gint" c:type="gint*" />
          </parameter>
        </parameters>
        <return-value transfer-ownership="full">
          <array length="0" c:type="gchar**">
            <type name="utf8" c:type="gchar*" />
          </array>
        </return-value>
      </method>
      <method name="poke" c:identifier="frida_thing_poke">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.Thing" c:type="FridaThing*" />
          </instance-parameter>
          <parameter name="cancellable" transfer-ownership="none" nullable="1">
            <type name="Gio.Cancellable" c:type="GCancellable*" />
          </parameter>
          <parameter name="_callback_" transfer-ownership="none" nullable="1" scope="async" closure="2">
            <type name="Gio.AsyncReadyCallback" c:type="GAsyncReadyCallback" />
          </parameter>
          <parameter name="_callback__target" transfer-ownership="none" nullable="1">
            <type name="gpointer" c:type="void*" />
          </parameter>
        </parameters>
        <return-value transfer-ownership="none">
          <type name="none" c:type="void" />
        </return-value>
      </method>
      <method name="poke_finish" c:identifier="frida_thing_poke_finish" throws="1">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.Thing" c:type="FridaThing*" />
          </instance-parameter>
          <parameter name="_res_" transfer-ownership="none">
            <type name="Gio.AsyncResult" c:type="GAsyncResult*" />
          </parameter>
        </parameters>
        <return-value transfer-ownership="full">
          <type name="Frida.Kind" c:type="FridaKind" />
        </return-value>
      </method>
      <method name="poke_sync" c:identifier="frida_thing_poke_sync" throws="1">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.Thing" c:type="FridaThing*" />
          </instance-parameter>
          <parameter name="cancellable" transfer-ownership="none" nullable="1">
            <type name="Gio.Cancellable" c:type="GCancellable*" />
          </parameter>
        </parameters>
        <return-value transfer-ownership="full">
          <type name="Frida.Kind" c:type="FridaKind" />
        </return-value>
      </method>
      <property name="label" writable="1">
        <type name="utf8" c:type="gchar*" />
      </property>
      <glib:signal name="poked">
        <parameters>
          <parameter name="how" transfer-ownership="none">
            <type name="Frida.Kind" c:type="FridaKind" />
          </parameter>
        </parameters>
        <return-value transfer-ownership="full">
          <type name="none" c:type="void" />
        </return-value>
      </glib:signal>
    </class>
    <record name="ThingClass" c:type="FridaThingClass" glib:is-gtype-struct-for="Thing" />
    <enumeration name="Kind" c:type="FridaKind" glib:type-name="FridaKind" glib:get-type="frida_kind_get_type">
      <member name="gentle" c:identifier="FRIDA_KIND_GENTLE" value="0" />
      <member name="firm" c:identifier="FRIDA_KIND_FIRM" value="1" />
    </enumeration>
    <enumeration name="Error" c:type="FridaError" glib:type-name="FridaError" glib:get-type="frida_error_get_type"
                 glib:error-domain="frida-error-quark">
      <member name="not_supported" c:identifier="FRIDA_ERROR_NOT_SUPPORTED" value="10" />
    </enumeration>
"""

UNIX_ONLY = b"""
    <enumeration name="WaitKind" c:type="FridaWaitKind" glib:type-name="FridaWaitKind" glib:get-type="frida_wait_kind_get_type">
      <member name="exited" c:identifier="FRIDA_WAIT_KIND_EXITED" value="0" />
    </enumeration>
"""


def gir(*parts: bytes) -> bytes:
    return HEAD + b"".join(parts) + TAIL


def _dependency(name: bytes, prefix: bytes, body: bytes = b"") -> bytes:
    return b"""<?xml version="1.0"?>
<repository xmlns="http://www.gtk.org/introspection/core/1.0"
            xmlns:c="http://www.gtk.org/introspection/c/1.0"
            xmlns:glib="http://www.gtk.org/introspection/glib/1.0" version="1.2">
  <namespace name="%s" version="2.0" c:identifier-prefixes="%s" c:symbol-prefixes="%s">%s
  </namespace>
</repository>
""" % (name, prefix, prefix.lower(), body)


# What the core resolves in the fragments, declared as GLib's, GObject's and Gio's GIRs
# declare it: each foreign type Frida's GIR names (customization.FOREIGN_OBJECTS and
# FOREIGN_ENUMS, the boxed types, the GLib callbacks) and the parents, all GObject.Object.
_GPOINTER = b'<type name="gpointer" c:type="gpointer"/>'


def _callback(name: bytes, params: bytes, returns: bytes = b'<type name="none" c:type="void"/>') -> bytes:
    return b"""
    <callback name="%s" c:type="G%s">
      <return-value transfer-ownership="none">%s</return-value>
      <parameters>%s</parameters>
    </callback>""" % (name, name, returns, params)


def _pointer(name: bytes, closure: bytes = b"") -> bytes:
    extra = b' nullable="1" closure="%s"' % closure if closure else b""
    return b'<parameter name="%s" transfer-ownership="none"%s>%s</parameter>' % (name, extra, _GPOINTER)


DEPENDENCIES = {
    "GLib-2.0.gir": _dependency(b"GLib", b"G", b"""
    <record name="Bytes" c:type="GBytes" copy-function="g_bytes_ref" free-function="g_bytes_unref" />
    <record name="Variant" c:type="GVariant" copy-function="g_variant_ref_sink" free-function="g_variant_unref" />
    <record name="HashTable" c:type="GHashTable" glib:get-type="g_hash_table_get_type" />""" + b"".join([
        _callback(b"Func", _pointer(b"data") + _pointer(b"user_data", b"1")),
        _callback(b"HFunc", _pointer(b"key") + _pointer(b"value") + _pointer(b"user_data", b"2")),
        _callback(b"SourceFunc", _pointer(b"user_data", b"0"), b'<type name="gboolean" c:type="gboolean"/>'),
        _callback(b"DestroyNotify", _pointer(b"data")),
    ])),
    "GObject-2.0.gir": _dependency(b"GObject", b"G", b"""
    <class name="Object" c:type="GObject" glib:type-name="GObject" glib:get-type="g_object_get_type"
           glib:type-struct="ObjectClass" />"""),
    "Gio-2.0.gir": _dependency(b"Gio", b"G", b"""
    <class name="Cancellable" c:type="GCancellable" glib:get-type="g_cancellable_get_type" parent="GObject.Object" />
    <class name="SocketAddress" c:type="GSocketAddress" glib:get-type="g_socket_address_get_type" parent="GObject.Object" />
    <class name="IOStream" c:type="GIOStream" glib:get-type="g_io_stream_get_type" parent="GObject.Object" />
    <class name="TlsCertificate" c:type="GTlsCertificate" glib:get-type="g_tls_certificate_get_type" parent="GObject.Object" />
    <interface name="File" c:type="GFile" glib:get-type="g_file_get_type" />
    <interface name="AsyncResult" c:type="GAsyncResult" glib:get-type="g_async_result_get_type" />
    <enumeration name="FileMonitorEvent" c:type="GFileMonitorEvent" glib:get-type="g_file_monitor_event_get_type" />
    <callback name="AsyncReadyCallback" c:type="GAsyncReadyCallback" />"""),
}


def _write(directory: Path, name: str, text: bytes) -> Path:
    path = directory / name
    path.write_bytes(text)
    return path


def write_girs(directory: Path, unix: bytes, windows: Optional[bytes] = None) -> dict:
    """The fragments and the stand-ins as files in `directory`: their paths by role."""
    paths = {role: _write(directory, name, text) for role, (name, text) in {
        "glib": ("GLib-2.0.gir", DEPENDENCIES["GLib-2.0.gir"]),
        "gobject": ("GObject-2.0.gir", DEPENDENCIES["GObject-2.0.gir"]),
        "gio": ("Gio-2.0.gir", DEPENDENCIES["Gio-2.0.gir"]),
    }.items()}
    paths["unix"] = _write(directory, "unix.gir", unix)
    paths["windows"] = _write(directory, "windows.gir", unix if windows is None else windows)
    return paths


def compute_model(frida: bytes):
    """The model of one Frida GIR, as `loader.compute_model` makes it. The files can go
    once it is made: the core keeps the parsed elements."""
    with tempfile.TemporaryDirectory() as tmp:
        p = write_girs(Path(tmp), frida)
        model = loader.compute_model(p["unix"], p["glib"], p["gobject"], p["gio"])
        return model


def load(unix: bytes, windows: Optional[bytes] = None):
    """The merged model of a Unix and a Windows GIR, as `loader.load` makes it."""
    with tempfile.TemporaryDirectory() as tmp:
        p = write_girs(Path(tmp), unix, windows)
        model = loader.load(p["unix"], p["windows"], p["glib"], p["gobject"], p["gio"])
        return model


def method(name: str, param_type: bytes, transfer: bytes = b"none") -> bytes:
    """A class holding one method taking one argument of `param_type`."""
    return b"""
    <class name="Odd" c:type="FridaOdd" glib:type-name="FridaOdd" glib:get-type="frida_odd_get_type" parent="GObject.Object">
      <method name="%s" c:identifier="frida_odd_%s">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.Odd" c:type="FridaOdd*" />
          </instance-parameter>
          <parameter name="value" transfer-ownership="%s">
            %s
          </parameter>
        </parameters>
        <return-value transfer-ownership="none">
          <type name="none" c:type="void" />
        </return-value>
      </method>
    </class>
""" % (name.encode(), name.encode(), transfer, param_type)


def emitter(arg_type: bytes, plain_method: bool = False) -> bytes:
    """A class with read-only state, one signal taking one argument of `arg_type`, and,
    if asked, a plain method that is not a property accessor."""
    plain = b"""
      <method name="tweak" c:identifier="frida_emitter_tweak">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.Emitter" c:type="FridaEmitter*" />
          </instance-parameter>
        </parameters>
        <return-value transfer-ownership="none">
          <type name="none" c:type="void" />
        </return-value>
      </method>""" if plain_method else b""
    return b"""
    <class name="Emitter" c:type="FridaEmitter" glib:type-name="FridaEmitter" glib:get-type="frida_emitter_get_type" parent="GObject.Object">%s
      <glib:signal name="went-off">
        <doc xml:space="preserve">Emitted when it goes off.</doc>
        <parameters>
          <parameter name="what" transfer-ownership="none">
            %s
          </parameter>
        </parameters>
        <return-value transfer-ownership="full">
          <type name="none" c:type="void" />
        </return-value>
      </glib:signal>
    </class>
""" % (plain, arg_type)


def handle_thing() -> bytes:
    """THING with its property read-only: a handle, not a value."""
    start = THING.index(b'      <method name="set_label"')
    end = THING.index(b"</method>", start) + len(b"</method>\n")
    return (THING[:start] + THING[end:]).replace(
        b'<property name="label" writable="1">', b'<property name="label">'
    )


# A value class: writable properties, a parameterless constructor, a collection.
OPTIONS = b"""
    <class name="TweakOptions" c:type="FridaTweakOptions" glib:type-name="FridaTweakOptions"
           glib:get-type="frida_tweak_options_get_type" parent="GObject.Object" final="1">
      <doc xml:space="preserve">How to tweak.</doc>
      <constructor name="new" c:identifier="frida_tweak_options_new">
        <return-value transfer-ownership="full">
          <type name="Frida.TweakOptions" c:type="FridaTweakOptions*" />
        </return-value>
      </constructor>
      <method name="get_name" c:identifier="frida_tweak_options_get_name">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.TweakOptions" c:type="FridaTweakOptions*" />
          </instance-parameter>
        </parameters>
        <return-value transfer-ownership="none" nullable="1">
          <type name="utf8" c:type="const gchar*" />
        </return-value>
      </method>
      <method name="set_name" c:identifier="frida_tweak_options_set_name">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.TweakOptions" c:type="FridaTweakOptions*" />
          </instance-parameter>
          <parameter name="value" transfer-ownership="none" nullable="1">
            <type name="utf8" c:type="const gchar*" />
          </parameter>
        </parameters>
        <return-value transfer-ownership="none">
          <type name="none" c:type="void" />
        </return-value>
      </method>
      <method name="get_depth" c:identifier="frida_tweak_options_get_depth">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.TweakOptions" c:type="FridaTweakOptions*" />
          </instance-parameter>
        </parameters>
        <return-value transfer-ownership="none">
          <type name="guint" c:type="guint" />
        </return-value>
      </method>
      <method name="set_depth" c:identifier="frida_tweak_options_set_depth">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.TweakOptions" c:type="FridaTweakOptions*" />
          </instance-parameter>
          <parameter name="value" transfer-ownership="none">
            <type name="guint" c:type="guint" />
          </parameter>
        </parameters>
        <return-value transfer-ownership="none">
          <type name="none" c:type="void" />
        </return-value>
      </method>
      <method name="get_wait" c:identifier="frida_tweak_options_get_wait">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.TweakOptions" c:type="FridaTweakOptions*" />
          </instance-parameter>
        </parameters>
        <return-value transfer-ownership="none">
          <type name="gint" c:type="gint" />
        </return-value>
      </method>
      <method name="set_wait" c:identifier="frida_tweak_options_set_wait">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.TweakOptions" c:type="FridaTweakOptions*" />
          </instance-parameter>
          <parameter name="value" transfer-ownership="none">
            <type name="gint" c:type="gint" />
          </parameter>
        </parameters>
        <return-value transfer-ownership="none">
          <type name="none" c:type="void" />
        </return-value>
      </method>
      <method name="add_tag" c:identifier="frida_tweak_options_add_tag">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.TweakOptions" c:type="FridaTweakOptions*" />
          </instance-parameter>
          <parameter name="tag" transfer-ownership="none">
            <type name="utf8" c:type="const gchar*" />
          </parameter>
        </parameters>
        <return-value transfer-ownership="none">
          <type name="none" c:type="void" />
        </return-value>
      </method>
      <property name="name" writable="1">
        <doc xml:space="preserve">What to call it.</doc>
        <type name="utf8" c:type="gchar*" />
      </property>
      <property name="depth" writable="1">
        <type name="guint" c:type="guint" />
      </property>
      <property name="wait" writable="1" default-value="0">
        <type name="gint" c:type="gint" />
      </property>
    </class>
"""


def owner_and_list() -> bytes:
    """A class with a blocking close and a list of itself returned by a static function."""
    def sync_pair(name: str, ret: bytes) -> bytes:
        return (b"""
      <method name="%(n)s" c:identifier="frida_tool_%(n)s">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.Tool" c:type="FridaTool*" />
          </instance-parameter>
          <parameter name="cancellable" transfer-ownership="none" nullable="1">
            <type name="Gio.Cancellable" c:type="GCancellable*" />
          </parameter>
          <parameter name="_callback_" transfer-ownership="none" nullable="1" scope="async" closure="2">
            <type name="Gio.AsyncReadyCallback" c:type="GAsyncReadyCallback" />
          </parameter>
          <parameter name="_callback__target" transfer-ownership="none" nullable="1">
            <type name="gpointer" c:type="void*" />
          </parameter>
        </parameters>
        <return-value transfer-ownership="none"><type name="none" c:type="void" /></return-value>
      </method>
      <method name="%(n)s_finish" c:identifier="frida_tool_%(n)s_finish" throws="1">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.Tool" c:type="FridaTool*" />
          </instance-parameter>
          <parameter name="_res_" transfer-ownership="none">
            <type name="Gio.AsyncResult" c:type="GAsyncResult*" />
          </parameter>
        </parameters>
        <return-value transfer-ownership="full">%(r)s</return-value>
      </method>
      <method name="%(n)s_sync" c:identifier="frida_tool_%(n)s_sync" throws="1">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.Tool" c:type="FridaTool*" />
          </instance-parameter>
          <parameter name="cancellable" transfer-ownership="none" nullable="1">
            <type name="Gio.Cancellable" c:type="GCancellable*" />
          </parameter>
        </parameters>
        <return-value transfer-ownership="full">%(r)s</return-value>
      </method>""" % {b"n": name.encode(), b"r": ret})
    return b"""
    <class name="Tool" c:type="FridaTool" glib:type-name="FridaTool" glib:get-type="frida_tool_get_type"
           parent="GObject.Object" final="1">
      <constructor name="new" c:identifier="frida_tool_new">
        <return-value transfer-ownership="full">
          <type name="Frida.Tool" c:type="FridaTool*" />
        </return-value>
      </constructor>""" + sync_pair("close", b'<type name="none" c:type="void" />') + sync_pair(
        "siblings", b'<type name="Frida.ToolList" c:type="FridaToolList*" />'
    ) + b"""
    </class>
    <class name="ToolList" c:type="FridaToolList" glib:type-name="FridaToolList" glib:get-type="frida_tool_list_get_type"
           parent="GObject.Object" final="1">
      <method name="size" c:identifier="frida_tool_list_size">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.ToolList" c:type="FridaToolList*" />
          </instance-parameter>
        </parameters>
        <return-value transfer-ownership="none"><type name="gint" c:type="gint" /></return-value>
      </method>
      <method name="get" c:identifier="frida_tool_list_get">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.ToolList" c:type="FridaToolList*" />
          </instance-parameter>
          <parameter name="index" transfer-ownership="none"><type name="gint" c:type="gint" /></parameter>
        </parameters>
        <return-value transfer-ownership="full"><type name="Frida.Tool" c:type="FridaTool*" /></return-value>
      </method>
    </class>
"""
