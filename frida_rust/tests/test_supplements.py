#
# Copyright © 2026 Kirby Kuehl
#
# Licence: wxWindows Library Licence, Version 3.1
#
"""What frida_rust.supplements reads of what the core leaves out: each kind, made as the
core's classes and marked with its kind."""
import unittest

import frida_bindgen_core as core

from frida_rust import model as m

from .fragments import THING, compute_model, gir

OPTIONS_HOLDER = b"""
    <class name="Holder" c:type="FridaHolder" glib:type-name="FridaHolder" glib:get-type="frida_holder_get_type"
           parent="GObject.Object">
      <method name="get_options" c:identifier="frida_holder_get_options">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.Holder" c:type="FridaHolder*" />
          </instance-parameter>
        </parameters>
        <return-value transfer-ownership="none">
          <type name="Frida.HolderOptions" c:type="FridaHolderOptions*" />
        </return-value>
      </method>
      <property name="name">
        <type name="utf8" c:type="gchar*" />
      </property>
      <property name="options" construct-only="1">
        <type name="Frida.HolderOptions" c:type="FridaHolderOptions*" />
      </property>
    </class>
    <class name="HolderOptions" c:type="FridaHolderOptions" glib:type-name="FridaHolderOptions"
           glib:get-type="frida_holder_options_get_type" parent="GObject.Object" />
"""


FINDER = b"""
    <class name="Finder" c:type="FridaFinder" glib:type-name="FridaFinder" glib:get-type="frida_finder_get_type"
           parent="GObject.Object">
      <method name="find" c:identifier="frida_finder_find">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.Finder" c:type="FridaFinder*" />
          </instance-parameter>
          <parameter name="predicate" transfer-ownership="none" closure="1" scope="call">
            <type name="Frida.FinderPredicate" c:type="FridaFinderPredicate" />
          </parameter>
          <parameter name="predicate_target" transfer-ownership="none" nullable="1">
            <type name="gpointer" c:type="void*" />
          </parameter>
        </parameters>
        <return-value transfer-ownership="none">
          <type name="gboolean" c:type="gboolean" />
        </return-value>
      </method>
      <method name="each" c:identifier="frida_finder_each">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.Finder" c:type="FridaFinder*" />
          </instance-parameter>
          <parameter name="func" transfer-ownership="none" closure="1" scope="call">
            <type name="GLib.Func" c:type="GFunc" />
          </parameter>
          <parameter name="func_target" transfer-ownership="none" nullable="1">
            <type name="gpointer" c:type="void*" />
          </parameter>
        </parameters>
        <return-value transfer-ownership="none">
          <type name="none" c:type="void" />
        </return-value>
      </method>
    </class>
    <callback name="FinderPredicate" c:type="FridaFinderPredicate">
      <return-value transfer-ownership="none">
        <type name="gboolean" c:type="gboolean" />
      </return-value>
      <parameters>
        <parameter name="name" transfer-ownership="none">
          <type name="utf8" c:type="const gchar*" />
        </parameter>
        <parameter name="user_data" transfer-ownership="none" closure="1">
          <type name="gpointer" c:type="void*" />
        </parameter>
      </parameters>
    </callback>
"""

FUNCTIONS = b"""
    <function name="twice" c:identifier="frida_twice">
      <doc xml:space="preserve">Twice @value.</doc>
      <return-value transfer-ownership="none">
        <type name="gint" c:type="gint" />
      </return-value>
      <parameters>
        <parameter name="value" transfer-ownership="none">
          <type name="gint" c:type="gint" />
        </parameter>
      </parameters>
    </function>
    <function name="from_json" c:identifier="frida_from_json">
      <return-value transfer-ownership="none">
        <type name="none" c:type="void" />
      </return-value>
      <parameters>
        <parameter name="node" transfer-ownership="none">
          <type name="Json.Node" c:type="JsonNode*" />
        </parameter>
      </parameters>
    </function>
"""


class CallbackMethodTest(unittest.TestCase):
    def setUp(self):
        self.model = compute_model(gir(FINDER))
        self.finder = self.model.frida_object_types["Finder"]

    def test_the_core_leaves_them_out(self):
        self.assertEqual(self.finder.methods, [])

    def test_they_are_made_as_the_core_makes_a_method(self):
        find, each = self.finder.every_method
        self.assertIsInstance(find, m.Method)
        self.assertEqual((find.supplement, each.supplement), ("callback-method", "callback-method"))
        self.assertEqual([p.name for p in find.parameters], ["predicate", "predicate_target"])
        self.assertEqual(find.return_value.type.name, "gboolean")
        self.assertFalse(find.is_async)

    def test_a_callback_is_linked_to_its_user_data(self):
        predicate, target = self.finder.every_method[0].parameters
        self.assertIs(predicate.closure, target)
        self.assertEqual(predicate.scope, "call")

    def test_frida_callback_types(self):
        cb = self.model.callback("Frida.FinderPredicate")
        self.assertEqual(cb.supplement, "callback")
        self.assertEqual([p.name for p in cb.parameters], ["name", "user_data"])
        self.assertIs(cb.parameters[1].closure, cb.parameters[1])
        self.assertEqual(cb.return_value.type.name, "gboolean")

    def test_glib_callback_types_come_from_glibs_gir(self):
        cb = self.model.callback("GLib.Func")
        self.assertEqual((cb.name, cb.c_type), ("Func", "GFunc"))
        self.assertEqual([p.name for p in cb.parameters], ["data", "user_data"])
        self.assertIs(cb.parameters[1].closure, cb.parameters[1])
        self.assertIsNone(cb.return_value)

    def test_a_type_that_is_no_callback(self):
        self.assertIsNone(self.model.callback("Gio.Cancellable"))


class FunctionTest(unittest.TestCase):
    def setUp(self):
        self.functions = compute_model(gir(THING, FUNCTIONS)).functions

    def test_a_function_is_read_with_the_cores_readers(self):
        twice = self.functions["twice"]
        self.assertIsInstance(twice, core.Procedure)
        self.assertEqual(twice.supplement, "function")
        self.assertEqual(twice.blocking_c_identifier, "frida_twice")
        self.assertEqual([p.name for p in twice.parameters], ["value"])
        self.assertIsInstance(twice.parameters[0], m.Parameter)
        self.assertEqual(twice.return_value.type.name, "gint")
        self.assertEqual(twice.doc, "Twice @value.")

    def test_one_the_core_cannot_read_is_unreadable(self):
        from_json = self.functions["from_json"]
        self.assertEqual(from_json.supplement, "unreadable")
        self.assertIn("unable to resolve namespace Json", from_json.error)


class UncoveredTest(unittest.TestCase):
    def test_a_class_whose_methods_the_core_cannot_read(self):
        fragment = THING.replace(
            b'<type name="Gio.Cancellable" c:type="GCancellable*" />', b'<type name="Json.Node" c:type="JsonNode*" />', 1
        )
        thing = compute_model(gir(fragment)).frida_object_types["Thing"]
        self.assertIn("Json", thing.methods_error)
        self.assertEqual(thing.every_method, [])
        self.assertEqual(
            [(u.category, u.name) for u in thing.uncovered],
            [("method", n) for n in ("get_label", "set_label", "get_names", "poke", "poke_finish", "poke_sync")],
        )

    def test_a_method_nothing_gives(self):
        # A `_finish` with no async method: the core drops it by its name, and it is no
        # supplement's kind.
        fragment = THING.replace(b'<method name="get_names"', b'<method name="get_names_finish"', 1)
        thing = compute_model(gir(fragment)).frida_object_types["Thing"]
        self.assertEqual([(u.category, u.name) for u in thing.uncovered], [("method", "get_names_finish")])

    def test_everything_covered(self):
        self.assertEqual(compute_model(gir(THING)).frida_object_types["Thing"].uncovered, [])


class VirtualMethodAndRecordTest(unittest.TestCase):
    def test_virtual_methods_are_counted_by_name(self):
        fragment = THING.replace(b"      <property name=\"label\"", b"""      <virtual-method name="prod" invoker="poke">
        <parameters>
          <instance-parameter name="self" transfer-ownership="none">
            <type name="Frida.Thing" c:type="FridaThing*" />
          </instance-parameter>
        </parameters>
        <return-value transfer-ownership="none">
          <type name="none" c:type="void" />
        </return-value>
      </virtual-method>
      <property name="label\"""", 1)
        thing = compute_model(gir(fragment)).frida_object_types["Thing"]
        self.assertEqual([(v.name, v.supplement) for v in thing.virtual_methods], [("prod", "virtual-method")])

    def test_records(self):
        record = compute_model(gir(THING)).records["ThingClass"]
        self.assertEqual((record.c_type, record.gtype_struct_for, record.supplement), ("FridaThingClass", "Thing", "record"))


class CountsTest(unittest.TestCase):
    def test_each_kind_is_counted(self):
        from frida_rust import supplements

        model = compute_model(gir(THING, FINDER, OPTIONS_HOLDER, FUNCTIONS))
        model.callback("GLib.Func")
        counts = supplements.counts(model)
        self.assertEqual(list(counts), list(supplements.KINDS))
        self.assertEqual(counts["callback-method"], 2)
        self.assertEqual(counts["options-getter"], 1)
        self.assertEqual(counts["options-property"], 1)
        self.assertEqual(counts["function"], 1)
        self.assertEqual(counts["unreadable"], 1)
        self.assertEqual(counts["callback"], 2)
        self.assertEqual(counts["record"], 1)
        self.assertEqual(counts["virtual-method"], 0)


class OptionsPropertyTest(unittest.TestCase):
    def setUp(self):
        self.holder = compute_model(gir(OPTIONS_HOLDER)).frida_object_types["Holder"]

    def test_the_core_leaves_it_out(self):
        self.assertEqual([p.name for p in self.holder.properties], ["name"])

    def test_it_is_read_as_the_core_reads_a_property(self):
        self.assertEqual([p.name for p in self.holder.every_property], ["name", "options"])
        name, options = self.holder.every_property
        self.assertIsNone(name.supplement)
        self.assertEqual(options.supplement, "options-property")
        self.assertIsInstance(options, m.Property)
        self.assertEqual(options.type.name, "Frida.HolderOptions")
        self.assertTrue(options.construct_only)
        self.assertEqual(options.getter, "get_options")
        self.assertIsNone(options.setter)

    def test_its_getter_is_an_options_getter(self):
        self.assertEqual(self.holder.methods, [])
        (get_options,) = self.holder.every_method
        self.assertEqual(get_options.supplement, "options-getter")
        self.assertEqual(get_options.return_value.type.name, "Frida.HolderOptions")
        self.assertTrue(get_options.is_property_accessor)


if __name__ == "__main__":
    unittest.main()
