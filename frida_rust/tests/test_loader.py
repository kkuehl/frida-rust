#
# Copyright © 2026 Kirby Kuehl
#
# Licence: wxWindows Library Licence, Version 3.1
#
import unittest

import frida_bindgen_core as core

from frida_rust import model as m
from frida_rust.model import UnsupportedConstruct

from .fragments import THING, UNIX_ONLY, compute_model, gir, load


class LoaderTest(unittest.TestCase):
    def setUp(self):
        self.model = compute_model(gir(THING))

    def test_namespace(self):
        self.assertEqual(self.model.namespace.name, "Frida")
        self.assertEqual(self.model.namespace.identifier_prefixes, "Frida")

    def test_the_model_is_the_cores(self):
        self.assertIsInstance(self.model, core.Model)
        thing = self.model.frida_object_types["Thing"]
        self.assertIsInstance(thing, core.ClassObjectType)
        self.assertIsInstance(thing, m.ClassObjectType)
        # The core resolves the parent into GObject's model, and holds GObject.Object
        # beside Frida's own types; frida_object_types is Frida's alone.
        self.assertEqual(thing.parent.c_type, "GObject")
        self.assertIn("Object", self.model.object_types)
        self.assertNotIn("Object", self.model.frida_object_types)

    def test_class(self):
        thing = self.model.frida_object_types["Thing"]
        self.assertEqual(thing.kind, "class")
        self.assertEqual(thing.c_type, "FridaThing")
        self.assertEqual(thing.get_type, "frida_thing_get_type")
        self.assertEqual(thing.parent_name, "GObject.Object")
        self.assertTrue(thing.final)
        self.assertEqual(thing.doc, "A thing, see [class@Frida.Thing].")
        self.assertEqual([c.c_identifier for c in thing.constructors], ["frida_thing_new"])
        self.assertEqual([m.name for m in thing.every_method], ["get_label", "set_label", "get_names", "poke"])
        self.assertEqual([p.name for p in thing.every_property], ["label"])
        self.assertTrue(thing.every_property[0].writable)
        self.assertEqual([s.name for s in thing.signals], ["poked"])

    def test_the_core_folds_the_forms_of_an_async_method_into_it(self):
        thing = self.model.frida_object_types["Thing"]
        # poke stands for poke_finish and poke_sync, which the core leaves out.
        self.assertEqual([m.name for m in thing.methods], ["get_label", "set_label", "get_names", "poke"])
        self.assertIsNone(thing.method("poke_sync"))
        self.assertEqual(m.attr(thing.method("poke").sync_element, "name"), "poke_sync")

    def test_ownership(self):
        thing = self.model.frida_object_types["Thing"]
        self.assertEqual(thing.constructors[0].return_value.transfer, "full")
        get_label = thing.method("get_label")
        self.assertEqual(get_label.return_value.transfer, "none")
        self.assertTrue(get_label.return_value.nullable)
        set_label = thing.method("set_label")
        self.assertTrue(set_label.parameters[0].nullable)
        self.assertIsNone(set_label.return_value)

    def test_arrays_and_out_parameters(self):
        get_names = self.model.frida_object_types["Thing"].method("get_names")
        rv = get_names.return_value
        self.assertEqual(rv.type.name, "utf8[]")
        self.assertIs(rv.length, get_names.parameters[0])
        self.assertEqual(rv.transfer, "full")
        self.assertEqual(get_names.parameters[0].direction, core.Direction.OUT)

    def test_async_parameters(self):
        poke = self.model.frida_object_types["Thing"].method("poke")
        # The core leaves out the callback and its user data, and reads the result and
        # `throws` from poke_finish.
        self.assertEqual([p.name for p in poke.parameters], ["cancellable"])
        self.assertTrue(poke.is_async)
        self.assertTrue(poke.throws)

    def test_enumerations_and_error_domain(self):
        kind = self.model.frida_enumerations["Kind"]
        self.assertIsInstance(kind, m.Enumeration)
        self.assertEqual([(m.name, m.value) for m in kind.members], [("gentle", 0), ("firm", 1)])
        self.assertIsNone(kind.error_domain)
        # The core keeps the error domain out of `enumerations`; frida_enumerations has
        # every one, in the GIR's order.
        self.assertEqual(list(self.model.enumerations), ["Kind"])
        self.assertEqual(list(self.model.frida_enumerations), ["Kind", "Error"])
        self.assertEqual(self.model.error_domain.name, "Error")
        self.assertEqual(self.model.error_domain.error_domain, "frida-error-quark")

    def test_a_second_error_domain_is_refused(self):
        second = THING.replace(b'name="Error" c:type="FridaError"', b'name="Fault" c:type="FridaFault"').replace(
            b'name="Thing"', b'name="Other"').replace(b'name="Kind"', b'name="Sort"').replace(
            b'name="ThingClass"', b'name="OtherClass"')
        model = compute_model(gir(THING, second))
        with self.assertRaises(UnsupportedConstruct) as caught:
            model.frida_enumerations
        self.assertIn("a second error domain", str(caught.exception))

    def test_records(self):
        self.assertEqual(self.model.records["ThingClass"].gtype_struct_for, "Thing")

    def test_what_the_core_refuses_is_an_unsupported_construct(self):
        orphan = THING.replace(b'parent="GObject.Object"', b'parent="Json.Node"')
        with self.assertRaises(UnsupportedConstruct) as caught:
            compute_model(gir(orphan))
        self.assertIn("frida_bindgen_core: unable to resolve namespace Json", str(caught.exception))


class StrictnessTest(unittest.TestCase):
    def assertRefused(self, fragment: bytes, fragment_text: str):
        with self.assertRaises(UnsupportedConstruct) as caught:
            compute_model(gir(fragment))
        self.assertIn(fragment_text, str(caught.exception))

    def test_unknown_toplevel_element(self):
        self.assertRefused(
            b'<bitfield name="Flags" c:type="FridaFlags"><member name="a" c:identifier="A" value="1"/></bitfield>',
            "unknown element <bitfield>",
        )

    def test_unknown_attribute(self):
        fragment = THING.replace(
            b'<parameter name="result_length1" direction="out"',
            b'<parameter name="result_length1" direction="out" caller-allocates="1"',
        )
        self.assertRefused(fragment, "unknown attribute caller-allocates")

    def test_unknown_xml_namespace(self):
        fragment = THING.replace(b'<method name="get_label"', b'<method xmlns:x="urn:x" x:new="1" name="get_label"')
        self.assertRefused(fragment, "unknown XML namespace urn:x")

    def test_varargs(self):
        fragment = THING.replace(
            b'<type name="utf8" c:type="const gchar*" />\n          </parameter>',
            b"<varargs />\n          </parameter>",
            1,
        )
        self.assertRefused(fragment, "unknown element <varargs>")

    def test_unknown_transfer(self):
        fragment = THING.replace(
            b'<return-value transfer-ownership="none" nullable="1">',
            b'<return-value transfer-ownership="floating" nullable="1">',
        )
        self.assertRefused(fragment, "transfer-ownership='floating'")

    def test_a_flag_other_than_0_or_1(self):
        self.assertRefused(THING.replace(b'final="1"', b'final="yes"'), "final='yes' is not 0 or 1")

    def test_an_unexpected_child(self):
        fragment = THING.replace(
            b'<property name="label" writable="1">',
            b'<property name="label" writable="1">\n        <implements name="Frida.Other" />',
        )
        self.assertRefused(fragment, "<property> has unexpected child <implements>")

    def test_arrays_of_arrays(self):
        fragment = THING.replace(
            b'<type name="utf8" c:type="gchar*" />\n          </array>',
            b'<array><type name="utf8" c:type="gchar*" /></array>\n          </array>',
        )
        self.assertRefused(fragment, "arrays of arrays")

    def test_a_method_without_an_instance_parameter(self):
        start = THING.index(b"<instance-parameter")
        end = THING.index(b"</instance-parameter>", start) + len(b"</instance-parameter>")
        self.assertRefused(THING[:start] + THING[end:], "Frida.Thing.get_label: method without an instance parameter")

    def test_an_instance_parameter_that_is_handed_over(self):
        fragment = THING.replace(
            b'<instance-parameter name="self" transfer-ownership="none">',
            b'<instance-parameter name="self" transfer-ownership="full">', 1,
        )
        self.assertRefused(fragment, "Frida.Thing.get_label: an instance parameter that is not transfer-ownership=none")

    def test_duplicate_definition(self):
        self.assertRefused(THING + THING, "defined twice")


class MergeTest(unittest.TestCase):
    def test_items_on_one_side_get_that_sides_cfg(self):
        merged = load(gir(THING, UNIX_ONLY), gir(THING))
        self.assertEqual(merged.frida_enumerations["WaitKind"].cfg, "not(windows)")
        self.assertIsNone(merged.frida_enumerations["Kind"].cfg)
        self.assertIsNone(merged.frida_object_types["Thing"].cfg)
        self.assertTrue(all(m.cfg is None for m in merged.frida_object_types["Thing"].every_method))

    def test_windows_only_members(self):
        merged = load(gir(THING), gir(THING.replace(
            b'<member name="firm" c:identifier="FRIDA_KIND_FIRM" value="1" />',
            b'<member name="firm" c:identifier="FRIDA_KIND_FIRM" value="1" />\n'
            b'      <member name="win" c:identifier="FRIDA_KIND_WIN" value="2" />',
        )))
        members = {m.name: m.cfg for m in merged.frida_enumerations["Kind"].members}
        self.assertEqual(members, {"gentle": None, "firm": None, "win": "windows"})

    def test_windows_only_class_and_method(self):
        other = (
            THING.replace(b'name="Thing"', b'name="Other"').replace(b'c:type="FridaThing"', b'c:type="FridaOther"')
            .replace(b"frida_thing_get_type", b"frida_other_get_type")
        )
        other = other[: other.index(b"<record")]  # the class alone
        windows = gir(THING.replace(b'<method name="get_names"', b'<method name="get_names_too"', 1)
                      .replace(b"frida_thing_get_names", b"frida_thing_get_names_too", 1), other)
        merged = load(gir(THING), windows)
        self.assertEqual(merged.frida_object_types["Other"].cfg, "windows")
        self.assertEqual(merged.frida_object_types["Other"].method("get_label").c_identifier, "frida_thing_get_label")
        methods = {m.name: m.cfg for m in merged.frida_object_types["Thing"].every_method}
        self.assertEqual(methods["get_names"], "not(windows)")
        self.assertEqual(methods["get_names_too"], "windows")
        self.assertIsNone(methods["poke"])

    def test_an_item_that_differs_is_refused(self):
        with self.assertRaises(UnsupportedConstruct) as caught:
            load(gir(THING), gir(THING.replace(
                b'<return-value transfer-ownership="none" nullable="1">',
                b'<return-value transfer-ownership="full" nullable="1">',
            )))
        self.assertIn("Frida.Thing.get_label: differs between platforms", str(caught.exception))

    def test_a_class_that_differs_is_refused(self):
        with self.assertRaises(UnsupportedConstruct) as caught:
            load(gir(THING), gir(THING.replace(b'final="1"', b'final="0"')))
        self.assertIn("Frida.Thing: differs between platforms", str(caught.exception))

    def test_docs_and_line_endings_do_not_count_as_differences(self):
        merged = load(gir(THING), gir(THING).replace(b"\n", b"\r\n").replace(b"A thing", b"One thing"))
        self.assertIn("Thing", merged.frida_object_types)


if __name__ == "__main__":
    unittest.main()
