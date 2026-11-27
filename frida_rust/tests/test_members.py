#
# Copyright © 2026 Kirby Kuehl
#
# Licence: wxWindows Library Licence, Version 3.1
#
"""The core's members, as the code generator reads them: made by the core through
`model.FACTORY`, with what the core leaves out read from their elements."""
import unittest

import frida_bindgen_core as core

from frida_rust import model as m
from frida_rust.model import UnsupportedConstruct

from .fragments import THING, compute_model, gir


def thing(fragment: bytes = THING):
    return compute_model(gir(fragment)).frida_object_types["Thing"]


def without_sync_form(fragment: bytes) -> bytes:
    start = fragment.index(b'<method name="poke_sync"')
    end = fragment.index(b"</method>", start) + len(b"</method>")
    return fragment[:start] + fragment[end:]


class MembersTest(unittest.TestCase):
    def test_the_members_are_the_cores(self):
        t = thing()
        self.assertEqual([x.name for x in t.methods], ["get_label", "set_label", "get_names", "poke"])
        for item, cls in (
            (t.methods[0], core.Method),
            (t.constructors[0], core.Constructor),
            (t.properties[0], core.Property),
            (t.signals[0], core.Signal),
            (t.methods[1].parameters[0], core.Parameter),
            (t.methods[0].return_value, core.ReturnValue),
        ):
            self.assertIsInstance(item, cls)
        self.assertIsInstance(t.methods[0], m.Method)
        self.assertIsNone(t.methods[0].supplement)

    def test_each_member_has_its_element(self):
        t = thing()
        self.assertEqual(m.attr(t.methods[0].element, "c:identifier"), "frida_thing_get_label")
        self.assertEqual(t.doc, "A thing, see [class@Frida.Thing].")
        self.assertEqual(m.attr(t.properties[0].element, "name"), "label")
        self.assertEqual(m.attr(t.signals[0].parameters[0].element, "name"), "how")

    def test_the_core_gives_ownership_and_nullability(self):
        t = thing()
        get_label = t.methods[0]
        self.assertTrue(get_label.return_value.nullable)
        self.assertEqual(get_label.return_value.transfer, "none")
        set_label = t.methods[1]
        self.assertIsNone(set_label.return_value)
        self.assertTrue(set_label.parameters[0].nullable)
        self.assertTrue(set_label.parameters[0].is_input)

    def test_a_constructor_has_its_return_value(self):
        new = thing().constructors[0]
        self.assertFalse(new.is_function)
        self.assertEqual(new.return_value.type.name, "Frida.Thing")
        self.assertEqual(new.return_value.transfer, "full")

    def test_an_arrays_length_is_the_out_argument_it_names(self):
        get_names = thing().methods[2]
        self.assertEqual(get_names.return_value.type.name, "utf8[]")
        self.assertIs(get_names.return_value.length, get_names.parameters[0])
        # The core knows a string vector's length is no output of its own.
        self.assertEqual(get_names.out_parameters, [])

    def test_a_signal_returns_nothing(self):
        self.assertIsNone(thing().signals[0].return_type)


class SyncFormTest(unittest.TestCase):
    def test_an_async_method_calls_its_sync_form(self):
        poke = thing().methods[3]
        self.assertTrue(poke.is_async)
        self.assertEqual(poke.finish_c_identifier, "frida_thing_poke_finish")
        self.assertEqual(poke.blocking_c_identifier, "frida_thing_poke_sync")
        # The shape is the core's: its arguments without the callback, and its result
        # and `throws` from the `_finish` form.
        self.assertEqual([p.name for p in poke.parameters], ["cancellable"])
        self.assertEqual(poke.return_value.type.name, "Frida.Kind")
        self.assertTrue(poke.throws)

    def test_a_plain_method_calls_itself(self):
        self.assertEqual(thing().methods[0].blocking_c_identifier, "frida_thing_get_label")

    def test_a_missing_sync_form_is_refused(self):
        poke = thing(without_sync_form(THING)).methods[3]
        with self.assertRaisesRegex(UnsupportedConstruct, "no `poke_sync` form"):
            poke.blocking_c_identifier

    def assert_disagrees(self, old: bytes, new: bytes, message: str) -> None:
        start = THING.index(b'<method name="poke_sync"')
        end = THING.index(b"</method>", start)
        body = THING[start:end]
        self.assertIn(old, body)
        fragment = THING[:start] + body.replace(old, new, 1) + THING[end:]
        poke = thing(fragment).methods[3]
        with self.assertRaisesRegex(UnsupportedConstruct, message):
            poke.blocking_c_identifier

    def test_a_sync_form_taking_other_arguments_is_refused(self):
        self.assert_disagrees(b'name="cancellable"', b'name="canceller"', r"it takes \(canceller\)")

    def test_a_sync_form_of_another_nullability_is_refused(self):
        self.assert_disagrees(b'transfer-ownership="none" nullable="1"', b'transfer-ownership="none"', "it takes")

    def test_a_sync_form_returning_another_type_is_refused(self):
        self.assert_disagrees(
            b'<return-value transfer-ownership="full">\n          <type name="Frida.Kind" c:type="FridaKind" />',
            b'<return-value transfer-ownership="full">\n          <type name="utf8" c:type="gchar*" />',
            "returns another type",
        )

    def test_a_sync_form_with_other_ownership_is_refused(self):
        self.assert_disagrees(
            b'<return-value transfer-ownership="full">', b'<return-value transfer-ownership="none">',
            "returns another type",
        )

    def test_a_sync_form_that_does_not_throw_is_refused(self):
        self.assert_disagrees(b' throws="1"', b"", "throws where")

    def test_a_sync_form_of_another_name_is_refused(self):
        self.assert_disagrees(b'c:identifier="frida_thing_poke_sync"', b'c:identifier="frida_thing_poke_blocking"',
                              "it is frida_thing_poke_blocking")


if __name__ == "__main__":
    unittest.main()
