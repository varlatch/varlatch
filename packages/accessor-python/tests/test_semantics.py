# SPDX-License-Identifier: Apache-2.0
# Contract Semantics version 2 in the Python runtime, held to the golden
# vectors and the portability vectors: the reference implementation's
# verdicts, reasons, and conversions, input for input.
import math
import unittest

from _support import ada_available, check_ada_mode, portability_v2, runtime, semantics_v2


def item(vector: dict) -> dict:
    fields = {"name": "ITEM", "type": vector["type"], "required": {"kind": "never"}}
    if "enumValues" in vector:
        fields["enumValues"] = vector["enumValues"]
    return fields


class ValidateVectors(unittest.TestCase):
    def check(self, vector: dict) -> None:
        ok, result = runtime._parse(item(vector), vector["value"])
        label = f"{vector['type']} {vector['value']!r}"
        if vector.get("internationalizedHost") and not ada_available():
            # Without UTS #46 the value is rejected, never guessed, with the fix named.
            self.assertEqual((ok, result), (False, runtime._IDN_REASON), label)
            return
        if not vector["valid"]:
            self.assertEqual((ok, result), (False, vector["reason"]), label)
            return
        self.assertTrue(ok, f"{label}: {result}")
        expected = vector["converted"]
        if "number" in expected:
            text = expected["number"]
            self.assertIsInstance(result, (int, float), label)
            self.assertNotIsInstance(result, bool, label)
            if "." in vector["value"]:
                self.assertIsInstance(result, float, label)
                self.assertEqual(result, float(text), label)
                self.assertEqual(math.copysign(1, result), math.copysign(1, float(text)), f"{label}: sign of zero")
            else:
                # Integral text is an int; int has no negative zero, so -0 is 0.
                self.assertIs(type(result), int, label)
                self.assertEqual(result, float(text), label)
        elif "boolean" in expected:
            self.assertIs(result, expected["boolean"], label)
        else:
            self.assertEqual(result, expected["string"], label)
            self.assertIs(type(result), str, label)

    def test_golden_vectors(self) -> None:
        data = semantics_v2()
        self.assertEqual(data["semanticsVersion"], 2)
        for vector in data["validate"]:
            with self.subTest(type=vector["type"], value=vector["value"]):
                self.check(vector)

    def test_portability_vectors(self) -> None:
        data = portability_v2()
        self.assertEqual(data["semanticsVersion"], 2)
        for vector in data["validate"]:
            with self.subTest(type=vector["type"], value=vector["value"]):
                self.check(vector)

    def test_the_dependency_mode_is_the_one_ci_asked_for(self) -> None:
        check_ada_mode(self)

    def test_no_reason_contains_a_fragment_of_the_value(self) -> None:
        for vector in semantics_v2()["validate"] + portability_v2()["validate"]:
            ok, reason = runtime._parse(item(vector), vector["value"])
            if ok or vector["type"] == "enum":
                continue
            value = vector["value"]
            for i in range(len(value) - 3):
                self.assertNotIn(value[i : i + 4], reason, repr(value))


class RequiredVectors(unittest.TestCase):
    def test_golden_vectors(self) -> None:
        for vector in semantics_v2()["required"]:
            subject = {"name": "ITEM", "type": "string", "required": vector["required"]}
            if "defaultValue" in vector:
                subject["defaultValue"] = vector["defaultValue"]
            with self.subTest(vector=vector):
                self.assertIs(runtime._required_applies(subject, vector["environment"]), vector["requiredApplies"])
                self.assertIs(runtime._missing_when_absent(subject, vector["environment"]), vector["missingWhenAbsent"])

    def test_an_empty_default_still_satisfies_requiredness(self) -> None:
        subject = {"name": "ITEM", "type": "string", "required": {"kind": "always"}, "defaultValue": ""}
        self.assertFalse(runtime._missing_when_absent(subject, {"rootId": "env_a", "tier": "production"}))


class Numbers(unittest.TestCase):
    def test_the_bound_is_checked_on_the_exact_digits(self) -> None:
        cases = {
            "9007199254740991": (True, 9007199254740991),
            "-9007199254740991": (True, -9007199254740991),
            "9007199254740991.0": (True, 9007199254740991.0),
            "9007199254740991.5": (False, "must be a number no larger in magnitude than 2^53 - 1"),
            "9007199254740992": (False, "must be a number no larger in magnitude than 2^53 - 1"),
            "0009007199254740991": (True, 9007199254740991),
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(runtime._parse_number(text), expected)

    def test_integral_text_is_an_int_and_a_fraction_a_float(self) -> None:
        self.assertIs(type(runtime._parse_number("3000")[1]), int)
        self.assertIs(type(runtime._parse_number("3000.0")[1]), float)
        self.assertEqual(runtime._parse_number("-0"), (True, 0))


if __name__ == "__main__":
    unittest.main()
