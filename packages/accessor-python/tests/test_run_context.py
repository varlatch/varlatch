# SPDX-License-Identifier: Apache-2.0
# VARLATCH_RUN_CONTEXT parsing, held to the language-neutral vectors that the
# TypeScript accessor passes too.
import unittest

from _support import run_context_v1, runtime


class RunContextVectors(unittest.TestCase):
    def test_version(self) -> None:
        self.assertEqual(run_context_v1()["v"], 1)

    def test_valid(self) -> None:
        for vector in run_context_v1()["valid"]:
            with self.subTest(note=vector["note"]):
                parsed = runtime._parse_run_context(vector["raw"])
                self.assertIsInstance(parsed, runtime._RunContext, parsed)
                expected = vector["parsed"]
                self.assertEqual(parsed.mode, expected["mode"])
                self.assertEqual(parsed.contract_revision_id, expected["contractRevisionId"])
                self.assertEqual(parsed.contract_hash, expected["contractHash"])
                self.assertEqual(parsed.semantics_version, expected["semanticsVersion"])
                self.assertIs(type(parsed.semantics_version), int)
                self.assertEqual(parsed.environment, expected["environment"])
                self.assertEqual(
                    {name: {"server": s, "delivery": d} for name, (s, d) in parsed.items.items()},
                    expected["items"],
                )

    def test_invalid(self) -> None:
        for vector in run_context_v1()["invalid"]:
            with self.subTest(note=vector["note"]):
                self.assertEqual(runtime._parse_run_context(vector["raw"]), vector["reason"])
                self.assertNotIn("leaked-secret-value", vector["reason"])


if __name__ == "__main__":
    unittest.main()
