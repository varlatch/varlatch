# SPDX-License-Identifier: Apache-2.0
# A seeded differential test: the TypeScript semantics (the reference, run
# in Node) and the Python runtime evaluate the same generated inputs, and
# must agree on every verdict, reason, and conversion. URLs have their own
# differential test against Node's URL parser (test_whatwg_url_differential).
import math
import os
import random
import unittest

from _support import built, run_node, runtime

SEED = int(os.environ.get("VARLATCH_DIFFERENTIAL_SEED", "20260929"))
COUNT = 4000

_REFERENCE = """
import { readFileSync } from "node:fs";
const { semanticsFor } = await import(process.env.SEMANTICS_JS);
const parse = semanticsFor(3).parse;
const cases = JSON.parse(readFileSync(0, "utf8"));
const out = cases.map(([type, value, enumValues]) => {
  const item = { name: "ITEM", type, required: { kind: "never" }, sensitive: false, ...(enumValues ? { enumValues } : {}) };
  const r = parse(item, value);
  if (!r.ok) return [false, r.reason];
  if (typeof r.value === "number") return [true, Object.is(r.value, -0) ? "-0" : String(r.value)];
  return [true, r.value];
});
process.stdout.write(JSON.stringify(out));
"""

# Characters that commonly differ between engines, mixed with ordinary ones.
NUMBER_CHARS = "0123456789" * 4 + "-.+eE_ x\n\t٤４१²"
BOOLEAN_WORDS = ["true", "false", "1", "0", "yes", "no", "t", "f", "01", ""]
EMAIL_CHARS = "ab.@@-_+" * 3 + " \t\n \u001c\u001f\u0085﻿ ​　éİ"
ENUM_VALUES = ["debug", "info", "café", "İstanbul", "a b"]


def number(rng: random.Random) -> str:
    kind = rng.random()
    if kind < 0.3:
        digits = "".join(rng.choice("0123456789") for _ in range(rng.randint(14, 19)))
        frac = "." + "".join(rng.choice("0123456789") for _ in range(rng.randint(1, 4))) if rng.random() < 0.4 else ""
        return rng.choice(["", "-"]) + rng.choice(["", "0", "00"]) + digits + frac
    if kind < 0.4:
        return rng.choice(["9007199254740991", "9007199254740992", "-9007199254740991"]) + rng.choice(["", ".0", ".5", ".00001", ".000"])
    return "".join(rng.choice(NUMBER_CHARS) for _ in range(rng.randint(0, 12)))


def boolean(rng: random.Random) -> str:
    word = rng.choice(BOOLEAN_WORDS)
    word = "".join(c.upper() if rng.random() < 0.5 else c for c in word)
    if rng.random() < 0.2:
        word = word.replace("s", "ſ").replace("S", "ſ")
    if rng.random() < 0.15:
        word = rng.choice([" ", "\n", "\t", " "]) + word if rng.random() < 0.5 else word + rng.choice([" ", "\n"])
    return word


def email(rng: random.Random) -> str:
    return "".join(rng.choice(EMAIL_CHARS) for _ in range(rng.randint(0, 14)))


def enum(rng: random.Random) -> str:
    value = rng.choice(ENUM_VALUES + ["DEBUG", "Info", "café", "i̇stanbul", "debug\n", " info"])
    return value


class Differential(unittest.TestCase):
    def test_python_agrees_with_the_reference_on_generated_inputs(self) -> None:
        os.environ["SEMANTICS_JS"] = "file://" + built("packages/contract/dist/semantics.js")
        rng = random.Random(SEED)
        cases: "list[list[object]]" = []
        for _ in range(COUNT):
            kind = rng.choice(["number", "number", "integer", "integer", "boolean", "email", "enum", "string"])
            if kind == "number":
                cases.append(["number", number(rng), None])
            elif kind == "integer":
                cases.append(["integer", number(rng), None])
            elif kind == "boolean":
                cases.append(["boolean", boolean(rng), None])
            elif kind == "email":
                cases.append(["email", email(rng), None])
            elif kind == "enum":
                cases.append(["enum", enum(rng), ENUM_VALUES])
            else:
                cases.append(["string", email(rng), None])
        reference = run_node(_REFERENCE, cases)
        mismatches = []
        for (kind, value, allowed), (ok, expected) in zip(cases, reference):  # type: ignore[misc]
            item = {"name": "ITEM", "type": kind, "required": {"kind": "never"}}
            if allowed is not None:
                item["enumValues"] = allowed
            got_ok, got = runtime._parse(item, value, 3)  # type: ignore[arg-type]
            if got_ok != ok:
                mismatches.append((kind, value, (ok, expected), (got_ok, got)))
            elif not ok and got != expected:
                mismatches.append((kind, value, (ok, expected), (got_ok, got)))
            elif ok and kind == "integer":
                if not (type(got) is int and got == int(expected)):
                    mismatches.append((kind, value, (ok, expected), (got_ok, got)))
            elif ok and kind == "number":
                same = float(got) == float(expected) and (
                    isinstance(got, int) or math.copysign(1, got) == math.copysign(1, float(expected))
                )
                if not same:
                    mismatches.append((kind, value, (ok, expected), (got_ok, got)))
            elif ok and got != expected:
                mismatches.append((kind, value, (ok, expected), (got_ok, got)))
        self.assertEqual(mismatches[:20], [], f"seed {SEED}: {len(mismatches)} of {COUNT} inputs disagree")
        # The corpus must exercise both outcomes of every type.
        for kind in ("number", "integer", "boolean", "email", "enum"):
            outcomes = {ok for (k, _, _), (ok, _) in zip(cases, reference) if k == kind}  # type: ignore[misc]
            self.assertEqual(outcomes, {True, False}, kind)


if __name__ == "__main__":
    unittest.main()
