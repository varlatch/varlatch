# SPDX-License-Identifier: Apache-2.0
"""Verdicts of the WHATWG URL failure port against Node's `new URL`."""

import ast
import contextlib
import io
import json
import random
import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve()
_SRC = _HERE.parents[1] / "src"
_VECTORS = _HERE.parents[2] / "contract" / "test" / "vectors"
sys.path.insert(0, str(_SRC))

from whatwg_url import _url_parse, _url_verdict  # noqa: E402

# Hand-picked inputs with the verdict of Node 26's `new URL(input)`.
NODE_VERDICTS = {
    # IPv4 hosts: hex, octal, part counts, ranges, the last-part rules.
    "http://0": True,
    "http://0x": True,
    "http://0X": True,
    "http://0x.0x.0x.0x": True,
    "http://0xffffffff": True,
    "http://0x100000000": False,
    "http://0377.0377.0377.0377": True,
    "http://0400.1.1.1": False,
    "http://08": False,
    "http://0.08": False,
    "http://1.2.3.4.": True,
    "http://1.2.3.4..": True,
    "http://1..2": False,
    "http://1.2.3.4.5.": False,
    "http://255.255.255.255": True,
    "http://256.0.0.1": False,
    "http://1.16777215": True,
    "http://1.16777216": False,
    "http://1.2.65535": True,
    "http://1.2.65536": False,
    "http://00000000000000000000000001": True,
    "http://0x00000000000000000000000001": True,
    "http://99999999999999999999999999999": False,
    "http://a.0x1g": True,
    "http://a.1a": True,
    "http://1.a": True,
    "http://.1": False,
    "http://1.": True,
    "http://..": True,
    "http://.": True,
    "http://0x.a": True,
    "http://a.0X": False,
    "http://1.0xG": True,
    "http://%30x7f.1": True,
    "file://1.2.3.256/": False,
    # IPv6 hosts: compression, piece counts, embedded IPv4.
    "http://[1:2:3:4:5:6:7:8]": True,
    "http://[1:2:3:4:5:6:7]": False,
    "http://[1::]": True,
    "http://[::1:2:3:4:5:6:7]": True,
    "http://[1:2:3:4:5:6:7::]": True,
    "http://[1:2:3:4::5:6:7:8]": False,
    "http://[12345::]": False,
    "http://[:1]": False,
    "http://[1:]": False,
    "http://[1::2:]": False,
    "http://[::1.2.3.4]": True,
    "http://[1:2:3:4:5:6:1.2.3.4]": True,
    "http://[1:2:3:4:5:6:7:1.2.3.4]": False,
    "http://[::1.2.3]": False,
    "http://[::1.2.3.4.5]": False,
    "http://[::01.2.3.4]": False,
    "http://[::1.2.3.04]": False,
    "http://[::1.2..3]": False,
    "http://[::.1.2.3]": False,
    "http://[::ffff:1.2.3.4:5]": False,
    "http://[]": False,
    "http://[": False,
    "http://]": False,
    "http://[::1]]": False,
    "http://[[::1]]": False,
    "http://[0000:0000::]": True,
    "http://[00000::]": False,
    "http://[::1%25eth0]": False,
    "http://[::A:b]": True,
    "http://[::1]:": True,
    "http://[::1]:65536": False,
    "http://[\u00fc]": False,
    "foo://[::1]": True,
    "foo://[::1": False,
    "foo://[x]": False,
    "file://[::1]/": True,
    "file://[::1/": False,
    # Ports.
    "http://h:1": True,
    "http://h:000000000000000080": True,
    "http://h:00065536": False,
    "http://h:-1": False,
    "http://h:+1": False,
    "http://h: 1": False,
    "http://h:1 ": True,
    "http://h:1\\x": True,
    "foo://h:1\\x": False,
    "http://h:1:2": False,
    "http://h::": False,
    "foo://h:": True,
    "foo://:1": False,
    "http://:1": False,
    "foo://h:99999": False,
    "http://h:\u0661": False,
    "http://h\t:\n8\r0": True,
    # Credentials.
    "http://u:p@h": True,
    "http://u@p@h": True,
    "http://@@h": True,
    "http://@": False,
    "http://:@h": True,
    "http://u:@": False,
    "foo://@": False,
    "foo://u@": False,
    "foo://u@h": True,
    "http://u@h:bad": False,
    "http://a@b@": False,
    "http://u\\@h": True,
    "foo://u\\@h": True,
    "http://u/@h": True,
    "http://\u00fc@h": True,
    "http://\u00fc@": False,
    # File URLs.
    "file:": True,
    "file:/": True,
    "file://": True,
    "file:///": True,
    "file:x": True,
    "file:/x": True,
    "file://C:/x": True,
    "file://C|/x": True,
    "file://C:x": False,
    "file://CC:/x": False,
    "file://1:/x": False,
    "file://localhost/x": True,
    "file://host:80/x": False,
    "file://u@host/x": False,
    "file:\\\\host\\x": True,
    "file:/\\host": True,
    "file://ho%20st": False,
    "file://%41": True,
    "file://C%3A/x": False,
    "FILE://h": True,
    "file://h?x": True,
    "file://h#x": True,
    "file://a<b/": False,
    # Opaque hosts (non-special schemes).
    "foo://a b": False,
    "foo://a%zz": True,
    "foo://a^b": False,
    "foo://a|b": False,
    "foo://a<b": False,
    "foo://a>b": False,
    "foo://a\\b": False,
    "foo://a]b": False,
    "foo://a\x01b": True,
    "foo://a\x7fb": True,
    "foo://\u00fc": True,
    "foo://a\x00b": False,
    "foo://h/pa th": True,
    "foo://": True,
    "foo:///": True,
    "foo:/x": True,
    "foo:x y": True,
    "foo://a{b}": True,
    "foo://a'b\"c": True,
    "foo://xn--a": True,
    # Percent-encoded special hosts.
    "http://%61": True,
    "http://%2e": True,
    "http://a%2Fb": False,
    "http://a%3Ab": False,
    "http://%25": False,
    "http://%%41": False,
    "http://%": False,
    "http://a%": False,
    "http://a%4": False,
    "http://%7F": False,
    "http://%1f": False,
    "http://%5B::1%5D": False,
    "http://%41%42.com": True,
    # Schemes.
    "A:": True,
    "a:": True,
    "Z9+-.:x": True,
    "1a:": False,
    "a_b:": False,
    "-a:": False,
    "+a:": False,
    ".a:": False,
    "a b:": False,
    "http//x": False,
    "http:/x": True,
    "http:///x": True,
    "https:\\\\\\x": True,
    "HtTpS://x": True,
    "WS:x": True,
    "wss:x": True,
    "ftp:x": True,
    "ftp:": False,
    "ws:": False,
    "ws://@x": True,
    "\u00e9:x": False,
    "a\u00e9:x": False,
    "\u212aa:x": False,
    ":": False,
    "::": False,
    "a": False,
    "http": False,
    # Other special-host code points, and stripping.
    "http://a\\b": True,
    "http://a?b": True,
    "http://a#b": True,
    "http://a b/c": False,
    "http://a/b c": True,
    " \x01http://h\x1f ": True,
    "http:// h": False,
    "http://h ": True,
    "http://h\x7f": False,
    "http://a^": False,
    "http://a~b": True,
    "http://a_b": True,
    "http://a*b": True,
    "http://a!b": True,
    "http://a$b&c'd(e)f*g+h,i;j=k": True,
    "http://a{b": True,
    "http://a`b": True,
    'http://a"b': True,
    "http://x/\u00fc?\u00fc#\u00fc": True,
    "foo:\ud800": True,
    "\ud800:x": False,
}

# Inputs whose verdict needs UTS #46: a special scheme reaches the host parser
# with a domain that is non-ASCII after percent-decoding, or has an xn-- label.
IDN_INPUTS = [
    "http://\u00fc",
    "https://%C3%BC",
    "http://%80",
    "http://%ff.com",
    "http://XN--a.com",
    "http://a.xN--b",
    "http://xn%2D-a",
    "file://\u00fc/x",
    "ws://h@\u00fc:1",
    "ftp://\ud800",
    "http://\u00fc:bad",
]

# Near misses: non-ASCII or xn-- that never reaches a special host parser.
DECIDED_INPUTS = [
    "foo://\u00fc",
    "foo://xn--a",
    "http://x/\u00fc",
    "http://x/xn--a",
    "http://xn-a",
    "http://axn--b",
    "http://\u00fc@h",
    "http://[\u00fc]",
    "file:///\u00fc",
    "file://C:/\u00fc",
    "\u00fc://x",
    "mailto:\u00fc@xn--a",
]


def _vectors(name):
    with open(_VECTORS / name, encoding="utf-8") as handle:
        return [v for v in json.load(handle)["validate"] if v["type"] == "url"]


class VectorTests(unittest.TestCase):
    def test_semantics_v2_url_vectors(self):
        vectors = _vectors("semantics-v2.json")
        self.assertGreater(len(vectors), 0)
        for vector in vectors:
            with self.subTest(value=vector["value"]):
                self.assertIs(_url_verdict(vector["value"]), vector["valid"])

    def test_portability_url_vectors(self):
        vectors = _vectors("semantics-v2-portability.json")
        self.assertGreater(len(vectors), 0)
        self.assertTrue(any(v.get("internationalizedHost") for v in vectors))
        for vector in vectors:
            expected = None if vector.get("internationalizedHost") else vector["valid"]
            with self.subTest(value=vector["value"]):
                self.assertIs(_url_verdict(vector["value"]), expected)


class EdgeCaseTests(unittest.TestCase):
    def test_node_verdicts(self):
        for value, expected in NODE_VERDICTS.items():
            with self.subTest(value=value):
                self.assertIs(_url_verdict(value), expected)

    def test_none_only_for_internationalized_special_hosts(self):
        for value in IDN_INPUTS:
            with self.subTest(value=value):
                self.assertIsNone(_url_verdict(value))
        for value in DECIDED_INPUTS:
            with self.subTest(value=value):
                self.assertIsNotNone(_url_verdict(value))


class RobustnessTests(unittest.TestCase):
    def test_random_strings_never_raise(self):
        rng = random.Random(20260929)
        pieces = (
            [chr(c) for c in range(0x80)]
            + ["\ud800", "\udfff", "\ud83d\ude00", "\u00e9", "\u212a", "\u0661", "\ufffd", "\u200d", "\uff0e"]
            + ["http://", "file://", "foo://", "ws:", "[", "]", "%", "%c3%a9", "%80", "xn--", "::", "0x", "@", ":"]
        )
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            for _ in range(20000):
                value = "".join(rng.choice(pieces) for _ in range(rng.randrange(0, 24)))
                # The unguarded parser must not raise either: None comes only
                # from the UTS #46 rule, never from the exception guard.
                verdict = _url_parse(value)
                self.assertTrue(verdict is True or verdict is False or verdict is None, repr(value))
                self.assertIs(_url_verdict(value), verdict)
        self.assertEqual(out.getvalue() + err.getvalue(), "")

    def test_huge_inputs(self):
        cases = {
            "http://" + "a" * 1_000_000: True,
            "http://" + "1." * 200_000: False,
            "http://" + "9" * 100_000: False,
            "http://0x" + "0" * 100_000 + "1": True,
            "http://h:" + "0" * 100_000 + "80": True,
            "http://h:" + "9" * 100_000: False,
            "http://[" + "1:" * 100_000 + "]": False,
            "http://[" + ":" * 100_000 + "]": False,
            "http://[" * 100_000: False,
            "foo:" + "\x00" * 100_000: True,
            "\x00" * 100_000: False,
            "": False,
        }
        for value, expected in cases.items():
            with self.subTest(size=len(value)):
                self.assertIs(_url_parse(value), expected)

    def test_non_string_input_is_undecided(self):
        self.assertIsNone(_url_verdict(None))
        self.assertIsNone(_url_verdict(b"http://x"))


class InliningTests(unittest.TestCase):
    def test_module_is_safe_to_inline(self):
        source = (_SRC / "whatwg_url.py").read_text(encoding="utf-8")
        self.assertTrue(source.startswith("# SPDX-License-Identifier: Apache-2.0\n"))
        self.assertTrue(all(c in "\t\n" or " " <= c <= "~" for c in source), "printable ASCII only")
        tree = ast.parse(source)
        self.assertIsNone(ast.get_docstring(tree))
        for node in tree.body:
            if isinstance(node, ast.Import):
                # The only import the inlined code may use: re, bound to a private name.
                self.assertEqual([a.name for a in node.names], ["re"])
                names = [a.asname or a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                self.fail("the module may import nothing but re")
            elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                names = [node.name]
            elif isinstance(node, ast.Assign):
                names = [t.id for t in node.targets if isinstance(t, ast.Name)]
                self.assertEqual(len(names), len(node.targets))
            else:
                self.fail("unexpected top-level statement: " + type(node).__name__)
            for name in names:
                self.assertTrue(name.startswith("_"), name)


if __name__ == "__main__":
    unittest.main()
