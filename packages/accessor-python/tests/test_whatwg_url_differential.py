# SPDX-License-Identifier: Apache-2.0
"""Differential test of the WHATWG URL failure port against Node's `new URL`.

A seeded, grammar-based corpus of URL-shaped strings is run through Node once
and through `_url_verdict`; every decided verdict must agree. Set
VARLATCH_URL_SEED to explore other corpora, and VARLATCH_REQUIRE_NODE=1 to fail
instead of skipping when `node` is not on PATH.
"""

import json
import os
import random
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from whatwg_url import _url_verdict  # noqa: E402

SEED = int(os.environ.get("VARLATCH_URL_SEED", "20260929"))
CORPUS_SIZE = 30000

NODE_SCRIPT = r"""
const chunks = [];
process.stdin.on("data", (chunk) => chunks.push(chunk));
process.stdin.on("end", () => {
  const inputs = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  const verdicts = inputs.map((input) => {
    try {
      new URL(input);
      return true;
    } catch {
      return false;
    }
  });
  process.stdout.write(JSON.stringify(verdicts));
});
"""

SPECIAL = ["http", "https", "ws", "wss", "ftp", "file"]
NON_SPECIAL = ["foo", "a", "x+y", "a.b-c", "mailto", "git+ssh", "sc", "data", "javascript", "z9"]
INVALID_SCHEMES = ["1a", "a_b", "-x", "", " a", "a b", "h ttp", "+a", ".a", "a%62", "a:b"]
SEPARATORS = [":", "://", ":/", ":\\\\", ":///", ":\\", ":/\\", "", "//", ":////", ":\\/", "::"]
FORBIDDEN = list(" #/:<>?@[\\]^|%") + ["\x00", "\x01", "\x1f", "\x7f", "\t", "\n", "\r"]
LABEL_CHARS = list("abcxyzABCXYZ0189-_~!$&'()*+,;=\"`{}") + FORBIDDEN
ESCAPES = ["%41", "%2e", "%2E", "%25", "%3a", "%2f", "%40", "%5b", "%00", "%7f", "%20", "%zz", "%4", "%",
           "%30", "%78", "%2D", "%5D", "%3C", "%09"]
HIGH_ESCAPES = ["%c3%a9", "%C3", "%80", "%ff", "%e2%98%83"]
CONTROLS = ["\x00", "\x01", "\x08", "\t", "\n", "\x0b", "\x0c", "\r", "\x1b", "\x1f", "\x7f"]
NON_ASCII = ["\u00fc", "\u00e9", "\u212a", "\u0661", "\u200d", "\uff0e", "\u3002", "\ufffd", "\U0001f4a9"]
PRINTABLE = [chr(c) for c in range(0x20, 0x7F)]


def _case(rng, text):
    choice = rng.random()
    if choice < 0.15:
        return text.upper()
    if choice < 0.25:
        return "".join(c.upper() if rng.random() < 0.5 else c for c in text)
    return text


def _scheme(rng):
    roll = rng.random()
    if roll < 0.6:
        return _case(rng, rng.choice(SPECIAL))
    if roll < 0.85:
        return _case(rng, rng.choice(NON_SPECIAL))
    return rng.choice(INVALID_SCHEMES)


def _label(rng):
    roll = rng.random()
    if roll < 0.02:
        return _case(rng, "xn--") + "".join(rng.choice("abc019-") for _ in range(rng.randrange(0, 5)))
    out = []
    for _ in range(rng.randrange(0, 7)):
        pick = rng.random()
        if pick < 0.7:
            out.append(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789-"))
        elif pick < 0.85:
            out.append(rng.choice(LABEL_CHARS))
        elif pick < 0.99:
            out.append(rng.choice(ESCAPES))
        else:
            out.append(rng.choice(HIGH_ESCAPES))
    return "".join(out)


def _ipv4_part(rng):
    roll = rng.random()
    if roll < 0.35:
        return str(rng.randrange(0, 300))
    if roll < 0.45:
        return str(rng.choice([4294967295, 4294967296, 16777215, 16777216, 65535, 65536, 999999999999]))
    if roll < 0.6:
        prefix = rng.choice(["0x", "0X"])
        return prefix + "".join(rng.choice("0123456789abcdefABCDEFg") for _ in range(rng.randrange(0, 10)))
    if roll < 0.75:
        return "0" + "".join(rng.choice("012345678") for _ in range(rng.randrange(0, 5)))
    if roll < 0.85:
        return ""
    return rng.choice(["a", "0xg", "1a", "08", "09", "00", "0", "x"])


def _ipv4(rng):
    host = ".".join(_ipv4_part(rng) for _ in range(rng.randrange(1, 7)))
    if rng.random() < 0.2:
        host += "."
    if rng.random() < 0.1:
        host = _label(rng) + "." + host
    return host


def _ipv6_group(rng):
    roll = rng.random()
    if roll < 0.8:
        return "".join(rng.choice("0123456789abcdefABCDEF") for _ in range(rng.randrange(0, 6)))
    if roll < 0.9:
        return ".".join(_ipv4_part(rng) for _ in range(rng.randrange(1, 6)))
    return rng.choice(["g", "%25eth0", " ", "::", "[", "]", "1.2.3.4"])


def _ipv6(rng):
    groups = [_ipv6_group(rng) for _ in range(rng.randrange(0, 10))]
    if rng.random() < 0.5:
        groups.insert(rng.randrange(0, len(groups) + 1), "")
    inner = ":".join(groups)
    if rng.random() < 0.3:
        inner = rng.choice(["::", ":", ""]) + inner
    if rng.random() < 0.2:
        inner += rng.choice(["::", ":", ".", ""])
    close = "]" if rng.random() < 0.9 else rng.choice(["", "]]", "]x", "] "])
    return "[" + inner + close


def _host(rng):
    roll = rng.random()
    if roll < 0.45:
        return ".".join(_label(rng) for _ in range(rng.randrange(1, 5)))
    if roll < 0.7:
        return _ipv4(rng)
    if roll < 0.9:
        return _ipv6(rng)
    if roll < 0.95:
        return ""
    return rng.choice(["localhost", "C:", "c|", "C:x", "ab:", "%41:", "\u00fc", "a\u00e9b", "\ud800"])


def _userinfo(rng):
    chars = "abcXYZ019-._~!$&'()*+,;=:%@/\\ "
    parts = []
    for _ in range(rng.randrange(1, 3)):
        parts.append("".join(rng.choice(chars) for _ in range(rng.randrange(0, 6))) + "@")
    return "".join(parts)


def _port(rng):
    roll = rng.random()
    if roll < 0.5:
        return "".join(rng.choice("0123456789") for _ in range(rng.randrange(0, 8)))
    if roll < 0.7:
        return rng.choice(["0", "80", "65535", "65536", "00065535", "99999", "-1", "+1", " 1"])
    return "".join(rng.choice("0123456789ax: []\\") for _ in range(rng.randrange(1, 5)))


def _tail(rng):
    pieces = []
    for _ in range(rng.randrange(0, 4)):
        start = rng.choice(["/", "?", "#", "\\", ""])
        body = "".join(rng.choice(PRINTABLE) for _ in range(rng.randrange(0, 6)))
        pieces.append(start + body)
    return "".join(pieces)


def _sprinkle(rng, text):
    # Leading/trailing C0 or space, and tabs or newlines anywhere.
    if rng.random() < 0.05:
        text = rng.choice([" ", "\x00", "\x1f", "\t", " \x01"]) + text
    if rng.random() < 0.05:
        text += rng.choice([" ", "\x00", "\x1f", "\n", "\x7f"])
    if text and rng.random() < 0.05:
        at = rng.randrange(0, len(text) + 1)
        text = text[:at] + rng.choice(["\t", "\n", "\r"]) + text[at:]
    return text


def _url_shaped(rng):
    text = _scheme(rng) + rng.choice(SEPARATORS)
    if rng.random() < 0.3:
        text += _userinfo(rng)
    text += _host(rng)
    if rng.random() < 0.3:
        text += ":" + _port(rng)
    if rng.random() < 0.5:
        text += _tail(rng)
    if rng.random() < 0.03:
        at = rng.randrange(0, len(text) + 1)
        text = text[:at] + rng.choice(NON_ASCII) + text[at:]
    return _sprinkle(rng, text)


def _random_printable(rng):
    out = []
    for _ in range(rng.randrange(0, 30)):
        out.append(rng.choice(CONTROLS) if rng.random() < 0.05 else rng.choice(PRINTABLE))
    return "".join(out)


def build_corpus(seed, size):
    rng = random.Random(seed)
    corpus = []
    while len(corpus) < size:
        corpus.append(_random_printable(rng) if rng.random() < 0.1 else _url_shaped(rng))
    return corpus


def node_verdicts(node, inputs):
    completed = subprocess.run(
        [node, "-e", NODE_SCRIPT],
        input=json.dumps(inputs).encode("utf-8"),
        capture_output=True,
        check=True,
        timeout=300,
    )
    return json.loads(completed.stdout)


_TAB_OR_NEWLINE = re.compile("[\t\n\r]")
_HIGH_ESCAPE = re.compile("%[89a-fA-F][0-9a-fA-F]")
_LOW_ESCAPE = re.compile("%([0-7][0-9a-fA-F])")


def matches_idn_rule(value):
    # A necessary condition for an undecided verdict: a special scheme, and a
    # non-ASCII code point, an escape of a byte >= 0x80, or an xn-- label.
    text = _TAB_OR_NEWLINE.sub("", value.strip("".join(map(chr, range(0x21)))))
    scheme, colon, _ = text.partition(":")
    if not colon or scheme.lower() not in SPECIAL:
        return False
    if not text.isascii() or _HIGH_ESCAPE.search(text):
        return True
    return "xn--" in _LOW_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text).lower()


class DifferentialTests(unittest.TestCase):
    def test_matches_node_new_url(self):
        node = shutil.which("node")
        if node is None:
            if os.environ.get("VARLATCH_REQUIRE_NODE") == "1":
                self.fail("node is not on PATH and VARLATCH_REQUIRE_NODE=1")
            self.skipTest("node is not on PATH")
        corpus = build_corpus(SEED, CORPUS_SIZE)
        expected = node_verdicts(node, corpus)
        self.assertEqual(len(expected), len(corpus))
        mismatches = []
        undecided = []
        for value, node_verdict in zip(corpus, expected):
            verdict = _url_verdict(value)
            if verdict is None:
                undecided.append(value)
            elif verdict is not node_verdict:
                mismatches.append((value, node_verdict))
        if mismatches:
            listing = "\n".join("  %r: node %s" % pair for pair in mismatches[:20])
            self.fail(
                "%d of %d verdicts differ from node (seed %d):\n%s"
                % (len(mismatches), len(corpus), SEED, listing)
            )
        self.assertLess(len(undecided), len(corpus) // 20, "seed %d" % SEED)
        stray = [value for value in undecided if not matches_idn_rule(value)]
        self.assertEqual(stray[:20], [], "seed %d" % SEED)
        # The corpus must exercise every kind of verdict.
        decided = [v for v in (_url_verdict(value) for value in corpus) if v is not None]
        self.assertGreater(decided.count(True), len(corpus) // 10)
        self.assertGreater(decided.count(False), len(corpus) // 10)
        self.assertGreater(len(undecided), 0)


if __name__ == "__main__":
    unittest.main()
