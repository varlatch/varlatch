#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * What Node.js's URL host parser (ada) knows about every code point, read
 * from Node itself through url.domainToASCII, for go/server/whatwg.
 *
 *   node go/server/whatwg/testdata/nodeidna.mjs        write both files
 *   node go/server/whatwg/testdata/nodeidna.mjs check  fail if either is stale
 *
 * ada's label validity (is_label_valid in its idna sources) checks, per
 * label: no leading combining mark (its own table); the first ZWNJ or ZWJ
 * settles the label at once (ContextJ, with its own virama and joining-type
 * lists); then, only for a label that holds an R, AL or AN character, the
 * RFC 5893 conditions (its own Bidi table). Those tables are not Unicode's
 * current data (U+0870, Unicode 14, is left-to-right there), so the Go
 * port takes them from Node: each code point is put in labels built so
 * that the answer isolates one property.
 *
 * - ../nodeidna_table.go: the properties, as ranges.
 * - node-idna.json: a hash of Node's answers for ten labels around every
 *   code point, per block of 256, which whatwg's tests recompute in Go.
 *
 * The services/varlatchd vector test runs the check, so a Node.js release
 * whose host parser answers differently fails CI until this is rerun.
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { domainToASCII } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const TABLE = join(here, "..", "nodeidna_table.go");
export const VECTORS = join(here, "node-idna.json");

// Companions whose own properties are known: a CJK ideograph (L, never
// composes), Hebrew alef (R), Arabic beh (AL, joining type D), an EN digit
// and an AN digit.
const C = "一";
const H = "א";
const BEH = "ب";
const ZWNJ = "‌";
const ZWJ = "‍";

// Bidi groups, as ada's rules can tell them apart. L and every class no
// rule allows (WS, B, S, the embeddings) behave the same, as group 0.
const LX = 0, RAL = 1, AN = 2, EN = 3, NSM = 4, NEU = 5;
const VALID = 1, COMB = 2, JOIN_LD = 1 << 5, JOIN_RD = 1 << 6, VIRAMA = 1 << 7;

const ok = (s) => domainToASCII(s) !== "";

/** The label as ada maps it, through its punycode output: null if refused. */
function mapped(label) {
  const out = domainToASCII(label);
  if (out === "" || out.includes(".")) return null; // refused, or not one label
  return out.startsWith("xn--") ? punyDecode(out.slice(4)) : out;
}

// RFC 3492 decoding, for reading ada's output back.
function punyDecode(input) {
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  let n = 128, i = 0, bias = 72;
  const d = input.lastIndexOf("-");
  const out = d > 0 ? [...input.slice(0, d)].map((c) => c.codePointAt(0)) : [];
  const digit = (c) => (c >= 48 && c < 58 ? c - 22 : c >= 97 && c < 123 ? c - 97 : 36);
  for (let p = d > 0 ? d + 1 : 0; p < input.length; ) {
    const old = i;
    for (let w = 1, k = base; ; k += base) {
      if (p >= input.length) return null;
      const dg = digit(input.charCodeAt(p++));
      if (dg >= base) return null;
      i += dg * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (dg < t) break;
      w *= base - t;
    }
    const len = out.length + 1;
    let delta = old === 0 ? Math.floor((i - old) / damp) : (i - old) >> 1;
    delta += Math.floor(delta / len);
    let k = 0;
    for (; delta > ((base - tMin) * tMax) >> 1; k += base) delta = Math.floor(delta / (base - tMin));
    bias = Math.floor(k + ((base - tMin + 1) * delta) / (delta + skew));
    n += Math.floor(i / len);
    i %= len;
    out.splice(i++, 0, n);
  }
  return String.fromCodePoint(...out);
}

/** The properties of one code point: 0 when ada does not keep it as itself. */
export function props(cp) {
  const x = String.fromCodePoint(cp);
  if (cp === 0x200c || cp === 0x200d) return VALID | (NEU << 2); // BN; checked by the joiner probes
  // Valid: some label keeps x as itself.
  if (cp === 0x2e) return 0; // the label separator
  const valid = [C + x, H + x, H + x + H].some((l) => mapped(l) === l);
  if (!valid) return 0;
  const q1 = ok(C + x), q2 = ok(H + x + H), q3 = ok(H + x), q4 = ok(H + x + "1"), q5 = ok(H + x + "٠");
  let group;
  if (!q2) group = LX;
  else if (!q1) group = q4 ? RAL : AN;
  else if (!q3) group = NEU;
  else group = q5 ? NSM : EN;
  let comb = false;
  if (group === RAL) comb = !ok(x + H);
  else if (group !== AN) comb = !ok(x + C);
  const virama = ok(C + x + ZWJ);
  const ld = !virama && ok(C + x + ZWNJ + BEH);
  const rd = ok(BEH + ZWNJ + x);
  return VALID | (comb ? COMB : 0) | (group << 2) | (ld ? JOIN_LD : 0) | (rd ? JOIN_RD : 0) | (virama ? VIRAMA : 0);
}

// The labels the block hashes cover, around each code point x.
export const TEMPLATES = [
  ["", ""], ["", ".example"], ["a", ""], ["", "a"], ["a", "a.א"], ["א", ""], ["א", "א"],
  ["א", "1"], ["", ".א"], ["क्", "ष"], ["ب‌", ""], ["", "‌ب"],
  ["xn--", ""], ["١", "א"], ["a‍", ""],
];

export function build() {
  const ranges = [];
  const blocks = [];
  let hash = createHash("sha256");
  for (let cp = 0x20; cp <= 0x10ffff; cp++) {
    if (cp % 256 === 0 && cp > 0x20) {
      blocks.push(hash.digest("hex").slice(0, 16));
      hash = createHash("sha256");
    }
    if (cp >= 0xd800 && cp <= 0xdfff) continue;
    const p = props(cp);
    const last = ranges[ranges.length - 1];
    if (last && last[1] === cp - 1 && last[2] === p) last[1] = cp;
    else ranges.push([cp, cp, p]);
    const x = String.fromCodePoint(cp);
    hash.update(TEMPLATES.map(([a, b]) => domainToASCII(a + x + b)).join("|") + "\n");
  }
  blocks.push(hash.digest("hex").slice(0, 16));
  const nonZero = ranges.filter((r) => r[2] !== 0);
  const go = [
    "// SPDX-License-Identifier: AGPL-3.0-or-later",
    "",
    `// Code generated by testdata/nodeidna.mjs from Node.js ${process.version} (ada ${process.versions.ada}); DO NOT EDIT.`,
    "",
    "package whatwg",
    "",
    `const nodeVersion = ${JSON.stringify(process.version)}`,
    "",
    "// nodeIDNA holds, for every code point ada keeps as itself, its properties",
    "// (see idna.go); code points outside it are refused.",
    "var nodeIDNA = []idnaRange{",
    ...nonZero.map(([lo, hi, p]) => `\t{0x${lo.toString(16)}, 0x${hi.toString(16)}, 0x${p.toString(16)}},`),
    "}",
    "",
  ].join("\n");
  const json = `${JSON.stringify({ node: process.version, ada: process.versions.ada, templates: TEMPLATES, blocks }, null, 1)}\n`;
  return { go, json };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { go, json } = build();
  if (process.argv[2] === "check") {
    const stale = [[TABLE, go], [VECTORS, json]].filter(([f, want]) => readFileSync(f, "utf8") !== want).map(([f]) => f);
    if (stale.length) {
      console.error(`stale (rerun node ${fileURLToPath(import.meta.url)}): ${stale.join(", ")}`);
      process.exit(1);
    }
  } else {
    writeFileSync(TABLE, go);
    writeFileSync(VECTORS, json);
  }
}
