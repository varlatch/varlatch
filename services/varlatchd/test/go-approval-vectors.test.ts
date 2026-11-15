// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step-up approval vectors for the Go server (ADR-0059 step 4.3b,
 * feature-parity decision 3): what this server's code gives for
 *
 * - the labels every approval summary names things with
 *   (approvallabels.ts): quoted, labelWithId, unnamed, quotedList and
 *   quotedMap, over names a request may hold, and the code points that
 *   are written escaped (INVISIBLE), as ranges over every code point;
 * - the digests an approval binds an operation to (approvals.ts):
 *   canonicalJson and approvalHash of bodies and queries, with a fixed key;
 * - the binding of an export (exportstepup.ts exportBinding);
 * - the operation catalogues: every operation an approval can be asked
 *   for, the ones each control at enforce asks for, and the ones an
 *   intent may be created for while the Organization is frozen.
 *
 * go/server/security's vector test must give the same. Every run checks
 * the committed file; after a change, regenerate it:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-approval-vectors.test.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { labelWithId, list, quoted, quotedList, quotedMap, unnamed } from "../src/domain/approvallabels.js";
import { APPROVAL_OPERATIONS, approvalHash, canonicalJson, CONTROL_APPROVAL_OPERATIONS, OPERATIONS_DURING_FREEZE } from "../src/domain/approvals.js";
import { exportBinding } from "../src/domain/exportstepup.js";
import type { CapturedState, ResolvedItem } from "../src/domain/retrieval.js";

const FILE = new URL("../../../go/server/security/testdata/approval-vectors.json", import.meta.url);

const KEY = Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex");

/** Names a request may hold: quotes, backslashes, ids, every kind of invisible character, astral text. */
const NAMES = [
  "", "reader", "Bob", "Bob ", " Bob", "a\"b", "a\\b", "a\\u{200B}b", "(rol_abcdefghijklmnopqrstuvwxyz)", "x\" (idn_abc)",
  "tab\there", "line\nbreak", "cr\rlf", "nul\u0000x", "del\u007fx", "c1\u0085x", "nbsp x", "ogham x", "en x",
  "zw​sp", "zwnj‌", "zwj‍", "lrm‎", "rlo‮", "ls x", "ps x", "nnbsp x", "mmsp x",
  "ideo　x", "bom﻿x", "vs16️", "vs-sup\u{e0100}", "mongolian᠎x", "hangulㅤx", "braille⠀x",
  "soft­hyphen", "cgj͏", "tag\u{e0041}", "shorthand\u{1bca0}", "interlinear￹", "emoji😀", "é", "日本語",
  "\u{10ffff}", "�", "back\\u{0041}slash",
];

/** The code points INVISIBLE matches, as [first, last] ranges over all of Unicode. */
function invisibleRanges(): [number, number][] {
  const re = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}⠀]|[^\S ]/u;
  const out: [number, number][] = [];
  for (let cp = 0; cp <= 0x10ffff; cp++) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue;
    if (!re.test(String.fromCodePoint(cp))) continue;
    const last = out[out.length - 1];
    if (last && last[1] === cp - 1) last[1] = cp;
    else out.push([cp, cp]);
  }
  return out;
}

/** Bodies and queries an approval binds: key orders, nesting, numbers, text beyond ASCII. */
const VALUES: unknown[] = [
  null, true, 0, 1.5, 1e21, 123456789012, "text", "é😀 ", [],
  {}, { b: 1, a: 2 }, { z: null, a: [3, { y: "x", b: false }] },
  { "é": 1, "z": 2, "Z": 3, "😀": 4, "～": 5, "a\u0000": 6, "": 7, "10": 8, "9": 9 },
  { mode: "off", config: null, expectedVersion: 3 },
  { mode: "enforce", config: { maxTtlSeconds: 7200, defaultTtlSeconds: 600 }, expectedVersion: 0 },
  { purpose: "export", mode: "items", requested: ["A", "B"], disclosed: ["A"] },
  { control: "admin-step-up" }, { projectId: "prj_a", environmentId: "env_b" },
];

const state = (projectName: string, envName: string) => ({
  org: { id: "org_aaaaaaaaaaaaaaaaaaaaaaaaaa" },
  project: { id: "prj_aaaaaaaaaaaaaaaaaaaaaaaaaa", name: projectName },
  env: { id: "env_aaaaaaaaaaaaaaaaaaaaaaaaaa", name: envName },
}) as unknown as CapturedState;
const items = (names: string[]) => names.map((name) => ({ name }) as ResolvedItem);

const EXPORTS: { project: string; environment: string; request: { items?: string[]; scope?: "all-authorized-secrets" }; selected: string[] }[] = [
  { project: "API", environment: "production", request: { items: ["B", "A", "B"] }, selected: ["B", "A"] },
  { project: "API", environment: "production", request: { scope: "all-authorized-secrets" }, selected: ["Z", "a", "B"] },
  { project: "My \"api\"", environment: "dev​", request: { items: ["S"] }, selected: ["S"] },
  { project: "API", environment: "dev", request: { items: ["X"] }, selected: [] },
  { project: "API", environment: "dev", request: { items: ["😀", "～", "é"] }, selected: ["😀", "～", "é"] },
];

function build() {
  return {
    comment: "Written by services/varlatchd/test/go-approval-vectors.test.ts from the TypeScript server's code; do not edit.",
    key: KEY.toString("hex"),
    invisible: invisibleRanges(),
    labels: NAMES.map((name) => ({
      name,
      quoted: quoted(name),
      labelWithId: labelWithId("role", name, "rol_abcdefghijklmnopqrstuvwxyz"),
      labelWithoutKind: labelWithId(null, name, "idn_abcdefghijklmnopqrstuvwxyz"),
      unnamed: unnamed("grant", name),
    })),
    lists: [[], ["a"], NAMES.slice(0, 6), NAMES.slice(10, 20)].map((names) => ({
      names,
      quotedList: quotedList(names),
      list: list(names.map((n) => labelWithId(null, n, "idn_x"))),
    })),
    maps: [{}, { repo: "acme/api", ref: "main" }, Object.fromEntries(NAMES.slice(0, 12).map((n, i) => [n, NAMES[NAMES.length - 1 - i]!]))].map((map) => ({
      map,
      quotedMap: quotedMap(map),
    })),
    digests: VALUES.map((value) => ({
      value,
      canonical: canonicalJson(value),
      body: approvalHash(KEY, "body", value),
      query: approvalHash(KEY, "query", value),
    })),
    operations: [...APPROVAL_OPERATIONS],
    controlOperations: CONTROL_APPROVAL_OPERATIONS,
    duringFreeze: [...OPERATIONS_DURING_FREEZE].sort(),
    exports: EXPORTS.map((e) => ({
      ...e,
      binding: exportBinding(state(e.project, e.environment), e.request, items(e.selected)),
    })),
  };
}

describe("approval vectors for the Go server", () => {
  it.skipIf(process.env.VARLATCH_WRITE_GO_VECTORS !== "1")("writes the file", () => {
    writeFileSync(FILE, JSON.stringify(build(), null, 2) + "\n");
  });
  it("the committed file is this code's answers", () => {
    expect(JSON.parse(readFileSync(FILE, "utf8"))).toEqual(JSON.parse(JSON.stringify(build())));
  });
});
