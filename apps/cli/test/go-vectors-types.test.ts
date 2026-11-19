// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { contractHash, normalizeContract, semanticsVersionOf } from "@varlatch/contract";
import { ACCESSOR_RUNTIME_SOURCE } from "@varlatch/accessor/embedded";
import { PYTHON_RUNTIME_SOURCE } from "@varlatch/accessor-python/embedded";
import { describe, expect, it } from "vitest";
import { TypesError, generateTypesModule, type RevisionInput } from "../src/typegen.js";
import { generatePythonModule } from "../src/typegenPython.js";
import { ITEMS, contractItem, revision } from "./fixtures.js";
import { writeOrCompare } from "./goKit.js";

/**
 * Vectors for the Go CLI's `varlatch types` (internal docs/design/go-cli.md,
 * slice 5.3c and decision 7): the module each TypeScript generator writes
 * for a revision, byte for byte, or the TypesError it throws.
 *
 * The revisions: every valid Contract of lib/contract's normalization
 * vectors, at its own semantics version and at 2 and 3 where valid; a
 * Contract built from each Contract Semantics vector file's requiredness
 * and type cases; every input of typegen.test.ts and
 * typegenPython.test.ts; and answers a server should never give (fields
 * missing or of the wrong type, a hash that does not match).
 *
 * A module embeds its runtime once; the vectors hold "{{runtime}}" there,
 * so the Go test puts in its embedded copy (which go.yml keeps equal to
 * the packages' build) and compares the whole file.
 *
 * Regenerate and commit:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/cli exec vitest run test/go-vectors-types.test.ts
 */

const VECTORS = fileURLToPath(new URL("../../../go/cmd/varlatch/testdata/vectors/types.json", import.meta.url));
const NORMALIZE = fileURLToPath(new URL("../../../go/lib/contract/testdata/ts-vectors.json", import.meta.url));
const SEMANTICS = (v: string) => fileURLToPath(new URL(`../../../packages/contract/test/vectors/${v}.json`, import.meta.url));
const RUNTIME = "{{runtime}}";
const GENERATOR = "0.11.0-test";

/** A revision answer; a field left out is one the server's answer lacked. */
type Answer = Partial<Record<keyof RevisionInput, unknown>>;

interface Case {
  name: string;
  revision: Answer;
  generatorVersion?: string;
}

/** A module with its one runtime replaced by the placeholder, or the TypesError's message. */
function outcome(generate: () => string, runtime: string): { module: string } | { error: string } {
  let text: string;
  try {
    text = generate();
  } catch (err) {
    if (err instanceof TypesError) return { error: err.message };
    throw err;
  }
  const parts = text.split(runtime);
  expect(parts, "the runtime is embedded exactly once").toHaveLength(2);
  return { module: parts.join(RUNTIME) };
}

function vector(c: Case) {
  const input = c.revision as RevisionInput;
  const opts = { generatorVersion: c.generatorVersion ?? GENERATOR };
  return {
    name: c.name,
    revision: c.revision,
    ...(c.generatorVersion !== undefined ? { generatorVersion: c.generatorVersion } : {}),
    typescript: outcome(() => generateTypesModule(input, opts), ACCESSOR_RUNTIME_SOURCE),
    python: outcome(() => generatePythonModule(input, opts), PYTHON_RUNTIME_SOURCE.trimEnd()),
  };
}

/** The answer for a Contract as the server stores it. */
function stored(name: string, contract: unknown, id = "crv_vector"): Case {
  const c = normalizeContract(contract);
  return { name, revision: { id, contentHash: contractHash(c), semanticsVersion: semanticsVersionOf(c), contract: c } };
}

function fromFixtures(name: string, items: Record<string, unknown>[], opts: Parameters<typeof revision>[1] = {}): Case {
  const r = revision(items, opts);
  return { name, revision: { id: r.id, contentHash: r.contentHash, semanticsVersion: r.semanticsVersion, contract: r.contract } };
}

const c = String.fromCharCode;

/** typegen.test.ts's and typegenPython.test.ts's inputs. */
function unitCases(): Case[] {
  const hostileTs = [
    "First line\r\nsecond\rthird",
    `${c(0x2028)}fourth${c(0x2029)}fifth${c(0x85)}sixth`,
    `bell${c(7)} escape${c(0x1b)}[31m red ${c(0x202e)}reversed${c(0x2066)} tab\there`,
    "ends */ export const pwned = 1; /*",
  ].join("\n");
  const hostilePy = '"""\nimport os; os.system("x")\n"""\\ \u202e end \u0000 \r\n next';
  const odd = `a${c(0x2028)}b${c(0x202e)}c*/d`;
  const base = revision(ITEMS);
  return [
    fromFixtures("fixtures.items", ITEMS),
    fromFixtures("fixtures.items.reversed", [...ITEMS].reverse()),
    fromFixtures("fixtures.rotation-hint", ITEMS.map((i) => (i.name === "API_KEY" ? { ...i, rotationHint: "ROTATE-HINT-CANARY-7: change it at the provider." } : i))),
    fromFixtures("fixtures.all-sensitive", [contractItem("TOKEN", { sensitive: true }), contractItem("KEY", { sensitive: true })]),
    fromFixtures("fixtures.empty", []),
    fromFixtures("fixtures.hostile-comment", [contractItem("NOTE", { description: hostileTs, example: `a*/b${c(0x2028)}c` })]),
    fromFixtures("fixtures.odd-enum", [contractItem("MODE", { type: "enum", enumValues: [odd, "plain"], defaultValue: odd })]),
    fromFixtures("fixtures.integer", [contractItem("WORKERS", { type: "integer", required: { kind: "always" } })], { semanticsVersion: 3 }),
    fromFixtures("fixtures.integer-and-number", [contractItem("WORKERS", { type: "integer", required: { kind: "always" } }), contractItem("RATIO", { type: "number" })], { semanticsVersion: 3 }),
    fromFixtures("fixtures.hostile-python", [
      contractItem("A", { description: hostilePy, example: hostilePy, defaultValue: hostilePy, type: "string" }),
      contractItem("B", { type: "enum", enumValues: ['x"y', "a\\b", "\u202e"] }),
    ]),
    fromFixtures("fixtures.unicode", [
      contractItem("U", {
        description: `lone ${c(0xd800)} high, lone ${c(0xdc00)} low, astral \u{1F600}, accented \u00e9, nbsp\u00a0 \u3000`,
        example: `\u{1F600}${c(0xd83d)}`,
        defaultValue: `\u00ff\u0100\u{10FFFF}${c(0xdfff)}\u007f`,
      }),
      contractItem("V", { type: "enum", enumValues: ["\u{1F600}", `${c(0xd800)}x`, "\u00e9"], defaultValue: "\u00e9" }),
    ]),
    fromFixtures("fixtures.environments-selector", [
      contractItem("MULTI", { required: { kind: "selector", selector: { kind: "environments", environmentIds: ["env_b", "env_a", "env_c"] } }, defaultValue: "x" }),
      contractItem("TIER", { required: { kind: "selector", selector: { kind: "tier", tier: "staging" } }, sensitive: true }),
    ]),
    fromFixtures("errors.version-1", ITEMS, { semanticsVersion: 1 }),
    { name: "errors.version-9", revision: { ...fromFixtures("", ITEMS).revision, semanticsVersion: 9 } },
    {
      name: "errors.tampered",
      revision: { ...fromFixtures("", ITEMS).revision, contract: { ...base.contract, items: [contractItem("OTHER")], semanticsVersion: 2 } },
    },
    { name: "errors.version-mismatch", revision: { ...fromFixtures("", ITEMS).revision, semanticsVersion: 1 } },
    { name: "errors.version-3-for-a-2", revision: { ...fromFixtures("", ITEMS).revision, semanticsVersion: 3 } },
    { name: "errors.id-unprintable", revision: { ...fromFixtures("", ITEMS).revision, id: "crv_1\n*/ evil" } },
    { name: "errors.hash-unprintable", revision: { ...fromFixtures("", ITEMS).revision, contentHash: "sha256:*/" } },
    { ...fromFixtures("errors.generator-version", ITEMS), generatorVersion: "1.0\n*/" },
  ];
}

/** Answers a server should never give. */
function answerCases(): Case[] {
  const good = fromFixtures("", ITEMS).revision;
  const without = (key: keyof Answer): Answer => Object.fromEntries(Object.entries(good).filter(([k]) => k !== key));
  return [
    { name: "answer.id-missing", revision: without("id") },
    { name: "answer.id-number", revision: { ...good, id: 7 } },
    { name: "answer.id-long", revision: { ...good, id: "c".repeat(129) } },
    { name: "answer.id-longest", revision: { ...good, id: "c".repeat(128) } },
    { name: "answer.hash-missing", revision: without("contentHash") },
    { name: "answer.hash-uppercase", revision: { ...good, contentHash: (good.contentHash as string).toUpperCase().replace("SHA256", "sha256") } },
    { name: "answer.version-missing", revision: without("semanticsVersion") },
    { name: "answer.version-null", revision: { ...good, semanticsVersion: null } },
    { name: "answer.version-string", revision: { ...good, semanticsVersion: "2" } },
    { name: "answer.version-fraction", revision: { ...good, semanticsVersion: 2.5 } },
    { name: "answer.version-array", revision: { ...good, semanticsVersion: [2, 3] } },
    { name: "answer.version-object", revision: { ...good, semanticsVersion: { v: 2 } } },
    { name: "answer.version-boolean", revision: { ...good, semanticsVersion: true } },
    { name: "answer.version-large", revision: { ...good, semanticsVersion: 1e21 } },
    { name: "answer.contract-missing", revision: without("contract") },
    { name: "answer.contract-null", revision: { ...good, contract: null } },
    { name: "answer.contract-array", revision: { ...good, contract: [] } },
    { name: "answer.contract-invalid", revision: { ...good, contract: { schemaVersion: 1, semanticsVersion: 2, items: [{ name: "lower", required: { kind: "sometimes" }, sensitive: "yes", type: "string" }], extra: 1 } } },
    { name: "generator.build-metadata", revision: good, generatorVersion: "1.2.3+build.4" },
    { name: "generator.longest", revision: good, generatorVersion: "9".repeat(64) },
    { name: "generator.too-long", revision: good, generatorVersion: "9".repeat(65) },
    { name: "generator.empty", revision: good, generatorVersion: "" },
  ];
}

/** Every valid Contract of lib/contract's normalization vectors, at its own version and at 2 and 3. */
function normalizeCases(): Case[] {
  const normalize = (JSON.parse(readFileSync(NORMALIZE, "utf8")) as { normalize: { name: string; input: string; canonical?: string }[] }).normalize;
  const out: Case[] = [];
  const seen = new Set<string>();
  for (const v of normalize.filter((n) => n.canonical !== undefined)) {
    const parsed = JSON.parse(v.input) as Record<string, unknown>;
    for (const [suffix, input] of [
      ["", parsed],
      [".v2", { ...parsed, semanticsVersion: 2 }],
      [".v3", { ...parsed, semanticsVersion: 3 }],
    ] as const) {
      let k: Case;
      try {
        k = stored(`normalize.${v.name}${suffix}`, input);
      } catch {
        continue; // Not valid at that version (an integer before 3).
      }
      const key = String(k.revision.contentHash);
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(k);
    }
  }
  return out;
}

/** One Contract per Contract Semantics vector file: an item per requiredness case and per type. */
function semanticsCases(): Case[] {
  return ["semantics-v1", "semantics-v2", "semantics-v3", "semantics-v2-portability", "semantics-v3-portability"].map((file) => {
    const data = JSON.parse(readFileSync(SEMANTICS(file), "utf8")) as {
      semanticsVersion: number;
      validate: { type: string; enumValues?: string[] }[];
      required?: { required: unknown }[];
    };
    const items: Record<string, unknown>[] = [];
    const requireds = [...new Set((data.required ?? []).map((r) => JSON.stringify(r.required)))];
    requireds.forEach((r, i) => items.push(contractItem(`R_${i}`, { required: JSON.parse(r) as unknown, sensitive: i % 2 === 1 })));
    const types = [...new Set(data.validate.map((v) => JSON.stringify({ type: v.type, ...(v.enumValues ? { enumValues: v.enumValues } : {}) })))];
    types.forEach((t, i) => items.push(contractItem(`T_${i}`, JSON.parse(t) as Record<string, unknown>)));
    const contract = { schemaVersion: 1, ...(data.semanticsVersion !== 1 ? { semanticsVersion: data.semanticsVersion } : {}), items };
    return stored(`semantics.${file}`, contract);
  });
}

describe("Go CLI vectors: types", () => {
  it("types.json is the TypeScript generators' modules", () => {
    const cases = [...unitCases(), ...answerCases(), ...normalizeCases(), ...semanticsCases()];
    expect(new Set(cases.map((k) => k.name)).size).toBe(cases.length);
    const vectors = {
      comment: "Generated by apps/cli/test/go-vectors-types.test.ts from the TypeScript CLI's generators; do not edit. Regenerate with VARLATCH_WRITE_GO_VECTORS=1.",
      runtime: RUNTIME,
      generatorVersion: GENERATOR,
      vectors: cases.map(vector),
    };
    const modules = vectors.vectors.filter((v) => "module" in v.typescript).length;
    expect(modules).toBeGreaterThan(50);
    const result = writeOrCompare(VECTORS, `${JSON.stringify(vectors, null, 2)}\n`);
    expect(result.current, "types.json is stale: regenerate it (see this file's comment)").toBe(true);
  });
});
