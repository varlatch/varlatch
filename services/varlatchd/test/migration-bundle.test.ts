// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from "node:fs";
import { PassThrough, Writable } from "node:stream";
import { describe, expect, it } from "vitest";
import type { Value } from "../src/migration/canonical.js";
import { encodeValue } from "../src/migration/canonical.js";
import { bundleTables, loadManifest, refusalKind, writeBundle, type Decision, type DecisionSource, type Digest, type ManifestTable } from "../src/migration/bundle.js";
import { orderClause, selectRows } from "../src/migration/source.js";
import { readBundle, type BundleParts } from "./helpers/bundle-read.js";

/**
 * bundle-v1 (go/server/migration/bundle/BUNDLE.md): the TypeScript writer
 * reproduces varlatchd's vector, test/migration/bundle-small.jsonl
 * (go/server/migration/bundle/testdata/small.jsonl), byte for byte, and
 * writes no bundle of its refused cases (testdata/refused.json, here
 * test/migration/bundle-refused.json).
 */

const small = readFileSync(new URL("./migration/bundle-small.jsonl", import.meta.url), "utf8");
const refused = JSON.parse(readFileSync(new URL("./migration/bundle-refused.json", import.meta.url), "utf8")) as { name: string; bundle: string; why: string }[];

const noDecisions = (): DecisionSource => ({ count: 0, at: 0n, decisions: (async function* () {})() });

/** A canonical row back into the values the writer takes, numbers exactly. */
function decodeRow(table: ManifestTable, line: string): Value[] {
  const raw = JSON.parse(line, (_key, value, context?: { source?: string }) =>
    typeof value === "number" && context?.source !== undefined ? { digits: context.source } : value,
  ) as unknown[];
  return table.columns.map((c, i) => {
    const v = raw[i];
    if (v === null) return null;
    switch (c.type) {
      case "timestamp with time zone":
      case "integer":
      case "bigint":
        return BigInt((v as { digits: string }).digits);
      case "boolean":
        return (v as { digits: string }).digits === "1";
      case "bytea":
        return Buffer.from(v as string, "base64");
      default:
        return v as Value;
    }
  });
}

/** Writes a bundle from its parts, each table's rows decoded from their lines. */
async function write(parts: BundleParts, opts: { out?: Writable; digests?: Digest[]; decisions?: Decision[] } = {}): Promise<string> {
  const out = opts.out ?? new PassThrough();
  const chunks: Buffer[] = [];
  out.on("data", (c: Buffer) => chunks.push(c));
  const decisions = opts.decisions ?? parts.decisions;
  await writeBundle(out, {
    manifest: loadManifest(),
    frozenPoint: { auditPosition: String(parts.header.frozenPoint.auditPosition), snapshot: parts.header.frozenPoint.snapshot },
    rows: async (table) => {
      const lines = parts.tables.get(table.source) ?? [];
      async function* gen() {
        for (const l of lines) yield decodeRow(table, l);
      }
      return { count: lines.length, rows: gen() };
    },
    digests: opts.digests ?? parts.digests,
    decisions: { count: decisions.length, at: parts.at, decisions: (async function* () { yield* decisions; })() },
  });
  out.end();
  return Buffer.concat(chunks).toString("utf8");
}

describe("bundle-v1", () => {
  it("writes varlatchd's vector byte for byte", async () => {
    expect(await write(readBundle(small))).toBe(small);
  });

  it("writes none of varlatchd's refused bundles: each is refused, or comes out as the format says", async () => {
    expect(refused.length).toBeGreaterThanOrEqual(30);
    for (const c of refused) {
      let parts: BundleParts | null = null;
      try {
        parts = readBundle(c.bundle);
      } catch {
        // Not even a bundle's shape: nothing of it can reach the writer.
      }
      if (!parts) continue;
      const written = await write(parts).catch(() => null);
      expect(written, `${c.name} (${c.why})`).not.toBe(c.bundle);
    }
  });

  it("sorts the digests by class, then by their ids as written in jsonb order, and refuses an item twice", async () => {
    const parts = readBundle(small);
    // Given last first, each with its ids in the reverse of jsonb's order.
    const given = [...parts.digests].reverse().map((d) => ({ ...d, ids: Object.fromEntries(Object.entries(d.ids).reverse()) }));
    expect(Object.keys(given[0]!.ids)).toEqual(["organizationId", "versionId", "secretId"]);
    expect(await write(parts, { digests: given })).toBe(small);
    await expect(write(parts, { digests: [...parts.digests, parts.digests[0]!] })).rejects.toThrow(/digested twice/);
    await expect(write(parts, { digests: [{ ...parts.digests[0]!, hmac: parts.digests[0]!.hmac.toUpperCase() }] })).rejects.toThrow(/lowercase hex/);
  });

  it("refuses a decision the format does not allow", async () => {
    const parts = readBundle(small);
    const d = parts.decisions[0]!;
    const cases: [Decision, RegExp][] = [
      [{ ...d, code: "PERMISSION_DENIED" }, /allowed with an error code/],
      [{ ...d, allowed: false, code: null }, /denied without one/],
      [{ ...d, state: "suspended" as Decision["state"] }, /state other than/],
      [{ ...d, project: "" }, /empty project/],
      [{ ...d, project: null }, /outside a Project/],
      [{ ...d, tailnet: { tailnet: "", nodeId: "n", tags: [], userLogin: null } }, /Tailnet Context without/],
    ];
    for (const [bad, why] of cases) {
      await expect(write(parts, { decisions: [bad] }), JSON.stringify(bad)).rejects.toThrow(why);
    }
  });

  it("stops at a write error (ENOSPC), never hangs", async () => {
    const full = new Writable({
      highWaterMark: 64,
      write(_chunk, _encoding, callback) {
        callback(Object.assign(new Error("ENOSPC: no space left on device, write"), { code: "ENOSPC" }));
      },
    });
    await expect(write(readBundle(small), { out: full })).rejects.toThrow(/ENOSPC/);
  });

  it("names every table the manifest copies or transforms, each once, in its order", () => {
    const names = bundleTables(loadManifest()).map((t) => t.source);
    expect(names).toEqual([...names].sort());
    expect(new Set(names).size).toBe(names.length);
    expect(names).toContain("session");
    expect(names).not.toContain("account");
    expect(names).not.toContain("verification");
  });

  it("writes the session's token as null whatever the source holds, so it never leaves", async () => {
    const session = loadManifest().tables.find((t) => t.source === "session")!;
    const token = session.columns.findIndex((c) => c.leftOut !== undefined);
    expect(session.columns[token]!.source).toBe("token");
    const marker = ["session", "token", "marker", "never", "exported"].join("-");
    const row: Value[] = session.columns.map((c) => (c.source === "token" ? marker : c.type === "text" ? "x" : c.type === "boolean" ? false : c.type === "bytea" ? new Uint8Array() : 1n));
    const out = new PassThrough();
    const chunks: Buffer[] = [];
    out.on("data", (c: Buffer) => chunks.push(c));
    await writeBundle(out, {
      manifest: loadManifest(),
      frozenPoint: { auditPosition: "0", snapshot: "1-1-1" },
      rows: async (table) => {
        async function* gen() {
          if (table.source === "session") yield row;
        }
        return { count: table.source === "session" ? 1 : 0, rows: gen() };
      },
      digests: [],
      decisions: noDecisions(),
    });
    expect(Buffer.concat(chunks).toString("utf8")).not.toContain(marker);
    // Nor is it ever read: its SELECT reads NULL in its place.
    expect(selectRows(session)).not.toMatch(/"token"/);
  });

  it("orders as SQLite does: text by its bytes, NULL first; requirements in physical order", () => {
    const m = loadManifest();
    const requirements = m.tables.find((t) => t.source === "requirements")!;
    expect(orderClause(requirements)).toBe("ctid");
    const events = m.tables.find((t) => t.source === "audit_events")!;
    expect(orderClause(events)).toMatch(/ASC NULLS FIRST/);
    for (const t of bundleTables(m).filter((t) => !t.physicalOrder)) {
      const clause = orderClause(t);
      for (const k of t.orderBy!) {
        const text = t.columns.find((c) => c.source === k)!.type === "text";
        expect(clause, `${t.source}.${k}`).toContain(`"${k}"${text ? ' COLLATE "C"' : ""} ASC NULLS FIRST`);
      }
    }
  });

  it("refuses a row it cannot encode, naming the table, never the value", async () => {
    const audit = loadManifest().tables.find((t) => t.source === "audit_events")!;
    const metadata = audit.columns.findIndex((c) => c.type === "jsonb");
    const secret = ["a", "value", "that", "stays", "inside"].join("-");
    const row: Value[] = audit.columns.map((c, i) => (i === metadata ? `{"n":1e400,"s":"${secret}"}` : c.type === "text" ? "x" : c.type === "jsonb" ? "{}" : c.type === "boolean" ? false : 1n));
    const out = new PassThrough();
    out.resume();
    const attempt = writeBundle(out, {
      manifest: loadManifest(),
      frozenPoint: { auditPosition: "1", snapshot: "1-1-1" },
      rows: async (table) => {
        async function* gen() {
          if (table.source === "audit_events") yield row;
        }
        return { count: table.source === "audit_events" ? 1 : 0, rows: gen() };
      },
      digests: [],
      decisions: noDecisions(),
    });
    await expect(attempt).rejects.toThrow(/a row of audit_events cannot be encoded \(jsonb-number-not-exact\)/);
    await attempt.catch((err: Error) => {
      expect(err.message).not.toContain(secret);
      expect(err.message).not.toContain("1e400");
    });
  });

  it("classifies a refusal without its value: an integer past int4, an inexact jsonb number, anything else", () => {
    const kind = (f: () => unknown) => {
      try {
        f();
      } catch (err) {
        return refusalKind(err);
      }
      return "encoded";
    };
    expect(kind(() => encodeValue("integer", 3_000_000_000n))).toBe("integer-out-of-range");
    expect(kind(() => encodeValue("jsonb", '{"n":1e400}'))).toBe("jsonb-number-not-exact");
    expect(kind(() => encodeValue("text", "a\u0000b"))).toBe("not-encodable");
    expect(kind(() => encodeValue("integer", 7n))).toBe("encoded");
  });
});
