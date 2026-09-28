// SPDX-License-Identifier: Apache-2.0
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { VarlatchApiError } from "@varlatch/sdk";
import { runTypes, type TypesClient, type TypesOptions } from "../src/typesCommand.js";
import { ITEMS, contractItem, revision } from "./fixtures.js";

type Revision = ReturnType<typeof revision>;

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "varlatch-types-test-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function client(active: Revision | (() => Revision), byId: Record<string, Revision> = {}) {
  const calls: string[] = [];
  const api: TypesClient = {
    async getActiveContract(org, project) {
      calls.push(`active ${org}/${project}`);
      return (typeof active === "function" ? active() : active) as never;
    },
    async getContractRevision(org, project, id) {
      calls.push(`byId ${org}/${project}/${id}`);
      const found = byId[id];
      if (!found) throw new VarlatchApiError(404, { code: "RESOURCE_NOT_FOUND", message: "Contract revision not found", requestId: "r" });
      return found as never;
    },
  };
  return { api, calls };
}

async function run(api: TypesClient, opts: Partial<TypesOptions> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const code = await runTypes(
    api,
    { organization: "acme", project: "api", out: join(dir, "src", "config.ts"), check: false, generatorVersion: "0.11.0-test", ...opts },
    { out: (l) => out.push(l), err: (l) => err.push(l) },
  );
  return { code, out: out.join("\n"), err: err.join("\n") };
}

const OUT = () => join(dir, "src", "config.ts");

describe("varlatch types", () => {
  it("fetches the active Contract, and nothing else, and writes the module", async () => {
    const rev = revision(ITEMS);
    const { api, calls } = client(rev);
    const result = await run(api);
    expect(result.code).toBe(0);
    expect(result.out).toContain(`Wrote ${OUT()} from Contract Revision ${rev.id} (${rev.contentHash}, Contract Semantics version 2).`);
    expect(calls).toEqual(["active acme/api"]);
    expect(readFileSync(OUT(), "utf8")).toContain(`// Contract Revision:          ${rev.id}`);
    // Replaced atomically: no temporary file is left next to it.
    expect(readdirSync(join(dir, "src"))).toEqual(["config.ts"]);
  });

  it("--revision fetches that revision by ID", async () => {
    const old = revision([contractItem("PORT", { type: "number" })], { id: "crv_older" });
    const { api, calls } = client(revision(ITEMS), { crv_older: old });
    expect((await run(api, { revision: "crv_older" })).code).toBe(0);
    expect(calls).toEqual(["byId acme/api/crv_older"]);
    expect(readFileSync(OUT(), "utf8")).toContain("// Contract Revision:          crv_older");

    const missing = await run(api, { revision: "crv_gone" });
    expect(missing.code).toBe(1);
    expect(missing.err).toContain("Contract Revision crv_gone was not found in acme/api");
  });

  it("leaves an unchanged file alone, modification time included", async () => {
    const { api } = client(revision(ITEMS));
    await run(api);
    const past = new Date("2026-01-01T00:00:00Z");
    utimesSync(OUT(), past, past);
    const again = await run(api);
    expect(again.code).toBe(0);
    expect(again.out).toContain("is already current with Contract Revision");
    expect(statSync(OUT()).mtime.getTime()).toBe(past.getTime());
  });

  it("keeps the existing file's mode when it rewrites it", async () => {
    await run(client(revision(ITEMS)).api);
    chmodSync(OUT(), 0o600);
    await run(client(revision([contractItem("OTHER")])).api);
    expect(statSync(OUT()).mode & 0o777).toBe(0o600);
    expect(readFileSync(OUT(), "utf8")).toContain("readonly OTHER?: string;");
  });

  it("--check passes on a current file and fails, writing nothing, on any change, including a type change (C-T4)", async () => {
    await run(client(revision(ITEMS)).api);
    const before = readFileSync(OUT());
    const fresh = await run(client(revision(ITEMS)).api, { check: true });
    expect(fresh.code).toBe(0);
    expect(fresh.out).toContain("is current with Contract Revision");

    // Same names, one type changed: stale.
    const retyped = ITEMS.map((i) => (i.name === "PORT" ? { ...i, type: "string" } : i));
    const stale = await run(client(revision(retyped)).api, { check: true });
    expect(stale.code).toBe(1);
    expect(stale.err).toContain(`--check: ${OUT()} is stale`);
    expect(readFileSync(OUT()).equals(before)).toBe(true);

    rmSync(OUT());
    const missing = await run(client(revision(ITEMS)).api, { check: true });
    expect(missing.code).toBe(1);
    expect(missing.err).toContain("does not exist");
    expect(existsSync(OUT())).toBe(false);
  });

  it("never writes through a symbolic link (C-T2)", async () => {
    const target = join(dir, "elsewhere.ts");
    writeFileSync(target, "original");
    mkdirSync(join(dir, "src"));
    symlinkSync(target, OUT());
    for (const check of [false, true]) {
      const result = await run(client(revision(ITEMS)).api, { check });
      expect(result.code).toBe(1);
      expect(result.err).toContain("is a symbolic link; varlatch types never writes through one");
    }
    expect(readFileSync(target, "utf8")).toBe("original");
    expect(readdirSync(join(dir, "src"))).toEqual(["config.ts"]);
  });

  it("refuses an output path that is not a regular file, or not a TypeScript file", async () => {
    mkdirSync(OUT(), { recursive: true });
    expect((await run(client(revision(ITEMS)).api)).err).toContain("is not a regular file");
    const js = await run(client(revision(ITEMS)).api, { out: join(dir, "config.js") });
    expect(js.code).toBe(1);
    expect(js.err).toContain("--out must name a TypeScript file (.ts, .mts, .cts)");
  });

  it("refuses a version 1 revision, naming the fix, and writes nothing", async () => {
    const result = await run(client(revision(ITEMS, { semanticsVersion: 1 })).api);
    expect(result.code).toBe(1);
    expect(result.err).toContain("which defines no conversion");
    expect(result.err).toContain("varlatch contract push --semantics latest");
    expect(result.err).toContain("Nothing was written.");
    expect(existsSync(OUT())).toBe(false);
  });

  it("names contract.read when the identity may not read the Contract", async () => {
    const api: TypesClient = {
      getActiveContract: async () => {
        throw new VarlatchApiError(403, { code: "PERMISSION_DENIED", message: "denied", requestId: "r" });
      },
      getContractRevision: async () => {
        throw new Error("unused");
      },
    };
    const result = await run(api);
    expect(result.code).toBe(1);
    expect(result.err).toContain("reading the Contract needs contract.read on the project");
  });
});
