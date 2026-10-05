// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { parseRunContext } from "@varlatch/accessor";
import type { EffectiveConfiguration, StateManifest } from "@varlatch/protocol";
import { VarlatchApiError } from "@varlatch/sdk";
import {
  EXPORT_CONTEXT_ATTEMPTS,
  ExportContextError,
  exportedRunContext,
  prepareExportedContext,
  readConsistently,
  type ConfigurationRead,
  type ExportContextClient,
} from "../src/exportContext.js";
import { RUN_CONTEXT, buildEnv } from "../src/inject.js";
import { contractItem, revision } from "./fixtures.js";

const REVISION = revision([
  contractItem("API_KEY", { sensitive: true, required: { kind: "always" } }),
  contractItem("LOG_LEVEL", { defaultValue: "info" }),
  contractItem("PORT", { type: "number" }),
  contractItem("REGION"),
  contractItem("TOKEN", { sensitive: true }),
]);

const MANIFEST: StateManifest = {
  manifestVersion: 1,
  projectId: "prj_1",
  environment: { id: "env_dev_child", rootId: "env_dev", parentId: "env_dev", tier: "development", expiresAt: null },
  contract: { revisionId: REVISION.id, contentHash: REVISION.contentHash, semanticsVersion: 2 },
  items: [],
};

const DIGEST = `sha256:${"a".repeat(64)}`;
const OTHER = `sha256:${"b".repeat(64)}`;

/** A default run's Effective Configuration after disclosure: Secrets the caller may not reveal stay null. */
function effective(items: { name: string; value: string | null; sensitive?: boolean }[], manifest: StateManifest | null = MANIFEST): EffectiveConfiguration {
  return {
    environmentId: "env_dev_child",
    items: items.map((i) => ({ name: i.name, sensitive: i.sensitive ?? false, source: "self" as const, value: i.value })),
    ...(manifest ? { manifest, stateDigest: DIGEST } : {}),
  };
}

const client = (fetched = REVISION, calls: string[] = []): ExportContextClient => ({
  async getContractRevision(org, project, id) {
    calls.push(`${org}/${project}/${id}`);
    return fetched as never;
  },
});

describe("the exported run context", () => {
  it("--omit: an omitted item is absent, never inherited, and a Secret that was not asked for is not called withheld", () => {
    const delivered = effective([
      { name: "PORT", value: "8080" },
      { name: "API_KEY", value: null, sensitive: true },
      { name: "TOKEN", value: null, sensitive: true },
    ]);
    const omitted = new Set(["API_KEY", "PORT", "REGION"]);
    const context = exportedRunContext(MANIFEST.contract!, MANIFEST.environment, REVISION.contract as never, delivered, { API_KEY: "shell", REGION: "eu" }, omitted);
    expect(context.items).toMatchObject({
      API_KEY: { server: "delivered", delivery: "absent" },
      PORT: { server: "delivered", delivery: "absent" },
      REGION: { server: "notStored", delivery: "absent" },
      // Not omitted: a Secret the disclosure did not return is withheld, as before.
      TOKEN: { server: "withheld", delivery: "absent" },
    });
    // Control, same input: without --omit the parent's copies are inherited and API_KEY is withheld.
    const control = exportedRunContext(MANIFEST.contract!, MANIFEST.environment, REVISION.contract as never, delivered, { API_KEY: "shell", REGION: "eu" });
    expect(control.items).toMatchObject({
      API_KEY: { server: "withheld", delivery: "inherited" },
      PORT: { server: "delivered", delivery: "varlatch" },
      REGION: { server: "notStored", delivery: "inherited" },
    });
  });

  it("records what the server did and how a default run delivered each Contract item, names only", () => {
    const delivered = effective([
      { name: "PORT", value: "8080" },
      { name: "API_KEY", value: null, sensitive: true },
      { name: "TOKEN", value: null, sensitive: true },
      { name: "OUTSIDE", value: "not in the Contract" },
    ]);
    const context = exportedRunContext(MANIFEST.contract!, MANIFEST.environment, REVISION.contract as never, delivered, {
      API_KEY: "from-the-shell",
      REGION: "eu-west",
    });
    expect(context).toEqual({
      v: 1,
      mode: "exported",
      contractRevisionId: REVISION.id,
      contractHash: REVISION.contentHash,
      semanticsVersion: 2,
      environment: { rootId: "env_dev", tier: "development" },
      items: {
        API_KEY: { server: "withheld", delivery: "inherited" },
        // A default run never applies a Contract default.
        LOG_LEVEL: { server: "notStored", delivery: "absent" },
        PORT: { server: "delivered", delivery: "varlatch" },
        REGION: { server: "notStored", delivery: "inherited" },
        TOKEN: { server: "withheld", delivery: "absent" },
      },
    });
    const encoded = JSON.stringify(context);
    for (const value of ["8080", "from-the-shell", "eu-west", "not in the Contract", "info"]) expect(encoded).not.toContain(value);
  });

  it("is read by the Typed Accessor, like the strict run's context", () => {
    const context = exportedRunContext(MANIFEST.contract!, MANIFEST.environment, REVISION.contract as never, effective([]), {});
    const parsed = parseRunContext(JSON.stringify(context));
    expect(parsed.mode).toBe("exported");
    expect(parsed.environment).toEqual({ rootId: "env_dev", tier: "development" });
    expect(parsed.items.get("PORT")).toEqual({ server: "notStored", delivery: "absent" });
  });

  it("is prepared from the revision the manifest names, before anything is disclosed, and added to the child's environment", async () => {
    const calls: string[] = [];
    const first = effective([{ name: "PORT", value: "8080" }]);
    const encode = await prepareExportedContext(client(REVISION, calls), "acme", "api", first);
    expect(calls).toEqual([`acme/api/${REVISION.id}`]);

    // The run: disclosure fills a Secret, then the environment is built.
    const after = effective([
      { name: "PORT", value: "8080" },
      { name: "API_KEY", value: "sk-disclosed", sensitive: true },
    ]);
    const parent = { PATH: "/bin", [RUN_CONTEXT]: '{"stale":true}' };
    const env = buildEnv(parent, after);
    env[RUN_CONTEXT] = encode(after, parent);
    const context = JSON.parse(env[RUN_CONTEXT] as string);
    expect(context.mode).toBe("exported");
    expect(context.items.API_KEY).toEqual({ server: "delivered", delivery: "varlatch" });
    expect(env[RUN_CONTEXT]).not.toContain("sk-disclosed");
    expect(env.PATH).toBe("/bin");
    expect(env.API_KEY).toBe("sk-disclosed");
  });

  it("fails, naming the fix, without a manifest, without an active Contract, or without contract.read", async () => {
    await expect(prepareExportedContext(client(), "acme", "api", effective([], null))).rejects.toThrow(
      "--export-context needs a server that returns a state manifest with the configuration: Varlatch 0.11.0 or later",
    );
    const undigested = effective([]);
    delete undigested.stateDigest;
    await expect(prepareExportedContext(client(), "acme", "api", undigested)).rejects.toThrow(
      "--export-context needs a server that returns a state manifest with the configuration: Varlatch 0.11.0 or later",
    );
    await expect(prepareExportedContext(client(), "acme", "api", effective([], { ...MANIFEST, contract: null }))).rejects.toThrow(
      "--export-context needs an active Contract",
    );
    for (const status of [403, 404]) {
      const denied: ExportContextClient = {
        getContractRevision: async () => {
          throw new VarlatchApiError(status, { code: status === 403 ? "PERMISSION_DENIED" : "RESOURCE_NOT_FOUND", message: "no", requestId: "r" });
        },
      };
      await expect(prepareExportedContext(denied, "acme", "api", effective([]))).rejects.toThrow(
        "--export-context needs contract.read on the project",
      );
    }
    const other = revision([contractItem("OTHER")]);
    await expect(prepareExportedContext(client(other), "acme", "api", effective([]))).rejects.toThrow(ExportContextError);
  });

  it("fails rather than truncating a context over the size bound, before anything is disclosed", async () => {
    const items = Array.from({ length: 400 }, (_, i) => contractItem(`ITEM_${String(i).padStart(3, "0")}_${"X".repeat(180)}`));
    const big = revision(items);
    const manifest = { ...MANIFEST, contract: { revisionId: big.id, contentHash: big.contentHash, semanticsVersion: 2 } };
    await expect(prepareExportedContext(client(big), "acme", "api", effective([], manifest))).rejects.toThrow(
      "the run context would exceed 65536 bytes; it is never truncated",
    );
  });

  it("a default run without the flag still removes an inherited context", () => {
    const env = buildEnv({ [RUN_CONTEXT]: '{"v":1}', PATH: "/bin" }, effective([{ name: "PORT", value: "1" }]));
    expect(env[RUN_CONTEXT]).toBeUndefined();
  });
});

describe("reading the configuration and its Secrets consistently", () => {
  /** Reads that return the given digest pairs in order, recording each read. */
  function reads(pairs: [string | undefined, string | null | undefined][]) {
    const done: number[] = [];
    const read = async (): Promise<ConfigurationRead<number>> => {
      const [configurationDigest, disclosureDigest] = pairs[done.length]!;
      done.push(done.length + 1);
      return { configurationDigest, disclosureDigest, result: done.length };
    };
    return { read, done };
  }

  it("takes the first read when both responses carry the same digest", async () => {
    const { read, done } = reads([[DIGEST, DIGEST]]);
    const notices: string[] = [];
    expect(await readConsistently(read, (line) => notices.push(line))).toBe(1);
    expect(done).toEqual([1]);
    expect(notices).toEqual([]);
  });

  it("takes a read whose disclosure was refused: every value delivered came from the configuration", async () => {
    const { read, done } = reads([[DIGEST, null]]);
    expect(await readConsistently(read, () => {})).toBe(1);
    expect(done).toEqual([1]);
  });

  it("reads again when the digests differ, saying that it discloses again, and takes the read that agrees", async () => {
    const { read, done } = reads([
      [DIGEST, OTHER],
      [OTHER, OTHER],
    ]);
    const notices: string[] = [];
    expect(await readConsistently(read, (line) => notices.push(line))).toBe(2);
    expect(done).toEqual([1, 2]);
    expect(notices).toEqual([
      "varlatch: the configuration changed between reading it and disclosing its Secrets; reading both again (attempt 2 of 3, another audited disclosure)",
    ]);
  });

  it("does not take a disclosure without a digest as agreement", async () => {
    const { read, done } = reads([
      [DIGEST, undefined],
      [DIGEST, DIGEST],
    ]);
    expect(await readConsistently(read, () => {})).toBe(2);
    expect(done).toEqual([1, 2]);
  });

  it(`refuses after ${EXPORT_CONTEXT_ATTEMPTS} reads that never agree`, async () => {
    expect(EXPORT_CONTEXT_ATTEMPTS).toBe(3);
    const { read, done } = reads([
      [DIGEST, OTHER],
      [OTHER, DIGEST],
      [DIGEST, undefined],
      [DIGEST, DIGEST],
    ]);
    const notices: string[] = [];
    const refused = readConsistently(read, (line) => notices.push(line));
    await expect(refused).rejects.toThrow(ExportContextError);
    await expect(refused).rejects.toThrow(
      "the configuration changed between reading it and disclosing its Secrets, on each of 3 attempts, so the run context could not describe the values delivered",
    );
    expect(done).toEqual([1, 2, 3]);
    expect(notices).toHaveLength(2);
  });
});
