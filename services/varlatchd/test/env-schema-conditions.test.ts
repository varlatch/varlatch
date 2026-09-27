// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { diffContracts, type ConfigurationContract } from "@varlatch/contract";
import { parseEnvSchema, resolveDraft } from "@varlatch/env-schema";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import {
  consumeSetupGrant,
  ensureInstallation,
  issueBootstrapGrant,
} from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * `.env.schema` conditions name Environments: `env(...)` is resolved to root
 * Environment IDs when a Contract is pushed, exactly as `varlatch contract
 * push --schema` does. A stored revision keeps the IDs it was resolved to;
 * a later push resolves names again, so a reused name selects the new
 * Environment and shows up as a requiredness change.
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let token: string;

const P = "/v1/organizations/acme/projects/api";

async function call(method: string, path: string, body?: unknown) {
  return app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

/** What the CLI does on `contract push --schema`: parse, resolve names, push. */
async function pushSchema(schema: string): Promise<string> {
  const draft = parseEnvSchema(schema);
  const envs = (await (await call("GET", `${P}/environments`)).json()).items as {
    id: string;
    name: string;
    parentEnvironmentId: string | null;
  }[];
  const contract = resolveDraft(
    draft,
    envs.map((e) => ({ id: e.id, name: e.name, parentEnvironmentId: e.parentEnvironmentId ?? null })),
  );
  const res = await call("POST", `${P}/contract/revisions`, { contract });
  expect(res.status).toBe(201);
  return (await res.json()).id as string;
}

async function activate(revisionId: string) {
  const res = await call("POST", `${P}/contract/revisions/${revisionId}/activate`, {});
  expect(res.status).toBe(200);
}

async function stored(revisionId: string): Promise<ConfigurationContract> {
  const row = (await ctx.db.query("SELECT contract FROM contract_revisions WHERE id = $1", [revisionId]))
    .rows[0] as { contract: unknown };
  return (typeof row.contract === "string" ? JSON.parse(row.contract) : row.contract) as ConfigurationContract;
}

async function envId(name: string): Promise<string> {
  return (await (await call("GET", `${P}/environments/${name}`)).json()).id as string;
}

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId } = await consumeSetupGrant(ctx, grant.token, { adminName: "Admin" });
  token = (await issueCredential(ctx.db, { identityId, kind: "cli" })).token;
  app = buildApp(ctx);
  await call("POST", "/v1/organizations", { name: "Acme", slug: "acme" });
  await call("POST", "/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "git" });
  for (const [name, tier] of [["development", "development"], ["staging", "staging"]]) {
    expect((await call("POST", `${P}/environments`, { name, tier })).status).toBe(201);
  }
});
afterEach(async () => {
  await ctx.close();
});

describe(".env.schema environment conditions", () => {
  it("env(...) stores the root Environment's ID, and tier(...) the tier selector", async () => {
    const rev = await pushSchema(
      "# @required=env(staging)\nSTAGING_ONLY=\n\n# @required=tier(production)\nPROD_TIER=\n",
    );
    const contract = await stored(rev);
    const byName = new Map(contract.items.map((i) => [i.name, i]));
    expect(byName.get("STAGING_ONLY")?.required).toEqual({
      kind: "selector",
      selector: { kind: "environments", environmentIds: [await envId("staging")] },
    });
    expect(byName.get("PROD_TIER")?.required).toEqual({
      kind: "selector",
      selector: { kind: "tier", tier: "production" },
    });
  });

  it("a reused name: the stored revision keeps the old ID, a new push selects the new Environment", async () => {
    const schema = "# @required=env(staging)\nKEY=\n";
    const first = await pushSchema(schema);
    await activate(first);
    const oldStaging = await envId("staging");

    // Free the name: a revision that no longer references staging, then delete it.
    await activate(await pushSchema("# @optional\nKEY=\n"));
    expect((await call("DELETE", `${P}/environments/staging`)).status).toBe(204);
    expect((await call("POST", `${P}/environments`, { name: "staging", tier: "staging" })).status).toBe(201);
    const newStaging = await envId("staging");
    expect(newStaging).not.toBe(oldStaging);

    // The same schema, pushed again, resolves the name again.
    const second = await pushSchema(schema);
    expect(second).not.toBe(first);
    const before = await stored(first);
    const after = await stored(second);
    expect(before.items[0]?.required).toEqual({
      kind: "selector",
      selector: { kind: "environments", environmentIds: [oldStaging] },
    });
    expect(after.items[0]?.required).toEqual({
      kind: "selector",
      selector: { kind: "environments", environmentIds: [newStaging] },
    });
    // The change is visible as a requiredness change, not silent.
    expect(diffContracts(before, after).requirednessChanged.map((c) => c.name)).toEqual(["KEY"]);
  });

  it("an unknown name fails before anything is pushed", async () => {
    await expect(pushSchema("# @required=env(prod)\nKEY=\n")).rejects.toThrow(
      /unknown environment name\(s\) in env\(\.\.\.\): prod\. This project's root environments: development, staging\./,
    );
    const revisions = await ctx.db.query("SELECT count(*)::int AS n FROM contract_revisions");
    expect((revisions.rows[0] as { n: number }).n).toBe(0);
  });
});
