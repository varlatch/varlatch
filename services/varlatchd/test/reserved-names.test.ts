// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
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
 * VARLATCH_RUN_CONTEXT is launcher metadata that `varlatch run` sets itself:
 * no Contract item and no stored value may take the name.
 */

const P = "/v1/organizations/acme/projects/api";
const E = `${P}/environments/development`;
let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let token: string;

async function call(method: string, path: string, body?: unknown) {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: res.status, text: await res.text() };
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
  await call("POST", "/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "managed" });
  await call("POST", `${P}/environments`, { name: "development", tier: "development" });
});
afterEach(async () => {
  await ctx.close();
});

describe("the reserved run-context name", () => {
  it("cannot be a Contract item", async () => {
    const res = await call("POST", `${P}/contract/revisions`, {
      contract: {
        schemaVersion: 1,
        items: [{ name: "VARLATCH_RUN_CONTEXT", required: { kind: "never" }, sensitive: false, type: "string" }],
      },
    });
    expect(res.status).toBe(422);
    expect(res.text).toContain("reserved for launcher metadata");
  });

  it("cannot be stored, rotated, or written in a change set", async () => {
    expect((await call("PUT", `${E}/values/VARLATCH_RUN_CONTEXT`, { value: "{}" })).status).toBe(422);
    expect((await call("POST", `${E}/values/VARLATCH_RUN_CONTEXT/rotations`, { value: "{}" })).status).toBe(422);
    const changes = await call("POST", `${E}/changes`, {
      changes: [{ op: "set", item: "VARLATCH_RUN_CONTEXT", value: "{}" }],
    });
    expect(changes.status).toBe(422);
    const stored = await ctx.db.query("SELECT count(*)::int AS n FROM env_values WHERE item_name = 'VARLATCH_RUN_CONTEXT'");
    expect((stored.rows[0] as { n: number }).n).toBe(0);
  });
});
