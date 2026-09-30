// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { LATEST_SEMANTICS_VERSION, SEMANTICS_VERSIONS, contractHash, normalizeContract } from "@varlatch/contract";
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
 * Every Contract Revision carries a semantics version, fixed when it is
 * created. A pushed Contract that names one pins it; otherwise the revision
 * keeps the active revision's version, and a project with no active
 * revision gets the newest. Validation evaluates with the revision's version.
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let token: string;

const P = "/v1/organizations/acme/projects/api";
const E = `${P}/environments/development`;

async function call(method: string, path: string, body?: unknown) {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: res.status, body: (await res.json().catch(() => null)) as Record<string, unknown> };
}

function contract(description: string, semanticsVersion?: number) {
  return {
    schemaVersion: 1,
    ...(semanticsVersion === undefined ? {} : { semanticsVersion }),
    items: [{ name: "PORT", required: { kind: "always" }, sensitive: false, type: "number", description }],
  };
}

async function push(body: unknown) {
  const res = await call("POST", `${P}/contract/revisions`, { contract: body });
  expect(res.status).toBe(201);
  return res.body as { id: string; contentHash: string; semanticsVersion: number; contract: { semanticsVersion?: number } };
}

async function activate(id: string) {
  expect((await call("POST", `${P}/contract/revisions/${id}/activate`, {})).status).toBe(200);
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
  expect((await call("POST", `${P}/environments`, { name: "development", tier: "development" })).status).toBe(201);
});
afterEach(async () => {
  await ctx.close();
});

describe("Contract Revision semantics version", () => {
  it("/v1/meta lists the versions the server evaluates", async () => {
    const meta = await app.request("/v1/meta");
    expect(((await meta.json()) as { semanticsVersions: number[] }).semanticsVersions).toEqual([...SEMANTICS_VERSIONS]);
  });

  it("a project's first revision gets the newest version, and edits keep it", async () => {
    const first = await push(contract("listen port"));
    expect(first.semanticsVersion).toBe(LATEST_SEMANTICS_VERSION);
    expect(first.contract.semanticsVersion).toBe(LATEST_SEMANTICS_VERSION);
    await activate(first.id);
    const edited = await push(contract("the port to listen on"));
    expect(edited.semanticsVersion).toBe(LATEST_SEMANTICS_VERSION);
  });

  it("a version 1 project stays at version 1 until a push pins another", async () => {
    // Pinned to 1, stored exactly as a revision from before versions existed.
    const legacy = await push(contract("listen port", 1));
    expect(legacy.semanticsVersion).toBe(1);
    expect(legacy.contract).not.toHaveProperty("semanticsVersion");
    expect(legacy.contentHash).toBe(contractHash(normalizeContract(contract("listen port"))));
    await activate(legacy.id);

    // A description-only edit never migrates the rules.
    const edited = await push(contract("the port to listen on"));
    expect(edited.semanticsVersion).toBe(1);
    await activate(edited.id);

    // An explicit upgrade: same items, a different revision and hash.
    const upgraded = await push(contract("the port to listen on", 2));
    expect(upgraded.semanticsVersion).toBe(2);
    expect(upgraded.id).not.toBe(edited.id);
    expect(upgraded.contentHash).not.toBe(edited.contentHash);
    await activate(upgraded.id);

    const activation = await ctx.db.query(
      "SELECT metadata FROM audit_events WHERE event_type = 'contract.activated' ORDER BY event_order DESC LIMIT 1",
    );
    const metadata = (activation.rows[0] as { metadata: unknown }).metadata;
    expect(typeof metadata === "string" ? JSON.parse(metadata) : metadata).toMatchObject({
      semanticsVersionFrom: 1,
      semanticsVersionTo: 2,
    });

    // Pinning back to 1 is allowed while the server supports it.
    expect((await push(contract("the port to listen on", 1))).semanticsVersion).toBe(1);
  });

  it("refuses a version the server does not evaluate, naming it", async () => {
    const res = await call("POST", `${P}/contract/revisions`, { contract: contract("listen port", 4) });
    expect(res.status).toBe(422);
    expect(JSON.stringify(res.body)).toContain("version 4 is not supported (supported: 1, 2, 3)");
    const revisions = await ctx.db.query("SELECT count(*)::int AS n FROM contract_revisions");
    expect((revisions.rows[0] as { n: number }).n).toBe(0);
  });

  it("validation evaluates with the active revision's version", async () => {
    // Above 2^53 - 1: valid under version 1, invalid under version 2.
    expect((await call("PUT", `${E}/values/PORT`, { value: "9007199254740993" })).status).toBe(200);

    await activate((await push(contract("listen port", 1))).id);
    const v1 = await call("POST", `${E}/validate`, {});
    expect(v1.body).toMatchObject({ valid: true, invalid: [] });

    await activate((await push(contract("listen port", 2))).id);
    const v2 = await call("POST", `${E}/validate`, {});
    expect(v2.body).toMatchObject({
      valid: false,
      invalid: [{ name: "PORT", reason: "must be a number no larger in magnitude than 2^53 - 1" }],
    });
  });
});

describe("a Contract Revision by ID", () => {
  it("returns any stored revision with its semantics version and content hash, active or not", async () => {
    const legacy = await push(contract("listen port", 1));
    const current = await push(contract("listen port", 2));
    await activate(current.id);

    const byId = await call("GET", `${P}/contract/revisions/${legacy.id}`);
    expect(byId.status).toBe(200);
    expect(byId.body).toMatchObject({ id: legacy.id, contentHash: legacy.contentHash, semanticsVersion: 1, active: false });
    expect(contractHash(normalizeContract(byId.body.contract))).toBe(legacy.contentHash);

    const active = await call("GET", `${P}/contract/revisions/${current.id}`);
    expect(active.body).toMatchObject({ id: current.id, semanticsVersion: 2, active: true });
    expect((await app.request("/v1/meta").then((r) => r.json()) as { capabilities: string[] }).capabilities).toContain(
      "contracts.revision-by-id",
    );
  });

  it("is not found for an unknown ID or another project's revision, and needs contract.read", async () => {
    const own = await push(contract("listen port"));
    expect((await call("GET", `${P}/contract/revisions/crv_unknown`)).status).toBe(404);

    await call("POST", "/v1/organizations/acme/projects", { name: "Web", slug: "web", contractAuthority: "managed" });
    expect((await call("GET", `/v1/organizations/acme/projects/web/contract/revisions/${own.id}`)).status).toBe(404);

    // Denied exactly as the active Contract is.
    await activate(own.id);
    const member = await call("POST", "/v1/organizations/acme/identities", { name: "no-grants", kind: "service" });
    const as = (path: string) => app.request(path, { headers: { Authorization: `Bearer ${member.body.credential as string}` } });
    const byId = await as(`${P}/contract/revisions/${own.id}`);
    expect(byId.status).toBe(403);
    expect(((await byId.json()) as { error: { code: string } }).error.code).toBe("PERMISSION_DENIED");
    expect((await as(`${P}/contract`)).status).toBe(403);
  });
});

describe("the integer type (ADR-0042)", () => {
  function withInteger(semanticsVersion?: number) {
    return {
      schemaVersion: 1,
      ...(semanticsVersion === undefined ? {} : { semanticsVersion }),
      items: [
        { name: "PORT", required: { kind: "always" }, sensitive: false, type: "integer" },
        { name: "RATIO", required: { kind: "never" }, sensitive: false, type: "number" },
      ],
    };
  }

  it("a push that keeps an older version is refused with the fix, and stores nothing", async () => {
    await activate((await push(contract("listen port", 2))).id);
    const res = await call("POST", `${P}/contract/revisions`, { contract: withInteger() });
    expect(res.status).toBe(422);
    expect(JSON.stringify(res.body)).toContain(
      "PORT: type integer needs Contract Semantics version 3 or later, and this Contract uses version 2",
    );
    expect(JSON.stringify(res.body)).toContain("--semantics latest");
    const pinnedOld = await call("POST", `${P}/contract/revisions`, { contract: withInteger(2) });
    expect(pinnedOld.status).toBe(422);
    const revisions = await ctx.db.query("SELECT count(*)::int AS n FROM contract_revisions");
    expect((revisions.rows[0] as { n: number }).n).toBe(1);
  });

  it("after a move to version 3, pushes that name no version keep it, as Git pushes do", async () => {
    await activate((await push(contract("listen port", 1))).id);
    // The move: the same items, pinned to the newest version.
    const moved = await push(contract("listen port", 3));
    expect(moved.semanticsVersion).toBe(3);
    await activate(moved.id);
    // A later push from a file that names no version (`varlatch contract push --schema`).
    const next = await push(withInteger());
    expect(next.semanticsVersion).toBe(3);
    expect(next.contract.semanticsVersion).toBe(3);
    await activate(next.id);
    expect((await push(contract("a description edit"))).semanticsVersion).toBe(3);
  });

  it("validates whole numbers only, while number keeps accepting fractions", async () => {
    await activate((await push(withInteger(3))).id);
    expect((await call("PUT", `${E}/values/PORT`, { value: "3.0" })).status).toBe(200);
    expect((await call("PUT", `${E}/values/RATIO`, { value: "3.5" })).status).toBe(200);
    const invalid = await call("POST", `${E}/validate`, {});
    expect(invalid.body).toMatchObject({ valid: false, invalid: [{ name: "PORT", reason: "must be a whole number" }] });
    expect((await call("PUT", `${E}/values/PORT`, { value: "3000" })).status).toBe(200);
    expect((await call("POST", `${E}/validate`, {})).body).toMatchObject({ valid: true, invalid: [] });
  });
});

