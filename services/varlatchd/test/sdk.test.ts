// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { VarlatchApiError, VarlatchClient } from "@varlatch/sdk";
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

let ctx: AppCtx & { close: () => Promise<void> };
let client: VarlatchClient;
let fetchImpl: typeof fetch;

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId } = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
  const cred = await issueCredential(ctx.db, { identityId, kind: "cli" });
  const app = buildApp(ctx);
  // The SDK exercises the exact same /v1 surface third parties get (ADR-0018 §7).
  fetchImpl = (input, init) =>
    app.request(input instanceof Request ? input : String(input).replace("http://varlatch", ""), init);
  client = new VarlatchClient({ server: "http://varlatch", token: cred.token, fetch: fetchImpl });
});
afterEach(async () => {
  await ctx.close();
});

describe("SDK against the real app", () => {
  it("drives the golden-path core loop end to end", async () => {
    expect((await client.meta()).apiMajor).toBe(1);

    const org = await client.createOrganization({ name: "Acme", slug: "acme" });
    const project = await client.createProject("acme", {
      name: "API",
      slug: "api",
      contractAuthority: "git",
    });
    expect(project.organizationId).toBe(org.id);

    await client.createEnvironment("acme", "api", { name: "development", tier: "development" });

    const revision = await client.pushContractRevision("acme", "api", {
      contract: {
        schemaVersion: 1,
        items: [
          { name: "DATABASE_URL", required: { kind: "always" }, sensitive: true, type: "url" },
          { name: "PORT", required: { kind: "never" }, sensitive: false, type: "number" },
        ],
      },
      provenance: { commitSha: "abc123" },
    });
    await client.activateContractRevision("acme", "api", revision.id);
    const fetched = await client.getContractRevision("acme", "api", revision.id);
    expect(fetched).toMatchObject({ id: revision.id, contentHash: revision.contentHash, active: true });

    await client.setValue("acme", "api", "development", "DATABASE_URL", {
      value: "postgres://dev",
    });
    await client.setValue(
      "acme",
      "api",
      "development",
      "PORT",
      { value: "3000" },
      { idempotencyKey: "ci-run-1" },
    );

    const report = await client.validateEnvironment("acme", "api", "development");
    expect(report.valid).toBe(true);

    const effective = await client.effectiveConfiguration("acme", "api", "development", {
      includeValues: true,
    });
    // Non-sensitive values arrive normally; Secrets require disclosure.
    expect(effective.items?.map((i) => [i.name, i.value])).toEqual([
      ["DATABASE_URL", null],
      ["PORT", "3000"],
    ]);
    const disclosed = await client.discloseSecrets("acme", "api", "development", {
      items: ["DATABASE_URL"],
    });
    expect(disclosed.items).toEqual([
      expect.objectContaining({ name: "DATABASE_URL", value: "postgres://dev" }),
    ]);

    const changeSet = await client.applyChangeSet(
      "acme",
      "api",
      "development",
      [{ op: "set", item: "PORT", value: "3001" }],
      { idempotencyKey: "review-1" },
    );
    expect(changeSet.changeSetId).toMatch(/^cs_/);

    const identity = await client.createIdentity("acme", { name: "deploy", kind: "service" });
    expect(identity.credential).toMatch(/^vlt_svc_/);
    await client.createGrant("acme", {
      subjectIdentityId: identity.id as string,
      scope: {
        kind: "environments",
        projectId: project.id,
        selector: { kind: "tier", tier: "development" },
      },
      actions: ["config.metadata.read", "config.value.read", "secret.reveal"],
    });

    const events = await client.listAuditEvents("acme", { limit: 5 });
    expect(events.items.length).toBe(5);
    const ndjson = await client.exportAuditEventsNdjson("acme");
    expect(ndjson.trim().split("\n").length).toBeGreaterThan(5);
  });

  it("deletes environments over HTTP with reference guards (ADR-0025)", async () => {
    await client.createOrganization({ name: "Acme", slug: "acme" });
    await client.createProject("acme", { name: "API", slug: "api", contractAuthority: "git" });
    const dev = await client.createEnvironment("acme", "api", {
      name: "development",
      tier: "development",
    });
    const preview = await client.createEnvironment("acme", "api", {
      name: "development/pr-1",
      parentEnvironmentId: dev.id as string,
      kind: "preview",
    });

    // Root blocked while a live child exists; child-then-root succeeds.
    const blocked = await client
      .deleteEnvironment("acme", "api", "development")
      .catch((e: unknown) => e);
    expect((blocked as VarlatchApiError).code).toBe("VALIDATION_FAILED");
    await client.deleteEnvironment("acme", "api", preview.name as string);

    await client.deleteEnvironment("acme", "api", "development");
    expect((await client.listEnvironments("acme", "api")).items).toEqual([]);

    const gone = await client
      .deleteEnvironment("acme", "api", "development")
      .catch((e: unknown) => e);
    expect((gone as VarlatchApiError).code).toBe("RESOURCE_NOT_FOUND");
  });

  it("says who the caller is, a person or a machine, and refuses a revoked credential (identity.whoami)", async () => {
    expect((await client.meta()).capabilities).toContain("identity.whoami");
    expect(await client.whoami()).toMatchObject({
      identity: { kind: "human", name: "Jeremy", email: null },
      organization: null,
      credential: { kind: "cli" },
      listener: "ordinary",
    });
    await client.createOrganization({ name: "Acme", slug: "acme" });
    const runner = await client.createIdentity("acme", { name: "runner-macmini", kind: "service" });
    const issued = await client.issueMachineCredential("acme", runner.id, { name: "desktop-runner" });
    const machine = new VarlatchClient({ server: "http://varlatch", token: issued.token, fetch: fetchImpl });
    expect(await machine.whoami()).toEqual({
      identity: { id: runner.id, name: "runner-macmini", kind: "service", email: null },
      organization: expect.objectContaining({ slug: "acme", name: "Acme" }),
      credential: { id: issued.id, name: "desktop-runner", kind: "service", expiresAt: null },
      listener: "ordinary",
    });
    await client.revokeIdentityCredential("acme", runner.id, issued.id);
    const refused = await machine.whoami().catch((e: unknown) => e);
    expect(refused).toBeInstanceOf(VarlatchApiError);
    expect((refused as VarlatchApiError).code).toBe("INVALID_CREDENTIAL");
  });

  it("surfaces the error envelope as typed errors", async () => {
    await client.createOrganization({ name: "Acme", slug: "acme" });
    const err = await client.getOrganization("nope").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VarlatchApiError);
    expect((err as VarlatchApiError).code).toBe("RESOURCE_NOT_FOUND");
    expect((err as VarlatchApiError).requestId).toMatch(/^req_/);

    const unauth = new VarlatchClient({
      server: "http://varlatch",
      fetch: (input, init) =>
        buildApp(ctx).request(input instanceof Request ? input : String(input).replace("http://varlatch", ""), init),
    });
    const e2 = await unauth.listOrganizations().catch((e: unknown) => e);
    expect((e2 as VarlatchApiError).code).toBe("AUTHENTICATION_REQUIRED");
  });
});
