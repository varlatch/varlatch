// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { generateKey } from "../src/crypto/aead.js";
import { newId } from "../src/db/ids.js";
import { runMigrations } from "../src/db/migrate.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { DomainError } from "../src/domain/errors.js";
import { createOrganization, getOrganization } from "../src/domain/orgs.js";
import { createProject, getProject } from "../src/domain/projects.js";
import {
  createEnvironment,
  deleteEnvironment,
  getEnvironment,
  listEnvironments,
} from "../src/domain/environments.js";
import { activateRevision, pushRevision } from "../src/domain/contracts.js";
import {
  beginRotation,
  completeRotation,
  deleteValue,
  setValue,
} from "../src/domain/values.js";
import * as values from "../src/domain/values.js";
import type { EnvironmentRow } from "../src/domain/environments.js";
import type { OrgRow } from "../src/domain/orgs.js";
import type { ProjectRow } from "../src/domain/projects.js";
import { captureState, inSnapshot } from "../src/domain/retrieval.js";
import { testDb } from "./helpers/pglite.js";

let ctx: AppCtx & { close: () => Promise<void> };

/** Capture the whole Environment in one snapshot, as the HTTP handlers do. */
const capture = (org: OrgRow, project: ProjectRow, env: EnvironmentRow) =>
  inSnapshot(ctx, (sctx, now) => captureState(sctx, { org, project, env }, now, () => true));
const resolveItems = async (_: AppCtx, org: OrgRow, project: ProjectRow, env: EnvironmentRow) =>
  (await capture(org, project, env)).items;
const effectiveConfiguration = async (
  _: AppCtx, org: OrgRow, project: ProjectRow, env: EnvironmentRow,
  opts: Parameters<typeof values.effectiveConfiguration>[2],
) => (await values.effectiveConfiguration(ctx, await capture(org, project, env), opts)).items;
const discloseSecrets = async (
  _: AppCtx, org: OrgRow, project: ProjectRow, env: EnvironmentRow,
  request: values.DisclosureRequest, opts: Parameters<typeof values.discloseSecrets>[3],
) => values.discloseSecrets(ctx, await capture(org, project, env), request, opts);
const validateEnvironment = async (
  _: AppCtx, org: OrgRow, project: ProjectRow, env: EnvironmentRow,
  opts: Parameters<typeof values.validateEnvironment>[2],
) => values.validateEnvironment(ctx, await capture(org, project, env), opts);
const actor = newId("identity");
// Domain tests exercise the rules, not authorization: every class allowed.
const fullValidation = {
  access: {
    metadata: async () => "allowed" as const,
    plain: async () => "allowed" as const,
    secret: async () => "allowed" as const,
  },
  actorIdentityId: actor,
};

beforeEach(async () => {
  const db = await testDb();
  await runMigrations(db);
  await db.query("INSERT INTO identities (id, kind, name) VALUES ($1,'human','Jeremy')", [actor]);
  ctx = { db, rootKek: generateKey(), close: db.close };
});
afterEach(async () => {
  await ctx.close();
});

const contract = {
  schemaVersion: 1,
  items: [
    { name: "DATABASE_URL", required: { kind: "always" }, sensitive: true, type: "url" },
    { name: "PORT", required: { kind: "never" }, sensitive: false, type: "number", defaultValue: "3000" },
    {
      name: "STRIPE_SECRET_KEY",
      required: { kind: "selector", selector: { kind: "tier", tier: "production" } },
      sensitive: true,
      type: "string",
    },
  ],
};

async function setup() {
  const org = await createOrganization(ctx, { slug: "acme", name: "Acme" }, actor);
  const project = await createProject(
    ctx,
    org.id,
    { slug: "api", name: "API", contractAuthority: "git" },
    actor,
  );
  const dev = await createEnvironment(
    ctx,
    org.id,
    project.id,
    { name: "development", tier: "development" },
    actor,
  );
  const prod = await createEnvironment(
    ctx,
    org.id,
    project.id,
    { name: "production", tier: "production" },
    actor,
  );
  return { org, project, dev, prod };
}

describe("organizations", () => {
  it("creator becomes org admin and gets a wrapped org KEK", async () => {
    const org = await createOrganization(ctx, { slug: "acme", name: "Acme" }, actor);
    expect(org.wrapped_org_kek).toBeTruthy();
    const role = await ctx.db.query(
      "SELECT role FROM org_memberships WHERE organization_id = $1 AND identity_id = $2",
      [org.id, actor],
    );
    expect((role.rows[0] as { role: string }).role).toBe("admin");
    expect(await getOrganization(ctx, "acme")).toMatchObject({ id: org.id });
  });

  it("rejects duplicate slugs with VALIDATION_FAILED", async () => {
    await createOrganization(ctx, { slug: "acme", name: "A" }, actor);
    await expect(createOrganization(ctx, { slug: "acme", name: "B" }, actor)).rejects.toMatchObject(
      { code: "VALIDATION_FAILED" },
    );
  });
});

describe("environments", () => {
  it("enforces derivation rules", async () => {
    const { org, project, dev, prod } = await setup();
    const personal = await createEnvironment(
      ctx,
      org.id,
      project.id,
      { name: "development/jeremy", parentEnvironmentId: dev.id },
      actor,
    );
    expect(personal).toMatchObject({ kind: "personal", tier: "development", owner_identity_id: actor });
    // No grandchildren.
    await expect(
      createEnvironment(
        ctx,
        org.id,
        project.id,
        { name: "development/jeremy/x", parentEnvironmentId: personal.id },
        actor,
      ),
    ).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
    // No personal children of production.
    await expect(
      createEnvironment(
        ctx,
        org.id,
        project.id,
        { name: "production/jeremy", parentEnvironmentId: prod.id },
        actor,
      ),
    ).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
    // Preview of production is allowed; tier is inherited and unchangeable.
    await expect(
      createEnvironment(
        ctx,
        org.id,
        project.id,
        { name: "production/pr-1", parentEnvironmentId: prod.id, kind: "preview", tier: "development" },
        actor,
      ),
    ).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
    const preview = await createEnvironment(
      ctx,
      org.id,
      project.id,
      { name: "production/pr-1", parentEnvironmentId: prod.id, kind: "preview" },
      actor,
    );
    expect(preview.tier).toBe("production");
  });
});

describe("environment removal (ADR-0025)", () => {
  it("tombstones, disappears from reads, audits, and frees the name", async () => {
    const { org, project, dev } = await setup();
    await deleteEnvironment(ctx, org.id, project, dev, actor);
    await expect(getEnvironment(ctx, project.id, "development")).rejects.toMatchObject({
      code: "RESOURCE_NOT_FOUND",
    });
    expect((await listEnvironments(ctx, project.id)).map((e) => e.name)).not.toContain(
      "development",
    );
    // Tombstone, not row removal: audit keeps a resolvable subject.
    const raw = await ctx.db.query("SELECT deleted_at FROM environments WHERE id = $1", [dev.id]);
    expect((raw.rows[0] as { deleted_at: string | null }).deleted_at).toBeTruthy();
    const audit = await ctx.db.query(
      "SELECT resource FROM audit_events WHERE event_type = 'environment.deleted'",
    );
    expect(audit.rows).toHaveLength(1);
    // The name is free for reuse; the successor is a new identity.
    const successor = await createEnvironment(
      ctx,
      org.id,
      project.id,
      { name: "development", tier: "development" },
      actor,
    );
    expect(successor.id).not.toBe(dev.id);
  });

  it("refuses a root with live derived children; child-then-root succeeds", async () => {
    const { org, project, dev } = await setup();
    const child = await createEnvironment(
      ctx,
      org.id,
      project.id,
      { name: "development/jeremy", parentEnvironmentId: dev.id },
      actor,
    );
    await expect(deleteEnvironment(ctx, org.id, project, dev, actor)).rejects.toMatchObject({
      code: "VALIDATION_FAILED",
    });
    await deleteEnvironment(ctx, org.id, project, child, actor);
    await deleteEnvironment(ctx, org.id, project, dev, actor);
  });

  it("blocks while the active Contract's selector references the environment", async () => {
    const { org, project, dev } = await setup();
    const rev = await pushRevision(
      ctx,
      org.id,
      project.id,
      {
        schemaVersion: 1,
        items: [
          {
            name: "ONLY_HERE",
            required: {
              kind: "selector",
              selector: { kind: "environments", environmentIds: [dev.id] },
            },
            sensitive: true,
            type: "string",
          },
        ],
      },
      undefined,
      actor,
    );
    await activateRevision(ctx, org.id, await getProject(ctx, org.id, project.id), rev.id, actor);
    const projectRow = await getProject(ctx, org.id, project.id);
    await expect(deleteEnvironment(ctx, org.id, projectRow, dev, actor)).rejects.toMatchObject({
      code: "VALIDATION_FAILED",
    });
  });

  it("soft-deletes values and revokes outstanding capabilities transactionally", async () => {
    const { org, project, dev } = await setup();
    await setValue(ctx, org, project, dev, "API_KEY", { value: "s3cret" }, actor);
    await ctx.db.query(
      `INSERT INTO capabilities
         (id, organization_id, broker_identity_id, agent_identity_id, project_id,
          environment_id, items, destinations, secret_hash, expires_at, created_by)
       VALUES ($1,$2,$3,$3,$4,$5,'{API_KEY}','{api.example.com:443}','h', now() + interval '1 hour', $3)`,
      [newId("capability"), org.id, actor, project.id, dev.id],
    );
    await deleteEnvironment(ctx, org.id, project, dev, actor);
    const values = await ctx.db.query(
      "SELECT deleted_at, current_version_id FROM env_values WHERE environment_id = $1",
      [dev.id],
    );
    for (const row of values.rows as { deleted_at: string | null; current_version_id: string | null }[]) {
      expect(row.deleted_at).toBeTruthy();
      expect(row.current_version_id).toBeNull();
    }
    const caps = await ctx.db.query(
      "SELECT revoked_at FROM capabilities WHERE environment_id = $1",
      [dev.id],
    );
    expect((caps.rows[0] as { revoked_at: string | null }).revoked_at).toBeTruthy();
  });
});

describe("values and effective configuration", () => {
  it("round-trips with inheritance, sensitivity gating, and audited disclosure", async () => {
    const { org, project, dev } = await setup();
    const rev = await pushRevision(ctx, org.id, project.id, contract, undefined, actor);
    await activateRevision(ctx, org.id, await getProject(ctx, org.id, project.id), rev.id, actor);
    const projectRow = await getProject(ctx, org.id, project.id);

    await setValue(ctx, org, projectRow, dev, "DATABASE_URL", { value: "postgres://dev" }, actor);
    await setValue(ctx, org, projectRow, dev, "PORT", { value: "3000" }, actor);

    const personal = await createEnvironment(
      ctx,
      org.id,
      project.id,
      { name: "development/jeremy", parentEnvironmentId: dev.id },
      actor,
    );
    await setValue(ctx, org, projectRow, personal, "PORT", { value: "4000" }, actor);

    const items = await effectiveConfiguration(ctx, org, projectRow, personal, {
      includeValues: true,
      mayReadValue: () => true,
      actorIdentityId: actor,
    });
    expect(items.map((i) => [i.name, i.value, i.source])).toEqual([
      ["DATABASE_URL", "postgres://dev", "parent"],
      ["PORT", "4000", "self"],
    ]);
    expect(items[0]?.sensitive).toBe(true);
    expect(items[1]?.sensitive).toBe(false);

    // Sensitivity gating withholds secrets when unauthorized.
    const gated = await effectiveConfiguration(ctx, org, projectRow, personal, {
      includeValues: true,
      mayReadValue: (sensitive) => !sensitive,
      actorIdentityId: actor,
    });
    expect(gated.find((i) => i.name === "DATABASE_URL")?.value).toBeNull();
    expect(gated.find((i) => i.name === "PORT")?.value).toBe("4000");

    // Disclosure was audited with item@version precision.
    const audit = await ctx.db.query(
      "SELECT metadata FROM audit_events WHERE event_type = 'value.disclosed' ORDER BY occurred_at",
    );
    expect(audit.rows.length).toBe(2);
  });

  it("optimistic concurrency rejects stale writes", async () => {
    const { org, project, dev } = await setup();
    const projectRow = await getProject(ctx, org.id, project.id);
    const v1 = await setValue(ctx, org, projectRow, dev, "PORT", { value: "1" }, actor);
    await setValue(ctx, org, projectRow, dev, "PORT", { value: "2", expectedVersionId: v1.versionId }, actor);
    await expect(
      setValue(ctx, org, projectRow, dev, "PORT", { value: "3", expectedVersionId: v1.versionId }, actor),
    ).rejects.toMatchObject({ code: "VERSION_CONFLICT" });
  });

  it("expired previews fail closed for retrieval and mutation", async () => {
    const { org, project, dev } = await setup();
    const projectRow = await getProject(ctx, org.id, project.id);
    const preview = await createEnvironment(
      ctx,
      org.id,
      project.id,
      {
        name: "development/pr-9",
        parentEnvironmentId: dev.id,
        kind: "preview",
        expiresAt: new Date(Date.now() - 1000).toISOString(),
      },
      actor,
    );
    await expect(
      effectiveConfiguration(ctx, org, projectRow, preview, {
        includeValues: true,
        mayReadValue: () => true,
        actorIdentityId: actor,
      }),
    ).rejects.toMatchObject({ code: "ENVIRONMENT_EXPIRED" });
    await expect(
      setValue(ctx, org, projectRow, preview, "PORT", { value: "1" }, actor),
    ).rejects.toMatchObject({ code: "ENVIRONMENT_EXPIRED" });
  });

  it("delete removes from resolution but keeps versions", async () => {
    const { org, project, dev } = await setup();
    const projectRow = await getProject(ctx, org.id, project.id);
    await setValue(ctx, org, projectRow, dev, "PORT", { value: "1" }, actor);
    await deleteValue(ctx, org, projectRow, dev, "PORT", actor);
    const items = await effectiveConfiguration(ctx, org, projectRow, dev, {
      includeValues: false,
      mayReadValue: () => false,
      actorIdentityId: actor,
    });
    expect(items).toEqual([]);
    const versions = await ctx.db.query("SELECT count(*)::int AS n FROM value_versions");
    expect((versions.rows[0] as { n: number }).n).toBe(1);
  });
});

describe("dual-phase rotation (ADR-0027)", () => {
  it("keeps the retiring value alongside the new primary, then drops it on complete", async () => {
    const { org, project, dev } = await setup();
    const projectRow = await getProject(ctx, org.id, project.id);
    const v1 = await setValue(ctx, org, projectRow, dev, "TOKEN", { value: "old" }, actor);

    const rot = await beginRotation(ctx, org, projectRow, dev, "TOKEN", { value: "new" }, actor);
    expect(rot.retiringVersionId).toBe(v1.versionId);
    expect(rot.primaryVersionId).not.toBe(v1.versionId);

    // Reads resolve the primary; the retiring version is pinned for the window.
    const resolved = await resolveItems(ctx, org, projectRow, dev);
    const token = resolved.find((i) => i.name === "TOKEN")!;
    expect(token.versionId).toBe(rot.primaryVersionId);
    expect(token.retiringVersionId).toBe(v1.versionId);

    // Disclosure exposes both values so a consumer can accept either.
    const disc = await discloseSecrets(ctx, org, projectRow, dev, { items: ["TOKEN"] }, { actorIdentityId: actor });
    expect(disc.items[0]!.value).toBe("new");
    expect(disc.items[0]!.retiring?.value).toBe("old");

    await completeRotation(ctx, org, projectRow, dev, "TOKEN", actor);
    const after = await resolveItems(ctx, org, projectRow, dev);
    expect(after.find((i) => i.name === "TOKEN")!.retiringVersionId).toBeUndefined();
    const discAfter = await discloseSecrets(ctx, org, projectRow, dev, { items: ["TOKEN"] }, { actorIdentityId: actor });
    expect(discAfter.items[0]!.retiring).toBeUndefined();
  });

  it("drops the retiring value once the deadline elapses, without a cleanup worker", async () => {
    const { org, project, dev } = await setup();
    const projectRow = await getProject(ctx, org.id, project.id);
    await setValue(ctx, org, projectRow, dev, "TOKEN", { value: "old" }, actor);
    await beginRotation(ctx, org, projectRow, dev, "TOKEN", { value: "new", graceSeconds: 1 }, actor);
    // Force the deadline into the past.
    await ctx.db.query("UPDATE env_values SET rotation_deadline = now() - interval '1 second' WHERE item_name = 'TOKEN'");
    const resolved = await resolveItems(ctx, org, projectRow, dev);
    expect(resolved.find((i) => i.name === "TOKEN")!.retiringVersionId).toBeUndefined();
    const disc = await discloseSecrets(ctx, org, projectRow, dev, { items: ["TOKEN"] }, { actorIdentityId: actor });
    expect(disc.items[0]!.retiring).toBeUndefined();
  });

  it("a plain write during a rotation supersedes it", async () => {
    const { org, project, dev } = await setup();
    const projectRow = await getProject(ctx, org.id, project.id);
    await setValue(ctx, org, projectRow, dev, "TOKEN", { value: "old" }, actor);
    await beginRotation(ctx, org, projectRow, dev, "TOKEN", { value: "new" }, actor);
    await setValue(ctx, org, projectRow, dev, "TOKEN", { value: "final" }, actor);
    const resolved = await resolveItems(ctx, org, projectRow, dev);
    expect(resolved.find((i) => i.name === "TOKEN")!.retiringVersionId).toBeUndefined();
  });

  it("rejects a second rotation while one is in progress", async () => {
    const { org, project, dev } = await setup();
    const projectRow = await getProject(ctx, org.id, project.id);
    await setValue(ctx, org, projectRow, dev, "TOKEN", { value: "old" }, actor);
    await beginRotation(ctx, org, projectRow, dev, "TOKEN", { value: "new" }, actor);
    await expect(
      beginRotation(ctx, org, projectRow, dev, "TOKEN", { value: "newer" }, actor),
    ).rejects.toMatchObject({ code: "ROTATION_IN_PROGRESS" });
  });

  it("rotating an item with no current value is a not-found", async () => {
    const { org, project, dev } = await setup();
    const projectRow = await getProject(ctx, org.id, project.id);
    await expect(
      beginRotation(ctx, org, projectRow, dev, "TOKEN", { value: "new" }, actor),
    ).rejects.toMatchObject({ code: "RESOURCE_NOT_FOUND" });
  });
});

describe("contracts", () => {
  it("pushes with dedup, activates with semantic diff audit, validates environments", async () => {
    const { org, project, dev, prod } = await setup();
    const rev1 = await pushRevision(ctx, org.id, project.id, contract, { commitSha: "abc" }, actor);
    const dup = await pushRevision(ctx, org.id, project.id, contract, undefined, actor);
    expect(dup.id).toBe(rev1.id);

    let projectRow = await getProject(ctx, org.id, project.id);
    await activateRevision(ctx, org.id, projectRow, rev1.id, actor);
    projectRow = await getProject(ctx, org.id, project.id);

    // dev: DATABASE_URL missing (required always); PORT has default; STRIPE only for production.
    let report = await validateEnvironment(ctx, org, projectRow, dev, fullValidation);
    expect(report.valid).toBe(false);
    expect(report.missing).toEqual(["DATABASE_URL"]);

    await setValue(ctx, org, projectRow, dev, "DATABASE_URL", { value: "not a url" }, actor);
    report = await validateEnvironment(ctx, org, projectRow, dev, fullValidation);
    expect(report.missing).toEqual([]);
    expect(report.invalid).toEqual([{ name: "DATABASE_URL", reason: "must be a valid URL" }]);

    await setValue(ctx, org, projectRow, dev, "DATABASE_URL", { value: "postgres://ok" }, actor);
    report = await validateEnvironment(ctx, org, projectRow, dev, fullValidation);
    expect(report.valid).toBe(true);

    // production additionally requires STRIPE_SECRET_KEY.
    report = await validateEnvironment(ctx, org, projectRow, prod, fullValidation);
    expect(report.missing.sort()).toEqual(["DATABASE_URL", "STRIPE_SECRET_KEY"]);

    // Activating a security-relevant change records the diff.
    const flipped = {
      ...contract,
      items: contract.items.map((i) => (i.name === "PORT" ? { ...i, sensitive: true } : i)),
    };
    const rev2 = await pushRevision(ctx, org.id, project.id, flipped, undefined, actor);
    await activateRevision(ctx, org.id, projectRow, rev2.id, actor);
    const audit = await ctx.db.query(
      "SELECT metadata FROM audit_events WHERE event_type = 'contract.activated' ORDER BY occurred_at DESC",
    );
    const meta = (audit.rows[0] as { metadata: string | Record<string, unknown> }).metadata;
    const parsed = typeof meta === "string" ? JSON.parse(meta) : meta;
    expect(parsed.securityRelevant).toBe(true);
    expect(parsed.sensitivityChanged).toBe("PORT");
  });

  it("rejects invalid contracts with CONTRACT_INVALID", async () => {
    const { org, project } = await setup();
    await expect(
      pushRevision(ctx, org.id, project.id, { schemaVersion: 1, items: [{ name: "bad" }] }, undefined, actor),
    ).rejects.toMatchObject({ code: "CONTRACT_INVALID" });
  });
});

describe("unknown items default to sensitive", () => {
  it("treats uncontracted items as Secrets", async () => {
    const { org, project, dev } = await setup();
    const projectRow = await getProject(ctx, org.id, project.id);
    await setValue(ctx, org, projectRow, dev, "MYSTERY", { value: "x" }, actor);
    const items = await effectiveConfiguration(ctx, org, projectRow, dev, {
      includeValues: false,
      mayReadValue: () => false,
      actorIdentityId: actor,
    });
    expect(items[0]).toMatchObject({ name: "MYSTERY", sensitive: true });
  });
});

describe("error mapping", () => {
  it("DomainError carries protocol codes", () => {
    const err = new DomainError("RESOURCE_NOT_FOUND", "x");
    expect(err.code).toBe("RESOURCE_NOT_FOUND");
  });

  it("environment lookup by name works alongside id", async () => {
    const { project, dev } = await setup();
    expect((await getEnvironment(ctx, project.id, "development")).id).toBe(dev.id);
  });
});
