// SPDX-License-Identifier: AGPL-3.0-or-later
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { expect } from "vitest";
import { issueCredential } from "../../src/auth/credentials.js";
import { ensureSigningKey } from "../../src/auth/jwt.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../../src/domain/bootstrap.js";
import type { AppCtx } from "../../src/domain/ctx.js";
import { rewrapForDrain } from "../../src/domain/auditexport.js";
import { buildApp } from "../../src/http/app.js";
import { OutboundPolicy } from "../../src/net/outbound.js";
import { PUBLIC_URL, RP } from "./device-sign-in.js";
import { fakeGitHubApps } from "./fake-github-app.js";
import { registerSoftPasskey } from "./soft-authenticator.js";

/**
 * A source installation for the migration's export tests (go-step7 slice
 * 7.2b), built through its own /v1 API as the fixture kit builds its
 * databases, from the admin-step-up catalogue's world: two Organizations,
 * Projects, Environments of three tiers, a Contract, Secret values with
 * several versions, machine identities (one retired), an OIDC binding,
 * people invited (with passkeys, browser sessions and credentials), Roles,
 * Groups, Teams, Grants, a webhook, a Platform Connection, a GitHub App
 * (attached, and one pending conversion), a tailnet Requirement and
 * Security Controls. Every secret value it makes (plaintexts, tokens,
 * session tokens, keys) is built here at random and returned, so a test can
 * scan an export for each.
 */

/** An S3 stand-in that takes each object once and refuses reads (audit-export-api.test.ts's). */
async function fakeStore(): Promise<{ url: string; close: () => Promise<void> }> {
  const seen = new Set<string>();
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      const key = (req.url ?? "").split("?")[0]!;
      if (req.method === "PUT" && !seen.has(key)) {
        seen.add(key);
        res.writeHead(200, { ETag: '"0"' });
        res.end();
        return;
      }
      res.writeHead(req.method === "PUT" ? 412 : 403, { "content-type": "application/xml" });
      res.end(req.method === "HEAD" ? undefined : '<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>');
    });
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", () => done()));
  return {
    url: `http://127.0.0.1:${(server.address() as { port: number }).port}`,
    close: () => new Promise<void>((done) => { server.closeAllConnections(); server.close(() => done()); }),
  };
}

export interface Seeded {
  /** Every secret value the installation holds in some form. */
  secrets: string[];
  acme: string;
  beta: string;
  admin: string;
  member: string;
  service: string;
  /** A Secret's current plaintext, its value row and version. */
  value: { plaintext: string; valueId: string; versionId: string; organizationId: string };
}

const rnd = (n = 12) => randomBytes(n).toString("hex");

export async function seedInstallation(ctx: AppCtx): Promise<Seeded> {
  const secrets: string[] = [];
  const keep = <T extends string>(s: T) => (secrets.push(s), s);
  await ensureInstallation(ctx);
  // The audit exports' destination is a local stand-in, allowed by the outbound policy.
  ctx.outbound = new OutboundPolicy("127.0.0.1/32:*");
  const store = await fakeStore();
  const OWNER = { login: `acme-gh-${rnd(3)}`, id: 1009, type: "Organization" as const };
  const PERMISSIONS = { secrets: "write", environments: "write", metadata: "read" };
  const github = fakeGitHubApps();
  let nextAppId = 5_254_113;
  const syncFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    if (/^\/app-manifests\/([^/]+)\/conversions$/.test(url.pathname) && init?.method === "POST") {
      const id = nextAppId++;
      const pem = github.addApp({ id, slug: `varlatch-${id}`, clientId: `Iv23li${id}`, owner: OWNER, permissions: PERMISSIONS });
      keep(pem.split("\n").filter((l) => l && !l.startsWith("-----")).join("").slice(0, 64));
      return Response.json({ id, slug: `varlatch-${id}`, client_id: `Iv23li${id}`, client_secret: "not-kept", pem, owner: OWNER, permissions: PERMISSIONS }, { status: 201 });
    }
    return github.fetchImpl(input, init);
  }) as typeof fetch;
  const app = buildApp(ctx, { publicUrl: PUBLIC_URL, clientAddress: () => "203.0.113.7", syncFetch });

  /** A person with a passkey, a browser session (its token kept as a secret) and a browser credential. */
  const person = async (identityId: string) => {
    const key = await registerSoftPasskey(ctx.db, identityId, { ...RP, trust: "trusted" });
    const sessionToken = keep(`session-token-${rnd()}`);
    await ctx.db.query(
      `INSERT INTO "session" (id, "expiresAt", token, "userId")
       SELECT $1, now() + interval '1 day', $2, better_auth_user_id FROM auth_user_links WHERE identity_id = $3`,
      [`session-${identityId}`, sessionToken, identityId],
    );
    await ctx.db.query(
      "INSERT INTO auth_session_evidence (session_id, ceremony, user_verified, passkey_id) VALUES ($1, 'sign-in', true, $2)",
      [`session-${identityId}`, key.passkeyId],
    );
    const web = await issueCredential(ctx.db, { identityId, kind: "browser", expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(), authSessionId: `session-${identityId}` });
    keep(web.token);
    return web.token;
  };
  const bootstrap = await issueBootstrapGrant(ctx);
  keep(bootstrap.token);
  const { identityId: admin } = await consumeSetupGrant(ctx, bootstrap.token, { adminName: "Admin" });
  const token = await person(admin);
  keep((await issueCredential(ctx.db, { identityId: admin, kind: "cli", name: "admin cli" })).token);

  const ok = async (method: string, path: string, body?: unknown): Promise<any> => {
    const res = await app.request(path, {
      method,
      headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await res.text();
    expect(res.status, `${method} ${path}: ${text}`).toBeLessThan(300);
    return text ? JSON.parse(text) : null;
  };
  const ACME = "/v1/organizations/acme";
  const BETA = "/v1/organizations/beta";

  const acme = (await ok("POST", "/v1/organizations", { name: "Acme", slug: "acme" })).id as string;
  const beta = (await ok("POST", "/v1/organizations", { name: "Beta", slug: "beta" })).id as string;
  const project = (await ok("POST", `${ACME}/projects`, { name: "API", slug: "api", contractAuthority: "managed" })).id as string;
  await ok("POST", `${ACME}/projects`, { name: "Web", slug: "web", contractAuthority: "managed" });
  for (const [name, tier] of [["production", "production"], ["staging", "staging"], ["development", "development"]]) {
    await ok("POST", `${ACME}/projects/api/environments`, { name, tier });
  }
  const revision = await ok("POST", `${ACME}/projects/api/contract/revisions`, {
    contract: { schemaVersion: 1, items: [{ name: "DB_PASS", required: { kind: "never" }, sensitive: true, type: "string" }, { name: "API_KEY", required: { kind: "never" }, sensitive: true, type: "string" }] },
  });
  await ok("POST", `${ACME}/projects/api/contract/revisions/${revision.id}/activate`, {});
  for (const env of ["production", "staging", "development"]) {
    await ok("PUT", `${ACME}/projects/api/environments/${env}/values/DB_PASS`, { value: keep(`db-pass-${env}-${rnd()}`) });
  }
  // A second version of one value: the first stays as an older version.
  const current = keep(`db-pass-production-next-${rnd()}`);
  await ok("PUT", `${ACME}/projects/api/environments/production/values/DB_PASS`, { value: current });
  await ok("PUT", `${ACME}/projects/api/environments/staging/values/API_KEY`, { value: keep(`api-key-${rnd()}`) });

  const service = (await ok("POST", `${ACME}/identities`, { name: "api-svc", kind: "service" })).id as string;
  keep((await issueCredential(ctx.db, { identityId: service, kind: "service", name: "svc" })).token);
  const ci = (await ok("POST", `${ACME}/identities`, { name: "deploy", kind: "ci" })).id as string;
  await ok("POST", `${ACME}/identities/${ci}/oidc-bindings`, { issuer: "https://ci.example", audience: "varlatch", subject: "repo:acme/api:ref:refs/heads/main" });
  const old = (await ok("POST", `${ACME}/identities`, { name: "old-worker", kind: "workload" })).id as string;
  await ok("POST", `${ACME}/identities/${old}/retire`);

  const invite = await issueInviteGrant(ctx, { organizationId: acme, role: "member", name: "Bob" }, admin);
  keep(invite.token);
  const { identityId: member } = await consumeSetupGrant(ctx, invite.token, {});
  await person(member);
  keep((await issueInviteGrant(ctx, { organizationId: acme, role: "member", name: "Pending" }, admin)).token);

  await ok("POST", `${ACME}/roles`, { name: "reader", actions: ["config.value.read", "project.read"] });
  const group = (await ok("POST", `${ACME}/groups`, { name: "oncall" })).id as string;
  await ok("POST", `${ACME}/groups/${group}/members`, { identityId: service });
  const team = (await ok("POST", `${ACME}/teams`, { name: "platform" })).id as string;
  await ok("POST", `${ACME}/teams/${team}/members`, { identityId: member });
  await ok("POST", `${ACME}/teams/${team}/projects`, { projectId: project });
  await ok("POST", `${ACME}/grants`, { subjectIdentityId: service, scope: { kind: "project", projectId: project }, actions: ["project.read"] });
  // A replacement under an Idempotency-Key (its record is kept).
  const replaced = await ok("POST", `${ACME}/grants`, { subjectIdentityId: service, scope: { kind: "organization" }, actions: ["project.read"] });
  const replace = await app.request(`${ACME}/grants/${replaced.id}/replace`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", "Idempotency-Key": `replace-${rnd(4)}` },
    body: JSON.stringify({ subjectIdentityId: service, scope: { kind: "organization" }, actions: ["organization.read"] }),
  });
  expect(replace.status, await replace.clone().text()).toBeLessThan(300);

  const hook = await ok("POST", `${ACME}/webhooks`, { url: `https://sink.example/hook/${rnd()}` });
  keep(hook.secret);
  const credential = keep(["ghp", "migration", rnd(16)].join("_"));
  await ok("POST", `${ACME}/platform-connections`, { platform: "github-actions", baseIdentity: "Acme", name: "GitHub", credential });
  const started = await ok("POST", `${ACME}/github-app/registrations`, { account: { login: OWNER.login, type: "organization" } });
  await ok("POST", `${ACME}/github-app/registrations/complete`, { state: started.state, code: `code-${started.id}` });
  await ok("POST", `${ACME}/requirements`, { kind: "tailnet", target: { kind: "tier", tier: "staging" }, selector: { tailnet: "example.ts.net", tags: ["tag:prod"] } });
  const tighten = async (org: string, mode: "report" | "enforce") => {
    const control = (await ok("GET", `${org}/security/controls`)).items.find((i: { control: string }) => i.control === "admin-step-up");
    await ok("PATCH", `${org}/security/controls/admin-step-up`, { mode, expectedVersion: control.version });
  };
  await tighten(ACME, "report");

  // beta: a converted registration whose attachment waits (its pending key).
  await tighten(BETA, "enforce");
  const pending = await ok("POST", `${BETA}/github-app/registrations`, { account: { login: OWNER.login, type: "organization" } });
  await app.request(`${BETA}/github-app/registrations/complete`, {
    method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ state: pending.state, code: `code-${pending.id}` }),
  });

  // The Convex token signer's key, and a device sign-in a person looked up.
  await ensureSigningKey(ctx);
  const device = await app.request("/v1/auth/device", {
    method: "POST", headers: { "Content-Type": "application/json", "User-Agent": "varlatch-cli/0.22.0 (linux; x64)" }, body: "{}",
  });
  expect(device.status).toBeLessThan(300);
  const { userCode } = (await device.json()) as { userCode: string };
  await app.request("/v1/auth/device/lookup", {
    method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify({ userCode }),
  });
  // An audit export in each Organization; beta's moves to its drain copy
  // under the Root KEK, as an Organization's deletion does.
  for (const [org, prefix] of [[ACME, "acme"], [BETA, "beta"]] as const) {
    await ok("POST", `${org}/audit-export`, {
      from: "now",
      destination: { endpoint: store.url, region: "us-east-1", bucket: "audit-bucket", prefix, pathStyle: true },
      credential: { accessKeyId: keep(["AKIA", rnd(8).toUpperCase()].join("")), secretAccessKey: keep(`audit-export-secret-${rnd()}`) },
    });
  }
  await rewrapForDrain(ctx, ctx.db, beta);
  await store.close();
  // An incident freeze, last: it stops beta's writes.
  await ok("POST", `${BETA}/incident-freeze`, { reason: "a drill" });

  const version = (await ctx.db.query(
    `SELECT ev.id AS value_id, ev.current_version_id FROM env_values ev JOIN environments e ON e.id = ev.environment_id
      WHERE e.name = 'production' AND ev.item_name = 'DB_PASS'`,
  )).rows[0] as { value_id: string; current_version_id: string };
  return {
    secrets, acme, beta, admin, member, service,
    value: { plaintext: current, valueId: version.value_id, versionId: version.current_version_id, organizationId: acme },
  };
}
