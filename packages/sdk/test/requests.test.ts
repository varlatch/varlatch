// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { VarlatchClient } from "../src/index.js";

/** The requests the SDK builds, checked against a recording fetch. */
function recorder(response: () => Response = () => new Response(JSON.stringify({ items: [], nextCursor: null }))) {
  const requests: { method: string; url: string; headers: Record<string, string>; body: unknown }[] = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    requests.push({
      method: init?.method ?? "GET",
      url: String(input),
      headers: { ...(init?.headers as Record<string, string> | undefined) },
      body: init?.body === undefined ? undefined : JSON.parse(String(init.body)),
    });
    return response();
  };
  return { requests, client: new VarlatchClient({ server: "https://v.example/", token: "vlt_cli_x", fetch: fetchImpl }) };
}

describe("invitations", () => {
  it("lists with status, limit, and cursor, and revokes by ID", async () => {
    const { requests, client } = recorder();
    await client.listInvitations("acme");
    await client.listInvitations("acme", { status: "all", limit: 20, cursor: "abc" });
    const revoking = recorder(() => new Response(null, { status: 204 }));
    await expect(revoking.client.revokeInvitation("acme", "sgr_1")).resolves.toBeUndefined();
    expect(requests.map((r) => [r.method, r.url])).toEqual([
      ["GET", "https://v.example/v1/organizations/acme/invitations"],
      ["GET", "https://v.example/v1/organizations/acme/invitations?status=all&limit=20&cursor=abc"],
    ]);
    expect(revoking.requests.map((r) => [r.method, r.url])).toEqual([
      ["DELETE", "https://v.example/v1/organizations/acme/invitations/sgr_1"],
    ]);
  });
});

describe("organization rename", () => {
  it("patches the organization with its new name", async () => {
    const { requests, client } = recorder(() => new Response(JSON.stringify({ id: "org_1", slug: "acme", name: "Acme" })));
    await expect(client.renameOrganization("acme", "Acme")).resolves.toMatchObject({ slug: "acme", name: "Acme" });
    expect(requests).toMatchObject([
      { method: "PATCH", url: "https://v.example/v1/organizations/acme", body: { name: "Acme" } },
    ]);
  });
});

describe("whoami", () => {
  it("gets /v1/me with the client's credential and returns the caller", async () => {
    const caller = {
      identity: { id: "idn_1", name: "runner-macmini", kind: "service", email: null },
      organization: { id: "org_1", slug: "acme", name: "Acme", createdAt: "2026-10-01T00:00:00.000Z" },
      credential: { id: "crd_1", name: "desktop-runner", kind: "service", expiresAt: null },
      listener: "ordinary",
    };
    const { requests, client } = recorder(() => new Response(JSON.stringify(caller)));
    await expect(client.whoami()).resolves.toEqual(caller);
    expect(requests).toMatchObject([
      { method: "GET", url: "https://v.example/v1/me", headers: { Authorization: "Bearer vlt_cli_x" }, body: undefined },
    ]);
  });
});

describe("machine credential issuance", () => {
  it("posts the name and the optional limits to the identity's credentials", async () => {
    const issued = { id: "crd_1", kind: "service", name: "backup job", token: "vlt_svc_x", expiresAt: null, maxUses: null };
    const { requests, client } = recorder(() => new Response(JSON.stringify(issued), { status: 201 }));
    await expect(client.issueMachineCredential("acme", "idn_1", { name: "backup job" })).resolves.toEqual(issued);
    await client.issueMachineCredential("acme", "idn 2", { name: "metrics", ttlSeconds: 600, maxUses: 5 });
    expect(requests).toMatchObject([
      { method: "POST", url: "https://v.example/v1/organizations/acme/identities/idn_1/credentials", body: { name: "backup job" } },
      { method: "POST", url: "https://v.example/v1/organizations/acme/identities/idn%202/credentials", body: { name: "metrics", ttlSeconds: 600, maxUses: 5 } },
    ]);
  });
});

describe("audit filters", () => {
  const filters = {
    decision: "deny",
    eventType: "value.*",
    actorIdentityId: "idn_1",
    projectId: "prj_1",
    environmentId: "env_1",
    item: "DB_URL",
    since: "2026-10-01T00:00:00+02:00",
    until: "2026-10-02T00:00:00Z",
  } as const;
  const query =
    "decision=deny&eventType=value.*&actorIdentityId=idn_1&projectId=prj_1&environmentId=env_1&item=DB_URL" +
    "&since=2026-10-01T00%3A00%3A00%2B02%3A00&until=2026-10-02T00%3A00%3A00Z";

  it("sends the filters with the listing, after limit and cursor, and stays compatible without them", async () => {
    const { requests, client } = recorder();
    await client.listAuditEvents("acme");
    await client.listAuditEvents("acme", { limit: 10, cursor: "c1" });
    await client.listAuditEvents("acme", { limit: 10, cursor: "c1", ...filters });
    expect(requests.map((r) => r.url)).toEqual([
      "https://v.example/v1/organizations/acme/audit-events",
      "https://v.example/v1/organizations/acme/audit-events?limit=10&cursor=c1",
      `https://v.example/v1/organizations/acme/audit-events?limit=10&cursor=c1&${query}`,
    ]);
  });

  it("sends the filters with the export", async () => {
    const { requests, client } = recorder(() => new Response('{"eventId":"evt_1"}\n'));
    await client.exportAuditEventsNdjson("acme");
    await client.exportAuditEventsNdjson("acme", filters);
    expect(requests.map((r) => r.url)).toEqual([
      "https://v.example/v1/organizations/acme/audit-events/export",
      `https://v.example/v1/organizations/acme/audit-events/export?${query}`,
    ]);
  });
});

describe("userAgent", () => {
  it("sends the User-Agent on every request when given, and none otherwise", async () => {
    const seen: (string | undefined)[] = [];
    const fetchImpl: typeof fetch = async (_input, init) => {
      seen.push((init?.headers as Record<string, string>)["User-Agent"]);
      return new Response("{}");
    };
    const ua = "varlatch-cli/0.14.0 (linux; x64)";
    const client = new VarlatchClient({ server: "https://v.example", token: "t", fetch: fetchImpl, userAgent: ua });
    await client.exchangeCliCredential();
    await client.meta();
    await client.exportAuditEventsNdjson("acme");
    await new VarlatchClient({ server: "https://v.example", fetch: fetchImpl }).meta();
    expect(seen).toEqual([ua, ua, ua, undefined]);
  });
});
