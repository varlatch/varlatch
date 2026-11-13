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
      listener: "tailnet",
      tailnet: { recognized: true, tailnet: "example.ts.net", nodeId: "nRunner", nodeName: "macmini", tags: ["tag:desktop-runner"] },
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

describe("GitHub App", () => {
  it("builds each request on the Organization's github-app routes, and creates an App Connection by installation", async () => {
    const { requests, client } = recorder(() => new Response(JSON.stringify({})));
    await client.getGitHubApp("acme");
    await client.startGitHubAppRegistration("acme", { login: "acme-gh", type: "organization" });
    await client.completeGitHubAppRegistration("acme", { state: "s", code: "c" });
    await client.importGitHubApp("acme", { appId: 5254113, privateKey: "KEY" });
    await client.listGitHubAppInstallations("acme");
    await client.rotateGitHubAppKey("acme", { privateKey: "NEW", expectedVersion: 2 });
    await client.createAppConnection("acme", { installationId: 169698431, name: "GitHub (acme-gh)" });
    const removing = recorder(() => new Response(null, { status: 204 }));
    await expect(removing.client.removeGitHubApp("acme", "gha_1")).resolves.toBeUndefined();
    expect(requests.map((r) => [r.method, r.url, r.body])).toEqual([
      ["GET", "https://v.example/v1/organizations/acme/github-app", undefined],
      ["POST", "https://v.example/v1/organizations/acme/github-app/registrations", { account: { login: "acme-gh", type: "organization" } }],
      ["POST", "https://v.example/v1/organizations/acme/github-app/registrations/complete", { state: "s", code: "c" }],
      ["POST", "https://v.example/v1/organizations/acme/github-app/import", { appId: 5254113, privateKey: "KEY" }],
      ["GET", "https://v.example/v1/organizations/acme/github-app/installations", undefined],
      ["POST", "https://v.example/v1/organizations/acme/github-app/key", { privateKey: "NEW", expectedVersion: 2 }],
      [
        "POST",
        "https://v.example/v1/organizations/acme/platform-connections",
        { credentialKind: "github-app", installationId: 169698431, name: "GitHub (acme-gh)" },
      ],
    ]);
    expect(removing.requests.map((r) => [r.method, r.url])).toEqual([["DELETE", "https://v.example/v1/organizations/acme/github-app?appId=gha_1"]]);
  });
});

describe("credential expiry notice", () => {
  const header = { "Varlatch-Credential-Expires": "2026-11-12T08:00:00.000Z" };

  it("hands the header's value to onCredentialExpires, on success and on error responses", async () => {
    const seen: string[] = [];
    const responses = [
      new Response(JSON.stringify({ items: [], nextCursor: null }), { headers: header }),
      new Response(JSON.stringify({ error: { code: "PERMISSION_DENIED", message: "no", requestId: "r" } }), { status: 403, headers: header }),
      new Response(JSON.stringify({ items: [], nextCursor: null })),
    ];
    const client = new VarlatchClient({
      server: "https://v.example",
      token: "vlt_svc_x",
      fetch: async () => responses.shift()!,
      onCredentialExpires: (at) => seen.push(at),
    });
    await client.listOrganizations();
    await expect(client.listOrganizations()).rejects.toMatchObject({ status: 403 });
    await client.listOrganizations();
    expect(seen).toEqual(["2026-11-12T08:00:00.000Z", "2026-11-12T08:00:00.000Z"]);
  });
});

describe("GitHub App registration under a step-up (ADR-0054 amendment D)", () => {
  const approval = { id: "apr_aaaaaaaaaaaaaaaaaaaaaaaaaa", operation: "github_app.register" };
  const stepUp = () =>
    new Response(
      JSON.stringify({ error: { code: "STEP_UP_REQUIRED", message: "approve", requestId: "r", details: { approval, registrationId: "ghr_1" } } }),
      { status: 403 },
    );

  function client(onStepUp?: () => Promise<boolean>) {
    const requests: { method: string; url: string; headers: Record<string, string> }[] = [];
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = String(input);
      requests.push({ method: init?.method ?? "GET", url, headers: { ...(init?.headers as Record<string, string> | undefined) } });
      if (url.endsWith("/registrations/complete")) return stepUp();
      return new Response(JSON.stringify({ outcome: "registered", app: { id: "gha_1" } }), { status: 201 });
    };
    return { requests, client: new VarlatchClient({ server: "https://v.example", token: "t", fetch: fetchImpl, ...(onStepUp ? { onStepUp } : {}) }) };
  }

  it("never repeats the callback: once approved, it attaches the registration with the approval", async () => {
    const { requests, client: c } = client(async () => true);
    await expect(c.completeGitHubAppRegistration("acme", { state: "s", code: "c" })).resolves.toMatchObject({ outcome: "registered" });
    expect(requests.map((r) => [r.method, r.url, r.headers["Varlatch-Approval"] ?? null])).toEqual([
      ["POST", "https://v.example/v1/organizations/acme/github-app/registrations/complete", null],
      ["POST", "https://v.example/v1/organizations/acme/github-app/registrations/ghr_1/attach", approval.id],
    ]);
  });

  it("surfaces STEP_UP_REQUIRED, naming the registration, when the approval is not given", async () => {
    const { requests, client: c } = client(async () => false);
    await expect(c.completeGitHubAppRegistration("acme", { state: "s", code: "c" })).rejects.toMatchObject({
      code: "STEP_UP_REQUIRED",
      details: { registrationId: "ghr_1" },
    });
    expect(requests).toHaveLength(1);
  });

  it("attaches and discards on the registration's routes", async () => {
    const { requests, client: c } = client();
    await c.attachGitHubAppRegistration("acme", "ghr_1");
    await c.discardGitHubAppRegistration("acme", "ghr_1");
    expect(requests.map((r) => [r.method, r.url])).toEqual([
      ["POST", "https://v.example/v1/organizations/acme/github-app/registrations/ghr_1/attach"],
      ["DELETE", "https://v.example/v1/organizations/acme/github-app/registrations/ghr_1"],
    ]);
  });
});

describe("an export whose read went stale under its approval (ADR-0054 amendment C)", () => {
  const error = (status: number, code: string, details: Record<string, unknown>) =>
    new Response(JSON.stringify({ error: { code, message: code, requestId: "req_1", details } }), { status });
  const approval = { id: "apr_aaaaaaaaaaaaaaaaaaaaaaaaaa", operation: "secret.export" };
  const disclosed = () => new Response(JSON.stringify({ items: [{ name: "API_KEY", versionId: "ver_2", value: "v" }], withheld: [] }));
  const scripted = (answers: (() => Response)[]) => {
    const requests: Record<string, string>[] = [];
    const fetchImpl: typeof fetch = async (_input, init) => {
      requests.push({ ...(init?.headers as Record<string, string> | undefined) });
      return answers.shift()!();
    };
    const client = new VarlatchClient({ server: "https://v.example", token: "vlt_x", fetch: fetchImpl, onStepUp: async () => true });
    return { requests, client };
  };
  const stale = () => error(409, "STATE_CHANGED", { reason: "stale-capture", approvalId: approval.id });

  it("repeats the request with the same approval, which reads afresh", async () => {
    const { requests, client } = scripted([() => error(403, "STEP_UP_REQUIRED", { approval }), stale, disclosed]);
    await expect(client.discloseSecrets("acme", "api", "dev", { items: ["API_KEY"], purpose: "export" })).resolves.toMatchObject({ items: [{ name: "API_KEY" }] });
    expect(requests.map((h) => h["Varlatch-Approval"] ?? null)).toEqual([null, approval.id, approval.id]);
  });

  it("gives up after two repeats, and never repeats another STATE_CHANGED or a request without an approval", async () => {
    const twice = scripted([() => error(403, "STEP_UP_REQUIRED", { approval }), stale, stale, stale]);
    await expect(twice.client.discloseSecrets("acme", "api", "dev", { items: ["API_KEY"], purpose: "export" })).rejects.toMatchObject({ code: "STATE_CHANGED" });
    expect(twice.requests).toHaveLength(4);
    const other = scripted([() => error(403, "STEP_UP_REQUIRED", { approval }), () => error(409, "STATE_CHANGED", {})]);
    await expect(other.client.discloseSecrets("acme", "api", "dev", { items: ["API_KEY"], purpose: "export" })).rejects.toMatchObject({ code: "STATE_CHANGED" });
    expect(other.requests).toHaveLength(2);
    const plain = scripted([stale]);
    await expect(plain.client.discloseSecrets("acme", "api", "dev", { items: ["API_KEY"] })).rejects.toMatchObject({ code: "STATE_CHANGED" });
    expect(plain.requests).toHaveLength(1);
  });
});
