// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import nacl from "tweetnacl";
import { convexAdapter } from "../src/convex.js";
import { coolifyAdapter } from "../src/coolify.js";
import { githubActionsAdapter } from "../src/github.js";
import { getAdapter, canonicalDestinationIdentity } from "../src/index.js";
import { sealedBox, sealedBoxOpen } from "../src/sealedbox.js";
import { AdapterError, type AdapterRequest } from "../src/types.js";

function fakeFetch(
  handler: (url: string, init: RequestInit) => { status: number; body?: unknown; headers?: Record<string, string> },
  calls: { url: string; init: RequestInit }[] = [],
): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init: init ?? {} });
    const res = handler(url, init ?? {});
    return new Response(res.body !== undefined ? JSON.stringify(res.body) : null, {
      status: res.status,
      headers: { "Content-Type": "application/json", ...res.headers },
    });
  }) as typeof fetch;
}

describe("sealed box", () => {
  it("round-trips against a known recipient keypair (libsodium crypto_box_seal shape)", () => {
    const recipient = nacl.box.keyPair();
    const message = new TextEncoder().encode("postgres://user:pw@host/db");
    const sealed = sealedBox(message, recipient.publicKey);
    // epk (32) || ciphertext (msg + 16 MAC)
    expect(sealed.length).toBe(32 + message.length + 16);
    const opened = sealedBoxOpen(sealed, recipient.publicKey, recipient.secretKey);
    expect(opened).not.toBeNull();
    expect(new TextDecoder().decode(opened as Uint8Array)).toBe("postgres://user:pw@host/db");
  });

  it("uses a fresh ephemeral key per seal", () => {
    const recipient = nacl.box.keyPair();
    const a = sealedBox(new Uint8Array([1]), recipient.publicKey);
    const b = sealedBox(new Uint8Array([1]), recipient.publicKey);
    expect(Buffer.from(a).toString("hex")).not.toBe(Buffer.from(b).toString("hex"));
  });
});

describe("allowlist", () => {
  it("resolves only the closed set", () => {
    expect(getAdapter("github-actions").platform).toBe("github-actions");
    expect(getAdapter("coolify").platform).toBe("coolify");
    expect(getAdapter("convex").platform).toBe("convex");
    expect(() => getAdapter("generic-url")).toThrow(AdapterError);
  });

  it("canonical destination identity is platform + base + destination, never a connection", () => {
    const a = canonicalDestinationIdentity("coolify", "https://a.example", "app1");
    const b = canonicalDestinationIdentity("coolify", "https://b.example", "app1");
    expect(a).not.toBe(b);
    expect(a).toBe(canonicalDestinationIdentity("coolify", "https://a.example", "app1"));
  });
});

describe("github-actions adapter", () => {
  it("canonicalizes owner and repo, rejects junk", () => {
    expect(githubActionsAdapter.canonicalizeBaseIdentity(" @Acme-Org ")).toBe("acme-org");
    expect(() => githubActionsAdapter.canonicalizeBaseIdentity("not a login!")).toThrow(AdapterError);
    const { destination, key } = githubActionsAdapter.canonicalizeDestination({ repo: "API" });
    expect(destination.repo).toBe("api");
    expect(key).toBe("api");
    expect(
      githubActionsAdapter.canonicalizeDestination({ repo: "api", environment: "production" }).key,
    ).toBe("api#production");
    expect(() => githubActionsAdapter.canonicalizeDestination({ repo: "" })).toThrow(AdapterError);
  });

  it("rejects reserved and unstorable names, uppercases canonical names", () => {
    expect(githubActionsAdapter.validateName("DATABASE_URL")).toBeNull();
    expect(githubActionsAdapter.validateName("github_token")).toMatch(/reserved/);
    expect(githubActionsAdapter.validateName("1BAD")).toMatch(/digit/);
    expect(githubActionsAdapter.canonicalizeName("database_url")).toBe("DATABASE_URL");
  });

  it("encrypts values with the destination public key and PUTs per name", async () => {
    const recipient = nacl.box.keyPair();
    const calls: { url: string; init: RequestInit }[] = [];
    const fetchImpl = fakeFetch((url) => {
      if (url.endsWith("/public-key")) {
        return {
          status: 200,
          body: { key_id: "k1", key: Buffer.from(recipient.publicKey).toString("base64") },
        };
      }
      return { status: 204 };
    }, calls);
    const req: AdapterRequest = {
      baseIdentity: "acme",
      destination: { repo: "api" },
      credential: "ghp_test",
      fetchImpl,
    };
    const outcomes = await githubActionsAdapter.writeValues(req, [
      { name: "DATABASE_URL", value: "postgres://x" },
    ]);
    expect(outcomes).toEqual([{ name: "DATABASE_URL", ok: true }]);
    const put = calls.find((c) => c.init.method === "PUT");
    expect(put?.url).toBe("https://api.github.com/repos/acme/api/actions/secrets/DATABASE_URL");
    const body = JSON.parse(put?.init.body as string) as { encrypted_value: string; key_id: string };
    expect(body.key_id).toBe("k1");
    // The wire body must be ciphertext the recipient key can open — never plaintext.
    expect(body.encrypted_value).not.toContain("postgres");
    const opened = sealedBoxOpen(
      new Uint8Array(Buffer.from(body.encrypted_value, "base64")),
      recipient.publicKey,
      recipient.secretKey,
    );
    expect(new TextDecoder().decode(opened as Uint8Array)).toBe("postgres://x");
  });

  it("scopes to a repository environment when configured", async () => {
    const recipient = nacl.box.keyPair();
    const calls: { url: string; init: RequestInit }[] = [];
    const fetchImpl = fakeFetch((url) => {
      if (url.endsWith("/public-key")) {
        return { status: 200, body: { key_id: "k1", key: Buffer.from(recipient.publicKey).toString("base64") } };
      }
      return { status: 201 };
    }, calls);
    await githubActionsAdapter.writeValues(
      { baseIdentity: "acme", destination: { repo: "api", environment: "production" }, credential: "t", fetchImpl },
      [{ name: "PORT", value: "8080" }],
    );
    expect(calls[0]?.url).toBe(
      "https://api.github.com/repos/acme/api/environments/production/secrets/public-key",
    );
  });

  it("treats delete-of-absent as converged and reports per-name failures", async () => {
    const fetchImpl = fakeFetch((url) =>
      url.endsWith("/GONE") ? { status: 404 } : { status: 500 },
    );
    const req: AdapterRequest = { baseIdentity: "acme", destination: { repo: "api" }, credential: "t", fetchImpl };
    const outcomes = await githubActionsAdapter.deleteNames(req, ["GONE", "STUCK"]);
    expect(outcomes).toEqual([
      { name: "GONE", ok: true },
      { name: "STUCK", ok: false, error: "HTTP 500" },
    ]);
  });

  it("fails the whole write when the public key is unavailable", async () => {
    const fetchImpl = fakeFetch(() => ({ status: 401 }));
    await expect(
      githubActionsAdapter.writeValues(
        { baseIdentity: "acme", destination: { repo: "api" }, credential: "bad", fetchImpl },
        [{ name: "A", value: "1" }],
      ),
    ).rejects.toThrow(AdapterError);
  });
});

describe("coolify adapter", () => {
  const baseReq = (
    fetchImpl: typeof fetch,
    destination: Record<string, string> = { applicationUuid: "app123" },
  ): AdapterRequest => ({
    baseIdentity: "https://coolify.example.com",
    destination,
    credential: "tok",
    fetchImpl,
  });
  const bodyOf = (c: { init: RequestInit }) => JSON.parse(String(c.init.body)) as Record<string, unknown>;

  it("canonicalizes the instance origin and requires https, no userinfo, no path", () => {
    expect(coolifyAdapter.canonicalizeBaseIdentity("https://Coolify.Example.com/")).toBe(
      "https://coolify.example.com",
    );
    expect(() => coolifyAdapter.canonicalizeBaseIdentity("http://coolify.example.com")).toThrow(/https/);
    expect(() => coolifyAdapter.canonicalizeBaseIdentity("https://u:p@host")).toThrow(/userinfo/);
    expect(() => coolifyAdapter.canonicalizeBaseIdentity("https://host/api")).toThrow(/origin/);
  });

  it("canonicalizes per-target options without letting them into the identity", () => {
    const plain = coolifyAdapter.canonicalizeDestination({ applicationUuid: " app123 " });
    expect(plain).toEqual({ destination: { applicationUuid: "app123" }, key: "app123" });
    const withOptions = coolifyAdapter.canonicalizeDestination({
      applicationUuid: "app123",
      buildTime: true,
      deployAction: "restart",
    });
    expect(withOptions).toEqual({
      destination: { applicationUuid: "app123", buildTime: "true", deployAction: "restart" },
      key: "app123",
    });
    expect(
      coolifyAdapter.canonicalizeDestination({ applicationUuid: "app123", buildTime: "false", deployAction: "" })
        .destination,
    ).toEqual({ applicationUuid: "app123", buildTime: "false" });
    expect(() =>
      coolifyAdapter.canonicalizeDestination({ applicationUuid: "app123", buildTime: "yes" }),
    ).toThrow(/buildTime/);
    expect(() =>
      coolifyAdapter.canonicalizeDestination({ applicationUuid: "app123", deployAction: "stop" }),
    ).toThrow(/deployAction/);
  });

  it("creates missing keys, patches existing ones, deletes by env uuid", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const fetchImpl = fakeFetch((url, init) => {
      if (url.endsWith("/envs") && (init.method ?? "GET") === "GET") {
        return { status: 200, body: [{ uuid: "e1", key: "EXISTING", value: "old" }] };
      }
      return { status: 201 };
    }, calls);
    const req = baseReq(fetchImpl);
    const outcomes = await coolifyAdapter.writeValues(req, [
      { name: "EXISTING", value: "new" },
      { name: "FRESH", value: "v" },
    ]);
    expect(outcomes.every((o) => o.ok)).toBe(true);
    expect(calls.map((c) => `${c.init.method ?? "GET"} ${c.url}`)).toEqual([
      "GET https://coolify.example.com/api/v1/applications/app123/envs",
      "PATCH https://coolify.example.com/api/v1/applications/app123/envs",
      "POST https://coolify.example.com/api/v1/applications/app123/envs",
    ]);
    // No build-time option and no flag vocabulary on the rows: production
    // scope only, nothing else sent — Coolify's own defaults apply.
    expect(bodyOf(calls[1]!)).toEqual({ key: "EXISTING", value: "new", is_preview: false });
    expect(bodyOf(calls[2]!)).toEqual({ key: "FRESH", value: "v", is_preview: false });

    const del = await coolifyAdapter.deleteNames(req, ["EXISTING", "ABSENT"]);
    expect(del).toEqual([
      { name: "EXISTING", ok: true },
      { name: "ABSENT", ok: true },
    ]);
    expect(calls.some((c) => c.url.endsWith("/envs/e1") && c.init.method === "DELETE")).toBe(true);
  });

  it("ignores preview-deployment rows the env listing merges in", async () => {
    // The same key exists only as a preview row: it must be CREATED in
    // production (a PATCH would 404 against the production scope), read
    // back as absent, and never deleted by its preview uuid.
    const calls: { url: string; init: RequestInit }[] = [];
    const fetchImpl = fakeFetch((url, init) => {
      if (url.endsWith("/envs") && (init.method ?? "GET") === "GET") {
        return {
          status: 200,
          body: [
            { uuid: "prod1", key: "SHARED", value: "prod", is_preview: false },
            { uuid: "prev1", key: "SHARED", value: "preview", is_preview: true },
            { uuid: "prev2", key: "ONLY_PREVIEW", value: "p", is_preview: true },
          ],
        };
      }
      return { status: 201 };
    }, calls);
    const req = baseReq(fetchImpl);

    await coolifyAdapter.writeValues(req, [
      { name: "SHARED", value: "x" },
      { name: "ONLY_PREVIEW", value: "y" },
    ]);
    expect(calls.slice(1).map((c) => `${c.init.method} ${bodyOf(c).key}`)).toEqual([
      "PATCH SHARED",
      "POST ONLY_PREVIEW",
    ]);

    const values = await coolifyAdapter.readValues!(req);
    expect(values.get("SHARED")).toBe("prod");
    expect(values.has("ONLY_PREVIEW")).toBe(false);

    calls.length = 0;
    await coolifyAdapter.deleteNames(req, ["SHARED", "ONLY_PREVIEW"]);
    const deletes = calls.filter((c) => c.init.method === "DELETE").map((c) => c.url);
    expect(deletes).toEqual(["https://coolify.example.com/api/v1/applications/app123/envs/prod1"]);
  });

  it("mirrors an existing row's flags on PATCH so a value update never strips them (current vocabulary)", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const fetchImpl = fakeFetch((url, init) => {
      if (url.endsWith("/envs") && (init.method ?? "GET") === "GET") {
        return {
          status: 200,
          body: [
            {
              uuid: "e1",
              key: "VITE_API",
              value: "old",
              is_preview: false,
              is_literal: true,
              is_multiline: null,
              is_shown_once: false,
              is_buildtime: true,
              is_runtime: false,
            },
          ],
        };
      }
      return { status: 201 };
    }, calls);
    await coolifyAdapter.writeValues(baseReq(fetchImpl), [{ name: "VITE_API", value: "new" }]);
    expect(bodyOf(calls[1]!)).toEqual({
      key: "VITE_API",
      value: "new",
      is_preview: false,
      is_literal: true,
      is_multiline: false,
      is_shown_once: false,
      is_buildtime: true,
      is_runtime: false,
    });
  });

  it("mirrors flags on PATCH in the legacy vocabulary and sends only fields legacy PATCH accepts", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const fetchImpl = fakeFetch((url, init) => {
      if (url.endsWith("/envs") && (init.method ?? "GET") === "GET") {
        return {
          status: 200,
          body: [
            {
              uuid: "e1",
              key: "VITE_API",
              value: "old",
              is_preview: false,
              is_literal: false,
              is_multiline: false,
              is_shown_once: false,
              is_build_time: true,
            },
          ],
        };
      }
      return { status: 201 };
    }, calls);
    await coolifyAdapter.writeValues(baseReq(fetchImpl), [{ name: "VITE_API", value: "new" }]);
    expect(bodyOf(calls[1]!)).toEqual({
      key: "VITE_API",
      value: "new",
      is_preview: false,
      is_literal: false,
      is_build_time: true,
    });
  });

  it("applies the buildTime option on create and on update, in the vocabulary the rows reveal", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const fetchImpl = fakeFetch((url, init) => {
      if (url.endsWith("/envs") && (init.method ?? "GET") === "GET") {
        return {
          status: 200,
          body: [{ uuid: "e1", key: "OLD", value: "v", is_preview: false, is_buildtime: false, is_runtime: true }],
        };
      }
      return { status: 201 };
    }, calls);
    const req = baseReq(fetchImpl, { applicationUuid: "app123", buildTime: "true" });
    await coolifyAdapter.writeValues(req, [
      { name: "OLD", value: "v2" },
      { name: "NEW", value: "n" },
    ]);
    expect(bodyOf(calls[1]!)).toMatchObject({ key: "OLD", is_buildtime: true, is_runtime: true });
    expect(bodyOf(calls[2]!)).toEqual({
      key: "NEW",
      value: "n",
      is_preview: false,
      is_buildtime: true,
      is_runtime: true,
    });

    // Legacy instance: the flag has its old name and nothing else is sent.
    calls.length = 0;
    const legacy = fakeFetch((url, init) => {
      if (url.endsWith("/envs") && (init.method ?? "GET") === "GET") {
        return { status: 200, body: [{ uuid: "e1", key: "OLD", value: "v", is_build_time: false }] };
      }
      return { status: 201 };
    }, calls);
    await coolifyAdapter.writeValues(baseReq(legacy, { applicationUuid: "app123", buildTime: "true" }), [
      { name: "NEW", value: "n" },
    ]);
    expect(bodyOf(calls[1]!)).toEqual({ key: "NEW", value: "n", is_preview: false, is_build_time: true });
  });

  it("buildTime=false keeps a key reachable at runtime", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const fetchImpl = fakeFetch((url, init) => {
      if (url.endsWith("/envs") && (init.method ?? "GET") === "GET") {
        return {
          status: 200,
          body: [{ uuid: "e1", key: "K", value: "v", is_buildtime: true, is_runtime: false }],
        };
      }
      return { status: 201 };
    }, calls);
    await coolifyAdapter.writeValues(baseReq(fetchImpl, { applicationUuid: "app123", buildTime: "false" }), [
      { name: "K", value: "v2" },
    ]);
    expect(bodyOf(calls[1]!)).toMatchObject({ is_buildtime: false, is_runtime: true });
  });

  it("falls back to the legacy vocabulary when an empty app rejects the current one", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const fetchImpl = fakeFetch((url, init) => {
      if (url.endsWith("/envs") && (init.method ?? "GET") === "GET") return { status: 200, body: [] };
      const body = JSON.parse(String(init.body)) as Record<string, unknown>;
      // A legacy instance: unknown fields fail validation.
      return "is_buildtime" in body ? { status: 422 } : { status: 201 };
    }, calls);
    const outcomes = await coolifyAdapter.writeValues(
      baseReq(fetchImpl, { applicationUuid: "app123", buildTime: "true" }),
      [
        { name: "A", value: "1" },
        { name: "B", value: "2" },
      ],
    );
    expect(outcomes).toEqual([
      { name: "A", ok: true },
      { name: "B", ok: true },
    ]);
    const posts = calls.filter((c) => c.init.method === "POST").map(bodyOf);
    // A: current guess rejected, legacy retry; B: legacy straight away.
    expect(posts.map((b) => ("is_buildtime" in b ? "current" : "legacy"))).toEqual([
      "current",
      "legacy",
      "legacy",
    ]);
    expect(posts[2]).toEqual({ key: "B", value: "2", is_preview: false, is_build_time: true });
  });

  it("stops a batch when shouldAbort reports lost authority", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const fetchImpl = fakeFetch((url, init) => {
      if (url.endsWith("/envs") && (init.method ?? "GET") === "GET") return { status: 200, body: [] };
      return { status: 201 };
    }, calls);
    let sent = 0;
    const req: AdapterRequest = {
      ...baseReq(fetchImpl),
      // Authority is lost after the first write goes out.
      shouldAbort: async () => sent++ >= 1,
    };
    const outcomes = await coolifyAdapter.writeValues(req, [
      { name: "A", value: "1" },
      { name: "B", value: "2" },
    ]);
    expect(outcomes).toEqual([{ name: "A", ok: true }]);
    expect(calls.filter((c) => c.init.method === "POST")).toHaveLength(1);
  });

  it("reads values back for verify-and-fix", async () => {
    const fetchImpl = fakeFetch(() => ({
      status: 200,
      body: [{ uuid: "e1", key: "A", value: "1" }, { uuid: "e2", key: "B", value: null }],
    }));
    const values = await coolifyAdapter.readValues!(baseReq(fetchImpl));
    expect(values.get("A")).toBe("1");
    expect(values.get("B")).toBe("");
  });

  it("redeploys with a forced rebuild by default, restarts on request, and reports failure", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const ok = fakeFetch(() => ({ status: 200, body: { message: "queued" } }), calls);
    await coolifyAdapter.triggerRedeploy!(baseReq(ok));
    await coolifyAdapter.triggerRedeploy!(baseReq(ok, { applicationUuid: "app123", deployAction: "restart" }));
    expect(calls.map((c) => `${c.init.method} ${c.url}`)).toEqual([
      "POST https://coolify.example.com/api/v1/applications/app123/start?force=true",
      "POST https://coolify.example.com/api/v1/applications/app123/restart",
    ]);

    // A restart is not a rebuild: build-time values stay stale, so the
    // adapter must never silently downgrade to it.
    const gone = fakeFetch(() => ({ status: 405, body: { message: "POST required" } }));
    await expect(coolifyAdapter.triggerRedeploy!(baseReq(gone))).rejects.toThrow(/deploy failed \(405\)/);
  });
});

describe("convex adapter", () => {
  const baseReq = (fetchImpl: typeof fetch): AdapterRequest => ({
    baseIdentity: "https://happy-animal-123.convex.cloud",
    destination: {},
    credential: "convex-key-material",
    fetchImpl,
  });
  const bodyOf = (c: { init: RequestInit }) => JSON.parse(String(c.init.body)) as Record<string, unknown>;

  it("declares per-deployment credential scoping, read-back, and no redeploy", () => {
    expect(convexAdapter.credentialScopeUnit).toBe("destination");
    expect(convexAdapter.supportsReadBack).toBe(true);
    expect(convexAdapter.supportsRedeploy).toBe(false);
    expect(convexAdapter.triggerRedeploy).toBeUndefined();
  });

  it("canonicalizes the deployment URL origin and requires https, no userinfo, no path", () => {
    expect(convexAdapter.canonicalizeBaseIdentity(" https://Happy-Animal-123.Convex.Cloud/ ")).toBe(
      "https://happy-animal-123.convex.cloud",
    );
    expect(convexAdapter.canonicalizeBaseIdentity("https://convex.internal.example:3210")).toBe(
      "https://convex.internal.example:3210",
    );
    expect(() => convexAdapter.canonicalizeBaseIdentity("http://convex.example")).toThrow(/https/);
    expect(() => convexAdapter.canonicalizeBaseIdentity("https://u:p@convex.example")).toThrow(/userinfo/);
    expect(() => convexAdapter.canonicalizeBaseIdentity("https://convex.example/api")).toThrow(/origin/);
    expect(() => convexAdapter.canonicalizeBaseIdentity("happy-animal-123")).toThrow(AdapterError);
  });

  it("takes no destination: empty record, stable key, rejects stray fields", () => {
    expect(convexAdapter.canonicalizeDestination({})).toEqual({ destination: {}, key: "" });
    // Blank form fields are as good as absent.
    expect(convexAdapter.canonicalizeDestination({ project: "", extra: null })).toEqual({
      destination: {},
      key: "",
    });
    expect(() => convexAdapter.canonicalizeDestination({ project: "my-app" })).toThrow(/no fields/);
    const identity = canonicalDestinationIdentity(
      "convex",
      "https://happy-animal-123.convex.cloud",
      "",
    );
    expect(identity).toBe(
      canonicalDestinationIdentity("convex", "https://happy-animal-123.convex.cloud", ""),
    );
    expect(identity).not.toBe(
      canonicalDestinationIdentity("convex", "https://other-animal-456.convex.cloud", ""),
    );
  });

  it("validates names against Convex's rule and keeps them case-sensitive", () => {
    expect(convexAdapter.validateName("DATABASE_URL")).toBeNull();
    expect(convexAdapter.validateName("lowercase_ok")).toBeNull();
    expect(convexAdapter.validateName("_leading_underscore")).toBeNull();
    expect(convexAdapter.validateName("1BAD")).toMatch(/digit/);
    expect(convexAdapter.validateName("BAD-NAME")).toMatch(/letters/);
    expect(convexAdapter.validateName("A".repeat(257))).toMatch(/256/);
    expect(convexAdapter.validateName("CONVEX_CLOUD_URL")).toMatch(/reserved/);
    expect(convexAdapter.validateName("CONVEX_SITE_URL")).toMatch(/reserved/);
    // Only the two system names are reserved, not the whole prefix.
    expect(convexAdapter.validateName("CONVEX_WEBHOOK_SECRET")).toBeNull();
    expect(convexAdapter.canonicalizeName("Database_Url")).toBe("Database_Url");
  });

  it("writes and deletes through one batched update call with per-name outcomes", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const fetchImpl = fakeFetch(() => ({ status: 200 }), calls);
    const req = baseReq(fetchImpl);

    const written = await convexAdapter.writeValues(req, [
      { name: "DATABASE_URL", value: "postgres://x" },
      { name: "API_KEY", value: "k" },
    ]);
    expect(written).toEqual([
      { name: "DATABASE_URL", ok: true },
      { name: "API_KEY", ok: true },
    ]);
    const deleted = await convexAdapter.deleteNames(req, ["STALE"]);
    expect(deleted).toEqual([{ name: "STALE", ok: true }]);

    expect(calls.map((c) => `${c.init.method} ${c.url}`)).toEqual([
      "POST https://happy-animal-123.convex.cloud/api/update_environment_variables",
      "POST https://happy-animal-123.convex.cloud/api/update_environment_variables",
    ]);
    expect(bodyOf(calls[0]!)).toEqual({
      changes: [
        { name: "DATABASE_URL", value: "postgres://x" },
        { name: "API_KEY", value: "k" },
      ],
    });
    // Deletion is value: null, exactly the CLI's env remove shape.
    expect(bodyOf(calls[1]!)).toEqual({ changes: [{ name: "STALE", value: null }] });
    for (const call of calls) {
      expect(new Headers(call.init.headers).get("Authorization")).toBe("Convex convex-key-material");
      expect(call.init.redirect).toBe("error");
    }
  });

  it("fails every name in the batch together and marks the status, never the credential", async () => {
    const fetchImpl = fakeFetch(() => ({ status: 403 }));
    const outcomes = await convexAdapter.writeValues(baseReq(fetchImpl), [
      { name: "A", value: "1" },
      { name: "B", value: "2" },
    ]);
    expect(outcomes).toEqual([
      { name: "A", ok: false, error: "HTTP 403" },
      { name: "B", ok: false, error: "HTTP 403" },
    ]);
    for (const o of outcomes) {
      expect(o.error).not.toContain("convex-key-material");
      expect(o.error).not.toContain("1");
    }
  });

  it("fails oversized values locally and still lands the valid remainder", async () => {
    // The batch is one transaction server-side: an 8 KiB+ value must never
    // enter it, or it would block every other name's write on each retry.
    const calls: { url: string; init: RequestInit }[] = [];
    const fetchImpl = fakeFetch(() => ({ status: 200 }), calls);
    const big = "x".repeat(8 * 1024 + 1);
    const outcomes = await convexAdapter.writeValues(baseReq(fetchImpl), [
      { name: "HUGE", value: big },
      { name: "OK", value: "fits" },
      { name: "EDGE", value: "a".repeat(8 * 1024) }, // exactly the limit: allowed
    ]);
    expect(outcomes).toEqual([
      { name: "HUGE", ok: false, error: "value exceeds Convex's 8192-byte limit" },
      { name: "OK", ok: true },
      { name: "EDGE", ok: true },
    ]);
    expect(outcomes[0]?.error).not.toContain("x".repeat(10));
    expect(calls).toHaveLength(1);
    const changes = (bodyOf(calls[0]!) as { changes: { name: string }[] }).changes;
    expect(changes.map((c) => c.name)).toEqual(["OK", "EDGE"]);
  });

  it("measures the value limit in UTF-8 bytes and sends nothing when all values are oversized", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const fetchImpl = fakeFetch(() => ({ status: 200 }), calls);
    // 4097 two-byte chars = 8194 bytes: over the limit despite < 8192 chars.
    const outcomes = await convexAdapter.writeValues(baseReq(fetchImpl), [
      { name: "MULTIBYTE", value: "é".repeat(4097) },
    ]);
    expect(outcomes).toEqual([
      { name: "MULTIBYTE", ok: false, error: "value exceeds Convex's 8192-byte limit" },
    ]);
    expect(calls).toHaveLength(0);
  });

  it("sends nothing once shouldAbort reports lost authority", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const fetchImpl = fakeFetch(() => ({ status: 200 }), calls);
    const req: AdapterRequest = { ...baseReq(fetchImpl), shouldAbort: async () => true };
    expect(await convexAdapter.writeValues(req, [{ name: "A", value: "1" }])).toEqual([]);
    expect(await convexAdapter.deleteNames(req, ["A"])).toEqual([]);
    expect(calls).toHaveLength(0);
  });

  it("stays visibly cut short when aborted with oversized items in the batch", async () => {
    // Locally failed oversized items must not pad the outcome list back to
    // full length: the engine detects a lost lease by truncation
    // (outcomes < items), and a padded list would hide the abort.
    const calls: { url: string; init: RequestInit }[] = [];
    const fetchImpl = fakeFetch(() => ({ status: 200 }), calls);
    const req: AdapterRequest = { ...baseReq(fetchImpl), shouldAbort: async () => true };
    const outcomes = await convexAdapter.writeValues(req, [
      { name: "HUGE", value: "x".repeat(8 * 1024 + 1) },
      { name: "OK", value: "fits" },
    ]);
    expect(outcomes).toEqual([
      { name: "HUGE", ok: false, error: "value exceeds Convex's 8192-byte limit" },
    ]);
    expect(outcomes.length).toBeLessThan(2);
    expect(calls).toHaveLength(0);
  });

  it("reads values back through the CLI's env list system query", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const fetchImpl = fakeFetch(() => ({
      status: 200,
      body: {
        status: "success",
        value: [
          { name: "DATABASE_URL", value: "postgres://x" },
          { name: "API_KEY", value: "k" },
        ],
      },
    }), calls);
    const values = await convexAdapter.readValues!(baseReq(fetchImpl));
    expect(values.get("DATABASE_URL")).toBe("postgres://x");
    expect(values.get("API_KEY")).toBe("k");
    expect(calls[0]?.url).toBe("https://happy-animal-123.convex.cloud/api/query");
    expect(bodyOf(calls[0]!)).toEqual({
      path: "_system/cli/queryEnvironmentVariables",
      args: {},
      format: "json",
    });
  });

  it("maps auth failures to non-retryable errors carrying only the status", async () => {
    for (const status of [401, 403, 404]) {
      const fetchImpl = fakeFetch(() => ({ status }));
      const err = await convexAdapter.readValues!(baseReq(fetchImpl)).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(AdapterError);
      expect((err as AdapterError).retryable).toBe(false);
      expect((err as AdapterError).message).toBe(`Convex env query failed (${status})`);
    }
    const flaky = fakeFetch(() => ({ status: 500 }));
    const err = await convexAdapter.readValues!(baseReq(flaky)).catch((e: unknown) => e);
    expect((err as AdapterError).retryable).toBe(true);
  });

  it("treats a UDF-level error as a failure without echoing the server's message", async () => {
    const fetchImpl = fakeFetch(() => ({
      status: 200,
      body: { status: "error", errorMessage: "boom convex-key-material" },
    }));
    const err = await convexAdapter.readValues!(baseReq(fetchImpl)).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AdapterError);
    expect((err as AdapterError).message).not.toContain("convex-key-material");
  });

  it("refuses to follow redirects off the pinned deployment origin", async () => {
    // With redirect: "error", the runtime rejects a redirect response; the
    // adapter must surface it as a transport failure carrying no material.
    const fetchImpl = (async () => {
      throw new TypeError("unexpected redirect");
    }) as typeof fetch;
    const err = await convexAdapter
      .writeValues(baseReq(fetchImpl), [{ name: "A", value: "secret-value" }])
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AdapterError);
    expect((err as AdapterError).message).toBe("TypeError");
    expect((err as AdapterError).message).not.toContain("secret-value");
  });
});

describe("access checks", () => {
  const github = (fetchImpl: typeof fetch, destination: Record<string, string> = {}): AdapterRequest => ({
    baseIdentity: "acme",
    destination,
    credential: "github_pat_test",
    fetchImpl,
  });
  const coolify = (fetchImpl: typeof fetch, destination: Record<string, string> = {}): AdapterRequest => ({
    baseIdentity: "https://coolify.example.com",
    destination,
    credential: "tok",
    fetchImpl,
  });
  const convex = (fetchImpl: typeof fetch): AdapterRequest => ({
    baseIdentity: "https://happy-animal-123.convex.cloud",
    destination: {},
    credential: "convex-key-material",
    fetchImpl,
  });
  const failing = (err: Error) =>
    (async () => {
      throw err;
    }) as typeof fetch;

  it("every adapter checks access", () => {
    for (const platform of ["github-actions", "coolify", "convex"]) {
      expect(typeof getAdapter(platform).checkAccess).toBe("function");
    }
  });

  describe("github-actions", () => {
    it("checks the owner with the token, and nothing else, without a destination", async () => {
      const calls: { url: string; init: RequestInit }[] = [];
      const result = await githubActionsAdapter.checkAccess(github(fakeFetch(() => ({ status: 200, body: {} }), calls)));
      expect(result.status).toBe("ok");
      expect(calls.map((c) => [c.init.method, c.url])).toEqual([["GET", "https://api.github.com/users/acme"]]);
      expect((calls[0]!.init.headers as Record<string, string>).Authorization).toBe("Bearer github_pat_test");
    });

    it("tells a rejected token from an unknown owner", async () => {
      expect((await githubActionsAdapter.checkAccess(github(fakeFetch(() => ({ status: 401 }))))).status).toBe(
        "credential-rejected",
      );
      const missing = await githubActionsAdapter.checkAccess(github(fakeFetch(() => ({ status: 404 }))));
      expect(missing).toMatchObject({ status: "not-found", httpStatus: 404, where: "connection" });
      expect(missing.message).toContain("acme");
    });

    it("reads the destination's public key, the request every push starts with", async () => {
      const calls: { url: string; init: RequestInit }[] = [];
      const result = await githubActionsAdapter.checkAccess(
        github(fakeFetch(() => ({ status: 200, body: { key_id: "k", key: "x" } }), calls), { repo: "api", environment: "production" }),
      );
      expect(result.status).toBe("ok");
      expect(calls.map((c) => c.url)).toEqual([
        "https://api.github.com/users/acme",
        "https://api.github.com/repos/acme/api/environments/production/secrets/public-key",
      ]);
      expect(calls.every((c) => c.init.method === "GET")).toBe(true);
    });

    it("names the permission the destination needs", async () => {
      const refuse = fakeFetch((url) => (url.endsWith("/public-key") ? { status: 403 } : { status: 200, body: {} }));
      const repoSecrets = await githubActionsAdapter.checkAccess(github(refuse, { repo: "api" }));
      expect(repoSecrets.status).toBe("permission-missing");
      expect(repoSecrets.message).toContain("Secrets: Read and write");
      const envSecrets = await githubActionsAdapter.checkAccess(github(refuse, { repo: "api", environment: "production" }));
      expect(envSecrets.message).toContain("Environments: Read and write");
    });

    it("reads a rate limit as unreachable, not as a missing permission", async () => {
      const result = await githubActionsAdapter.checkAccess(
        github(
          fakeFetch((url) =>
            url.endsWith("/public-key") ? { status: 403, headers: { "x-ratelimit-remaining": "0" } } : { status: 200, body: {} },
          ),
          { repo: "api" },
        ),
      );
      expect(result.status).toBe("unreachable");
    });

    it("tells a missing environment from a repository the token cannot see", async () => {
      const noEnvironment = await githubActionsAdapter.checkAccess(
        github(fakeFetch((url) => (url.endsWith("/public-key") ? { status: 404 } : { status: 200, body: {} })), {
          repo: "api",
          environment: "staging",
        }),
      );
      expect(noEnvironment).toMatchObject({ status: "not-found", where: "destination" });
      expect(noEnvironment.message).toContain("no environment named staging");
      const noRepo = await githubActionsAdapter.checkAccess(
        github(fakeFetch((url) => (url.endsWith("/users/acme") ? { status: 200, body: {} } : { status: 404 })), {
          repo: "api",
          environment: "staging",
        }),
      );
      expect(noRepo.message).toContain("cannot find acme/api");
    });

    it("never throws and never repeats what the platform said", async () => {
      const unreachable = await githubActionsAdapter.checkAccess(github(failing(new TypeError("fetch failed"))));
      expect(unreachable.status).toBe("unreachable");
      const odd = await githubActionsAdapter.checkAccess(
        github(fakeFetch(() => ({ status: 418, body: { message: "platform-composed text" } }))),
      );
      expect(odd).toMatchObject({ status: "failed", httpStatus: 418 });
      expect(odd.message).not.toContain("platform-composed text");
    });
  });

  describe("coolify", () => {
    it("checks the instance, then the application, read-only", async () => {
      const calls: { url: string; init: RequestInit }[] = [];
      const result = await coolifyAdapter.checkAccess(
        coolify(fakeFetch(() => ({ status: 200, body: {} }), calls), { applicationUuid: "app123" }),
      );
      expect(result.status).toBe("ok");
      expect(calls.map((c) => [c.init.method, c.url])).toEqual([
        ["GET", "https://coolify.example.com/api/v1/version"],
        ["GET", "https://coolify.example.com/api/v1/applications/app123"],
      ]);
    });

    it("picks advice from Coolify's 403 reason without repeating it", async () => {
      const reasons: [string, string][] = [
        ["API is disabled.", "API is off"],
        ["You are not allowed to access the API.", "IP addresses"],
        ["Missing required permissions: read", "read and write"],
        ["This API token has permissions (write) that exceed your current role as a team member.", "team admin"],
      ];
      for (const [reason, advice] of reasons) {
        const result = await coolifyAdapter.checkAccess(coolify(fakeFetch(() => ({ status: 403, body: { message: reason } }))));
        expect(result.status).toBe("permission-missing");
        expect(result.message).toContain(advice);
        expect(result.message).not.toContain(reason);
      }
    });

    it("reports a rejected token, a wrong URL, and another team's application", async () => {
      expect((await coolifyAdapter.checkAccess(coolify(fakeFetch(() => ({ status: 401 }))))).status).toBe("credential-rejected");
      const wrongUrl = await coolifyAdapter.checkAccess(coolify(fakeFetch(() => ({ status: 404 }))));
      expect(wrongUrl).toMatchObject({ status: "not-found", where: "connection" });
      expect(wrongUrl.message).toContain("No Coolify API answered at coolify.example.com");
      const noApp = await coolifyAdapter.checkAccess(
        coolify(fakeFetch((url) => (url.endsWith("/version") ? { status: 200, body: "4.0.0" } : { status: 404 })), {
          applicationUuid: "app123",
        }),
      );
      expect(noApp).toMatchObject({ status: "not-found", httpStatus: 404, where: "destination" });
      expect(noApp.message).toContain("app123");
    });

    it("tells a redirect, an unknown host, a refusal, and an untrusted certificate apart", async () => {
      const transport = (cause: object) => Object.assign(new TypeError("fetch failed"), { cause });
      const cases: [object, string][] = [
        [{ message: "unexpected redirect" }, "redirect, which Varlatch does not follow"],
        [{ code: "ENOTFOUND", message: "getaddrinfo ENOTFOUND coolify.example.com" }, "No address was found for coolify.example.com"],
        [{ code: "ECONNREFUSED" }, "refused the connection"],
        [{ code: "DEPTH_ZERO_SELF_SIGNED_CERT" }, "does not trust the certificate"],
        [{ code: "ECONNRESET" }, "could not reach coolify.example.com"],
      ];
      for (const [cause, text] of cases) {
        const result = await coolifyAdapter.checkAccess(coolify(failing(transport(cause))));
        expect(result).toMatchObject({ status: "unreachable", where: "connection" });
        expect(result.message).toContain(text);
      }
    });

    it("says when the address answers, but not like Coolify", async () => {
      const result = await coolifyAdapter.checkAccess(coolify(fakeFetch(() => ({ status: 410, body: { message: "Gone" } }))));
      expect(result).toMatchObject({ status: "failed", where: "connection", httpStatus: 410 });
      expect(result.message).toBe("coolify.example.com does not answer like a Coolify instance (HTTP 410). Check the address.");
    });

    it("reads server errors and timeouts as unreachable", async () => {
      expect((await coolifyAdapter.checkAccess(coolify(fakeFetch(() => ({ status: 502 }))))).status).toBe("unreachable");
      const timeout = Object.assign(new Error("aborted"), { name: "TimeoutError" });
      const result = await coolifyAdapter.checkAccess(coolify(failing(timeout)));
      expect(result).toMatchObject({ status: "unreachable" });
      expect(result.message).toContain("did not answer in time");
    });
  });

  describe("convex", () => {
    it("asks the deployment's key check, with GET and no body", async () => {
      const calls: { url: string; init: RequestInit }[] = [];
      const result = await convexAdapter.checkAccess(
        convex(fakeFetch(() => ({ status: 200, body: { success: true, allowedOps: [], isReadOnly: false } }), calls)),
      );
      expect(result.status).toBe("ok");
      expect(calls).toHaveLength(1);
      expect(calls[0]!.url).toBe("https://happy-animal-123.convex.cloud/api/check_admin_key");
      expect(calls[0]!.init.method).toBe("GET");
      expect(calls[0]!.init.body).toBeUndefined();
    });

    it("refuses a key that may not set environment variables", async () => {
      const readOnly = await convexAdapter.checkAccess(
        convex(fakeFetch(() => ({ status: 200, body: { allowedOps: [], isReadOnly: true } }))),
      );
      expect(readOnly.status).toBe("permission-missing");
      const narrowed = await convexAdapter.checkAccess(
        convex(fakeFetch(() => ({ status: 200, body: { allowedOps: ["ViewData"], isReadOnly: false } }))),
      );
      expect(narrowed.status).toBe("permission-missing");
      const allowed = await convexAdapter.checkAccess(
        convex(fakeFetch(() => ({ status: 200, body: { allowedOps: ["WriteEnvironmentVariables"], isReadOnly: false } }))),
      );
      expect(allowed.status).toBe("ok");
    });

    it("reports a key for another deployment, and a URL that is not one", async () => {
      expect((await convexAdapter.checkAccess(convex(fakeFetch(() => ({ status: 403 }))))).status).toBe("credential-rejected");
      expect((await convexAdapter.checkAccess(convex(fakeFetch(() => ({ status: 404 }))))).status).toBe("not-found");
      const notConvex = (async () => new Response("<html></html>", { status: 200 })) as typeof fetch;
      expect((await convexAdapter.checkAccess(convex(notConvex))).status).toBe("failed");
    });
  });
});
