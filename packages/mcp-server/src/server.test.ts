// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { VarlatchClient } from "@varlatch/sdk";
import { createVarlatchMcpServer, type VarlatchMcpOptions } from "./server.js";

/**
 * The MCP server's tools (ADR-0043 Decision 9): read tools by default, writes
 * with allowWrites, never a disclosure tool, and never a Secret's value written.
 */

interface RecordedRequest {
  method: string;
  url: string;
  body: unknown;
}

function fakeClient(responses: Record<string, unknown>): {
  client: VarlatchClient;
  requests: RecordedRequest[];
} {
  const requests: RecordedRequest[] = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = String(input);
    const path = new URL(url).pathname;
    requests.push({
      method: init?.method ?? "GET",
      url,
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    });
    const hit = Object.entries(responses).find(([key]) => path === key);
    if (!hit) {
      return new Response(
        JSON.stringify({ error: { code: "NOT_FOUND", message: `no stub for ${path}`, requestId: "t" } }),
        { status: 404 },
      );
    }
    // A stub `{ status, error }` answers with that API error.
    const stub = hit[1] as { status?: number; error?: string };
    if (stub.status && stub.error) {
      return new Response(JSON.stringify({ error: { code: stub.error, message: stub.error, requestId: "t" } }), { status: stub.status });
    }
    return new Response(JSON.stringify(hit[1]), { status: 200 });
  };
  return {
    client: new VarlatchClient({ server: "https://varlatch.test", token: "tok", fetch: fetchImpl }),
    requests,
  };
}

async function connect(options: VarlatchMcpOptions): Promise<Client> {
  const server = createVarlatchMcpServer(options);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const mcpClient = new Client({ name: "test", version: "0.0.0" });
  await Promise.all([server.connect(serverTransport), mcpClient.connect(clientTransport)]);
  return mcpClient;
}

const defaults = { organization: "acme", project: "api", environment: "dev" };

describe("varlatch MCP server", () => {
  it("registers only read tools by default", async () => {
    const { client } = fakeClient({});
    const mcp = await connect({ client, defaults });
    const names = (await mcp.listTools()).tools.map((t) => t.name).sort();
    expect(names).toEqual([
      "varlatch_effective_configuration",
      "varlatch_get_active_contract",
      "varlatch_list_audit_events",
      "varlatch_list_environments",
      "varlatch_list_organizations",
      "varlatch_list_projects",
      "varlatch_validate_environment",
      "varlatch_whoami",
    ]);
  });

  it("registers the write tools when enabled, and never a disclosure tool", async () => {
    const { client } = fakeClient({});
    const mcp = await connect({ client, defaults, allowWrites: true });
    const names = (await mcp.listTools()).tools.map((t) => t.name);
    expect(names).toContain("varlatch_set_value");
    expect(names).toContain("varlatch_delete_value");
    expect(names.filter((n) => /disclose|secret|reveal/i.test(n))).toEqual([]);
    // Calling it by name reaches no handler.
    const result = await mcp.callTool({ name: "varlatch_disclose_secrets", arguments: { items: ["API_KEY"] } }).catch((e: unknown) => e);
    expect(JSON.stringify(result)).toMatch(/not found|Tool varlatch_disclose_secrets/i);
  });

  it("lists projects using the default organization", async () => {
    const { client, requests } = fakeClient({
      "/v1/organizations/acme/projects": { items: [{ slug: "api" }], nextCursor: null },
    });
    const mcp = await connect({ client, defaults });
    const result = await mcp.callTool({ name: "varlatch_list_projects", arguments: {} });
    expect(result.isError).toBeFalsy();
    const text = (result.content as { type: string; text: string }[])[0]!.text;
    expect(JSON.parse(text).items[0].slug).toBe("api");
    expect(requests[0]!.method).toBe("GET");
  });

  const CONTRACT = "/v1/organizations/acme/projects/api/contract";
  const contract = {
    id: "crv_1",
    contract: {
      schemaVersion: 1,
      items: [
        { name: "LOG_LEVEL", sensitive: false, type: "string", required: { kind: "never" } },
        { name: "API_KEY", sensitive: true, type: "string", required: { kind: "never" } },
      ],
    },
  };

  const EFFECTIVE = "/v1/organizations/acme/projects/api/environments/dev/effective-configuration";
  const PUT_LOG_LEVEL = "/v1/organizations/acme/projects/api/environments/dev/values/LOG_LEVEL";
  const effective = (items: { name: string; source: "self" | "parent" }[]) => ({
    environmentId: "env_1",
    items: items.map((i) => ({ ...i, sensitive: false })),
  });
  const textOf = (result: Awaited<ReturnType<Client["callTool"]>>) => (result.content as { type: string; text: string }[])[0]!.text;
  const puts = (requests: RecordedRequest[]) => requests.filter((r) => r.method === "PUT");

  it("sets a new non-secret value against the resolved environment, without replace", async () => {
    const { client, requests } = fakeClient({ [CONTRACT]: contract, [EFFECTIVE]: effective([]), [PUT_LOG_LEVEL]: { versionId: "v1" } });
    const mcp = await connect({ client, defaults, allowWrites: true });
    const result = await mcp.callTool({ name: "varlatch_set_value", arguments: { item: "LOG_LEVEL", value: "debug" } });
    expect(result.isError).toBeFalsy();
    expect(puts(requests)).toMatchObject([{ body: { value: "debug" } }]);
    // Existence from metadata only: no values are read.
    expect(requests.find((r) => r.url.includes("/effective-configuration"))?.url).not.toMatch(/include/);
  });

  it.each([
    ["a value the environment has", effective([{ name: "LOG_LEVEL", source: "self" }]), /LOG_LEVEL already has a value in dev; setting it replaces that value\./],
    ["a value inherited from the parent environment", effective([{ name: "LOG_LEVEL", source: "parent" }]), /dev inherits a value for LOG_LEVEL from its parent environment; setting it here overrides that value in dev\./],
    ["a value whose existence cannot be checked", { status: 403, error: "PERMISSION_DENIED" }, /whether LOG_LEVEL already has a value in dev cannot be checked \(403 PERMISSION_DENIED\), so it counts as existing\./],
  ])("replacing %s needs replace naming the item: refused without it, written with it", async (_name, existing, message) => {
    const { client, requests } = fakeClient({ [CONTRACT]: contract, [EFFECTIVE]: existing, [PUT_LOG_LEVEL]: { versionId: "v2" } });
    const mcp = await connect({ client, defaults, allowWrites: true });
    // expectedVersionId guards against a concurrent change; it is no substitute for replace.
    for (const args of [{ item: "LOG_LEVEL", value: "debug" }, { item: "LOG_LEVEL", value: "debug", expectedVersionId: "v1" }]) {
      const refused = await mcp.callTool({ name: "varlatch_set_value", arguments: args });
      expect(refused.isError).toBe(true);
      expect(textOf(refused)).toMatch(message);
      expect(textOf(refused)).toMatch(/Replacing it is the human's decision, for this item only: ask them, and with their approval pass replace: "LOG_LEVEL"\. Nothing was stored\./);
    }
    expect(puts(requests)).toEqual([]);
    const approved = await mcp.callTool({ name: "varlatch_set_value", arguments: { item: "LOG_LEVEL", value: "debug", expectedVersionId: "v1", replace: "LOG_LEVEL" } });
    expect(approved.isError).toBeFalsy();
    expect(puts(requests)).toMatchObject([{ body: { value: "debug", expectedVersionId: "v1" } }]);
  });

  it("replace naming another item is refused before any request", async () => {
    const { client, requests } = fakeClient({ [CONTRACT]: contract, [EFFECTIVE]: effective([]), [PUT_LOG_LEVEL]: { versionId: "v1" } });
    const mcp = await connect({ client, defaults, allowWrites: true });
    const result = await mcp.callTool({ name: "varlatch_set_value", arguments: { item: "LOG_LEVEL", value: "debug", replace: "API_KEY" } });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/replace names API_KEY, but this call sets LOG_LEVEL; approval for one item never covers another\. Nothing was stored\./);
    expect(requests).toEqual([]);
  });

  it.each([
    ["a Secret in the Contract", "API_KEY", { [CONTRACT]: contract }],
    ["an item outside the Contract", "UNLISTED", { [CONTRACT]: contract }],
    ["any item of a project without a Contract", "LOG_LEVEL", {}],
    ["any item when the Contract cannot be read", "LOG_LEVEL", { [CONTRACT]: { status: 403, error: "PERMISSION_DENIED" } }],
  ])("refuses to write %s, and writes nothing", async (_name, item, stubs) => {
    const { client, requests } = fakeClient({
      ...stubs,
      [`/v1/organizations/acme/projects/api/environments/dev/values/${item}`]: { versionId: "v1" },
    });
    const mcp = await connect({ client, defaults, allowWrites: true });
    // replace never makes a Secret writable.
    for (const extra of [{}, { replace: item }]) {
      const result = await mcp.callTool({ name: "varlatch_set_value", arguments: { item, value: "mcp-secret-value-1", ...extra } });
      expect(result.isError).toBe(true);
      const text = (result.content as { type: string; text: string }[])[0]!.text;
      expect(text).toMatch(new RegExp(`${item} is a Secret, and its value is never written through MCP`));
      expect(text).toMatch(/--generate hex:32/);
      expect(text).not.toContain("mcp-secret-value-1");
    }
    expect(requests.filter((r) => r.method !== "GET")).toEqual([]);
  });

  it("deleting a value writes no value, and stays available with --allow-writes, given the item's name as confirm", async () => {
    const { client, requests } = fakeClient({ "/v1/organizations/acme/projects/api/environments/dev/values/API_KEY": {} });
    const mcp = await connect({ client, defaults, allowWrites: true });
    const result = await mcp.callTool({ name: "varlatch_delete_value", arguments: { item: "API_KEY", confirm: "API_KEY" } });
    expect(result.isError).toBeFalsy();
    expect(requests).toMatchObject([{ method: "DELETE", url: "https://varlatch.test/v1/organizations/acme/projects/api/environments/dev/values/API_KEY" }]);
  });

  it.each([
    ["no confirm (--allow-writes alone records no intent)", { item: "API_KEY" }, /deleting API_KEY from dev is the human's decision, for this item in this environment\. Ask the human, and with their approval for API_KEY in dev, pass confirm: "API_KEY"\. Nothing was deleted\./],
    ["confirm naming another item", { item: "API_KEY", confirm: "LOG_LEVEL" }, /confirm names LOG_LEVEL, but this call deletes API_KEY; approval for one item never covers another/],
    ["a plain item without confirm (sensitivity is not consulted)", { item: "LOG_LEVEL" }, /deleting LOG_LEVEL from dev is the human's decision/],
    ["an empty confirm", { item: "API_KEY", confirm: "" }, /confirm names , but this call deletes API_KEY/],
  ])("refuses a deletion with %s, before any request", async (_name, args, message) => {
    const { client, requests } = fakeClient({
      "/v1/organizations/acme/projects/api/environments/dev/values/API_KEY": {},
      "/v1/organizations/acme/projects/api/environments/dev/values/LOG_LEVEL": {},
    });
    const mcp = await connect({ client, defaults, allowWrites: true });
    const result = await mcp.callTool({ name: "varlatch_delete_value", arguments: args });
    expect(result.isError).toBe(true);
    expect((result.content as { type: string; text: string }[])[0]!.text).toMatch(message);
    expect(requests).toEqual([]);
  });

  it("the confirmation names the environment the deletion targets", async () => {
    const { client, requests } = fakeClient({ "/v1/organizations/acme/projects/api/environments/production/values/API_KEY": {} });
    const mcp = await connect({ client, defaults, allowWrites: true });
    const refused = await mcp.callTool({ name: "varlatch_delete_value", arguments: { item: "API_KEY", environment: "production" } });
    expect((refused.content as { type: string; text: string }[])[0]!.text).toMatch(/from production .* for API_KEY in production/);
    expect(requests).toEqual([]);
    const done = await mcp.callTool({ name: "varlatch_delete_value", arguments: { item: "API_KEY", environment: "production", confirm: "API_KEY" } });
    expect(done.isError).toBeFalsy();
    expect(requests).toMatchObject([{ method: "DELETE", url: expect.stringContaining("/environments/production/values/API_KEY") }]);
  });

  describe("varlatch_whoami", () => {
    const caller = {
      identity: { id: "idn_1", name: "runner-macmini", kind: "service", email: null },
      organization: { id: "org_1", slug: "acme", name: "Acme", createdAt: "2026-09-01T00:00:00.000Z" },
      credential: { id: "crd_1", name: "desktop-runner", kind: "service", expiresAt: null },
      listener: "tailnet",
      tailnet: { recognized: true, tailnet: "example.ts.net", nodeId: "nRunner", nodeName: "macmini", tags: ["tag:desktop-runner"] },
    };
    const meta = (capabilities: string[]) => ({ apiMajor: 1, serverVersion: "0.17.0", capabilities });
    const whoami = async (responses: Record<string, unknown>) => {
      const { client, requests } = fakeClient(responses);
      const mcp = await connect({ client, defaults });
      const result = await mcp.callTool({ name: "varlatch_whoami", arguments: {} });
      expect(result.isError).toBeFalsy();
      return { body: JSON.parse(textOf(result)) as Record<string, unknown>, requests };
    };

    it("names the caller: identity, organization, credential, and device, never a token", async () => {
      const { body, requests } = await whoami({ "/v1/meta": meta(["identity.whoami"]), "/v1/me": caller });
      expect(body).toMatchObject({ server: "https://varlatch.test", caller, defaults, allowWrites: false });
      expect(body).not.toHaveProperty("callerUnavailable");
      expect(JSON.stringify(body)).not.toContain("tok");
      expect(requests.map((r) => new URL(r.url).pathname)).toEqual(["/v1/meta", "/v1/me"]);
    });

    it("on a server without identity.whoami, says so and still answers, without asking /v1/me", async () => {
      const { body, requests } = await whoami({ "/v1/meta": meta([]) });
      expect(body).toMatchObject({ caller: null, callerUnavailable: expect.stringMatching(/no identity\.whoami capability/), defaults });
      expect(requests.map((r) => new URL(r.url).pathname)).toEqual(["/v1/meta"]);
    });

    it("with a credential the server refuses, says why and still answers", async () => {
      const { body } = await whoami({ "/v1/meta": meta(["identity.whoami"]), "/v1/me": { status: 401, error: "INVALID_CREDENTIAL" } });
      expect(body).toMatchObject({ caller: null, callerUnavailable: expect.stringMatching(/401 \(INVALID_CREDENTIAL/) });
    });
  });

  it("returns a tool error when scope cannot be resolved", async () => {
    const { client } = fakeClient({});
    const mcp = await connect({ client, defaults: {} });
    const result = await mcp.callTool({ name: "varlatch_list_projects", arguments: {} });
    expect(result.isError).toBe(true);
    const text = (result.content as { type: string; text: string }[])[0]!.text;
    expect(text).toContain("organization");
  });

  it("surfaces API errors with code and requestId", async () => {
    const { client } = fakeClient({});
    const mcp = await connect({ client, defaults });
    const result = await mcp.callTool({ name: "varlatch_list_organizations", arguments: {} });
    expect(result.isError).toBe(true);
    const text = (result.content as { type: string; text: string }[])[0]!.text;
    expect(text).toContain("NOT_FOUND");
  });
});
