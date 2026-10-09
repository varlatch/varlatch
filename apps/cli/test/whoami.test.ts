// SPDX-License-Identifier: Apache-2.0
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import type { Meta, WhoAmI } from "@varlatch/protocol";
import { WhoamiUnsupportedError, fetchWhoami, formatWhoamiHuman, whoamiServer, type WhoamiApi } from "../src/whoami.js";

/**
 * `varlatch whoami` (capability identity.whoami): asks GET /v1/me only when
 * the server says it can answer, picks the server the way the rest of the
 * CLI does, and prints names and identifiers, never a token.
 */

const machine: WhoAmI = {
  identity: { id: "idn_1", name: "runner-macmini", kind: "service", email: null },
  organization: { id: "org_1", slug: "acme", name: "Acme", createdAt: "2026-09-01T00:00:00.000Z" },
  credential: { id: "crd_1", name: "desktop-runner", kind: "service", expiresAt: null },
  listener: "ordinary",
};

const human: WhoAmI = {
  identity: { id: "idn_h", name: "Jeremy", kind: "human", email: "jeremy@example.com" },
  organization: null,
  credential: { id: "crd_h", name: "browser-handoff login", kind: "cli", expiresAt: "2026-10-10T08:00:00.000Z" },
  listener: "ordinary",
};

function fakeApi(capabilities: string[], caller: WhoAmI = machine): WhoamiApi & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    meta: async () => {
      calls.push("meta");
      return { apiMajor: 1, serverVersion: "0.16.0", capabilities } as Meta;
    },
    whoami: async () => {
      calls.push("whoami");
      return caller;
    },
  };
}

describe("fetchWhoami", () => {
  it("asks /v1/me when the server has identity.whoami", async () => {
    const api = fakeApi(["identity.whoami"]);
    await expect(fetchWhoami(api)).resolves.toEqual(machine);
    expect(api.calls).toEqual(["meta", "whoami"]);
  });

  it("refuses, naming the server's version and the capability, before asking an older server", async () => {
    const api = fakeApi(["identity.lifecycle"]);
    const err = await fetchWhoami(api).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(WhoamiUnsupportedError);
    expect((err as Error).message).toMatch(/this server \(0\.16\.0\) cannot say which identity .*identity\.whoami/);
    expect(api.calls).toEqual(["meta"]);
  });
});

describe("formatWhoamiHuman", () => {
  it("a machine: its identity, organization, and credential", () => {
    expect(formatWhoamiHuman("https://v.example", machine)).toBe(
      [
        "Identity      runner-macmini (service, idn_1)",
        "Organization  acme (Acme, org_1)",
        "Credential    desktop-runner (service, crd_1), no expiry",
        "Server        https://v.example (ordinary listener)",
      ].join("\n"),
    );
  });

  it("a person: the email, no organization of their own, and the credential's expiry", () => {
    expect(formatWhoamiHuman("https://v.example", human)).toBe(
      [
        "Identity      Jeremy (human, idn_h)",
        "Email         jeremy@example.com",
        "Organization  none: a person joins organizations as a member (varlatch org list)",
        "Credential    browser-handoff login (cli, crd_h), expires 2026-10-10T08:00:00.000Z",
        "Server        https://v.example (ordinary listener)",
      ].join("\n"),
    );
  });

  it("the tailnet listener's device, recognized or not", () => {
    const on = (tailnet: WhoAmI["tailnet"]) =>
      formatWhoamiHuman("http://varlatch:8687", { ...machine, listener: "tailnet", tailnet }).split("\n").slice(-2);
    expect(on({ recognized: true, tailnet: "example.ts.net", nodeId: "nR", nodeName: "macmini", tags: ["tag:desktop-runner", "tag:runner-macmini"] })).toEqual([
      "Server        http://varlatch:8687 (tailnet listener)",
      "Device        macmini (nR), tags tag:desktop-runner, tag:runner-macmini, on example.ts.net",
    ]);
    // A device Tailscale gave no machine name.
    expect(on({ recognized: true, tailnet: "example.ts.net", nodeId: "nR", tags: ["tag:desktop-runner"] })[1]).toBe(
      "Device        node nR, tags tag:desktop-runner, on example.ts.net",
    );
    expect(on({ recognized: true, tailnet: "example.ts.net", nodeId: "nL", nodeName: "laptop", tags: [], userLogin: "j@example.com" })[1]).toBe(
      "Device        laptop (nL), user j@example.com, on example.ts.net",
    );
    expect(on({ recognized: false, reason: "shared" })[1]).toBe("Device        not recognized (shared)");
  });

  it("an unnamed credential, and a machine whose organization is gone", () => {
    const text = formatWhoamiHuman("https://v.example", {
      ...machine,
      organization: null,
      credential: { ...machine.credential, name: null },
    });
    expect(text).toMatch(/^Organization {2}none$/m);
    expect(text).toMatch(/^Credential {4}unnamed \(service, crd_1\), no expiry$/m);
  });
});

describe("whoamiServer", () => {
  const dir = mkdtempSync(join(tmpdir(), "varlatch-whoami-server-"));
  const repo = join(dir, "repo");
  mkdirSync(repo);
  writeFileSync(join(repo, "varlatch.toml"), 'organization = "acme"\nproject = "web"\nserver = "https://repo.example"\n');
  const outside = join(dir, "outside");
  mkdirSync(outside);
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("--server first, then VARLATCH_SERVER, then the repository's server", () => {
    const env = { VARLATCH_SERVER: "https://env.example" };
    expect(whoamiServer({ server: "https://flag.example", env, cwd: repo, stored: [] })).toBe("https://flag.example");
    expect(whoamiServer({ server: undefined, env, cwd: repo, stored: [] })).toBe("https://env.example");
    expect(whoamiServer({ server: undefined, env: {}, cwd: repo, stored: ["https://stored.example"] })).toBe("https://repo.example");
  });

  it("outside a repository: the flag, the variable, else the only stored server", () => {
    expect(whoamiServer({ server: "https://flag.example", env: {}, cwd: outside, stored: [] })).toBe("https://flag.example");
    expect(whoamiServer({ server: undefined, env: { VARLATCH_SERVER: "https://env.example" }, cwd: outside, stored: [] })).toBe(
      "https://env.example",
    );
    expect(whoamiServer({ server: undefined, env: {}, cwd: outside, stored: ["https://stored.example"] })).toBe("https://stored.example");
    expect(whoamiServer({ server: undefined, env: {}, cwd: outside, stored: ["https://a.example", "https://b.example"] })).toBeNull();
    expect(whoamiServer({ server: undefined, env: {}, cwd: outside, stored: [] })).toBeNull();
  });
});
