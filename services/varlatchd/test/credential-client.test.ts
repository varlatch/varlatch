// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CLIENT_LABEL_MAX, clientLabel } from "../src/auth/client-label.js";
import { issueCredential } from "../src/auth/credentials.js";
import type { HumanAuth } from "../src/auth/humanauth.js";
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
 * A credential's readable client label: a short summary of the User-Agent
 * that requested a browser session or CLI login credential. Only the
 * summary is stored, never the header.
 */

const UA = {
  firefoxLinux: "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
  firefoxAndroid: "Mozilla/5.0 (Android 14; Mobile; rv:131.0) Gecko/131.0 Firefox/131.0",
  chromeMac:
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
  chromeAndroid:
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
  chromeIos:
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/129.0.6668.69 Mobile/15E148 Safari/604.1",
  chromeOs:
    "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
  safariMac:
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
  safariIos:
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
  edgeWindows:
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.2792.79",
  operaWindows:
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 OPR/114.0.0.0",
};

describe("clientLabel", () => {
  it("summarizes common browsers as browser and system, without versions", () => {
    expect(clientLabel(UA.firefoxLinux)).toBe("Firefox on Linux");
    expect(clientLabel(UA.firefoxAndroid)).toBe("Firefox on Android");
    expect(clientLabel(UA.chromeMac)).toBe("Chrome on macOS");
    expect(clientLabel(UA.chromeAndroid)).toBe("Chrome on Android");
    expect(clientLabel(UA.chromeIos)).toBe("Chrome on iOS");
    expect(clientLabel(UA.chromeOs)).toBe("Chrome on ChromeOS");
    expect(clientLabel(UA.safariMac)).toBe("Safari on macOS");
    expect(clientLabel(UA.safariIos)).toBe("Safari on iOS");
    expect(clientLabel(UA.edgeWindows)).toBe("Edge on Windows");
    expect(clientLabel(UA.operaWindows)).toBe("Opera on Windows");
    expect(clientLabel("Mozilla/5.0 Firefox/131.0")).toBe("Firefox");
  });

  it("names the varlatch CLI with its release version and platform", () => {
    expect(clientLabel("varlatch-cli/0.14.0 (linux; x64)")).toBe("varlatch CLI 0.14.0 on Linux");
    expect(clientLabel("varlatch-cli/0.14.0-rc.1 (darwin; arm64)")).toBe("varlatch CLI 0.14.0-rc.1 on macOS");
    expect(clientLabel("varlatch-cli/1.2.3 (win32; x64)")).toBe("varlatch CLI 1.2.3 on Windows");
    expect(clientLabel("varlatch-cli/1.2.3 (plan9; x64)")).toBe("varlatch CLI 1.2.3");
    expect(clientLabel("varlatch-cli/1.2.3")).toBe("varlatch CLI 1.2.3");
  });

  it("is null when the client is missing or not recognized", () => {
    for (const ua of [
      undefined,
      null,
      "",
      "node", // Node's fetch: any script, not necessarily the CLI
      "curl/8.9.1",
      "Mozilla/5.0",
      "Mozilla/5.0 (X11; Linux x86_64)",
      "varlatch-cli/latest (linux; x64)",
      "varlatch-cli/1.2.3-" + "a".repeat(21),
      "varlatch-cli/1.2.3<script> (linux; x64)",
      `${UA.firefoxLinux}${" ".repeat(1024)}`,
    ]) {
      expect(clientLabel(ua), String(ua)).toBeNull();
    }
  });

  it("never carries free text from the header, and stays short", () => {
    const hostile = [
      "Mozilla/5.0 (X11; Linux x86_64; jeremy@laptop.example) Firefox/131.0 <script>alert(1)</script>",
      "Firefox/131.0 (Windows NT 10.0; serial 1234-5678)",
      "varlatch-cli/9999.9999.9999-rc.abcdefghijklmnop (win32; x64) extra words here",
    ];
    const vocabulary = /^(?:varlatch CLI \d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?|[A-Za-z ]+)(?: on (?:Linux|macOS|Windows|iOS|Android|ChromeOS|FreeBSD|OpenBSD))?$/;
    for (const ua of [...hostile, ...Object.values(UA)]) {
      const label = clientLabel(ua);
      expect(label, ua).not.toBeNull();
      expect(label!.length, ua).toBeLessThanOrEqual(CLIENT_LABEL_MAX);
      expect(label, ua).toMatch(vocabulary);
      expect(label, ua).not.toMatch(/jeremy|script|serial|1234|extra|131/);
    }
  });
});

describe("credentials carry the label", () => {
  let ctx: AppCtx & { close: () => Promise<void> };
  let app: ReturnType<typeof buildApp>;
  let adminId: string;

  beforeEach(async () => {
    const db = await migratedTestDb();
    ctx = { db, rootKek: generateKey(), close: db.close };
    await ensureInstallation(ctx);
    const grant = await issueBootstrapGrant(ctx);
    adminId = (await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" })).identityId;
    // The session exchange needs human authentication; a stub session stands in for Better Auth.
    const humanAuth: HumanAuth = {
      handler: async () => new Response(null, { status: 404 }),
      identityForSession: async () => adminId,
    };
    app = buildApp(ctx, { humanAuth });
  });
  afterEach(async () => {
    await ctx.close();
  });

  async function browserSession(userAgent?: string): Promise<string> {
    const res = await app.request("/auth/varlatch-token", {
      method: "POST",
      headers: userAgent ? { "User-Agent": userAgent } : {},
    });
    expect(res.status).toBe(200);
    return ((await res.json()) as { token: string }).token;
  }

  async function cliLogin(bearer: string, userAgent?: string): Promise<string> {
    const res = await app.request("/v1/me/credentials/cli", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${bearer}`,
        "Content-Type": "application/json",
        ...(userAgent ? { "User-Agent": userAgent } : {}),
      },
      body: "{}",
    });
    expect(res.status).toBe(201);
    return ((await res.json()) as { token: string }).token;
  }

  async function myCredentials(token: string) {
    const res = await app.request("/v1/me/credentials", { headers: { Authorization: `Bearer ${token}` } });
    return ((await res.json()) as { items: { id: string; kind: string; client?: string | null; current: boolean }[] }).items;
  }

  it("labels a browser session from the browser, and the CLI login from the CLI", async () => {
    const bearer = await browserSession(UA.firefoxLinux);
    const cli = await cliLogin(bearer, "varlatch-cli/0.14.0 (linux; x64)");
    const items = await myCredentials(cli);
    expect(items.find((i) => i.kind === "browser")).toMatchObject({ client: "Firefox on Linux" });
    expect(items.find((i) => i.kind === "cli" && i.current)).toMatchObject({ client: "varlatch CLI 0.14.0 on Linux" });

    // Only the summary is stored: no trace of the header in credentials or audit.
    const rows = JSON.stringify([
      (await ctx.db.query("SELECT * FROM credentials")).rows,
      (await ctx.db.query("SELECT * FROM audit_events")).rows,
    ]);
    expect(rows).not.toMatch(/Gecko|rv:131|X11|x86_64|varlatch-cli\/|\(linux; x64\)/);
  });

  it("is null for an unrecognized or missing client and for every other kind", async () => {
    const bearer = await browserSession();
    const cli = await cliLogin(bearer, "node");
    expect((await myCredentials(cli)).map((i) => [i.kind, i.client])).toEqual([["cli", null], ["browser", null]]);

    // Machine credentials: the field is there, and null.
    const org = await app.request("/v1/organizations", {
      method: "POST",
      headers: { Authorization: `Bearer ${cli}`, "Content-Type": "application/json", "User-Agent": UA.chromeMac },
      body: JSON.stringify({ name: "Acme", slug: "acme" }),
    });
    expect(org.status).toBe(201);
    const svc = await app.request("/v1/organizations/acme/identities", {
      method: "POST",
      headers: { Authorization: `Bearer ${cli}`, "Content-Type": "application/json", "User-Agent": UA.chromeMac },
      body: JSON.stringify({ name: "runner", kind: "service" }),
    });
    const { id } = (await svc.json()) as { id: string };
    const listed = await app.request(`/v1/organizations/acme/identities/${id}/credentials`, {
      headers: { Authorization: `Bearer ${cli}` },
    });
    const creds = ((await listed.json()) as { items: { kind: string; client: string | null }[] }).items;
    expect(creds).toEqual([expect.objectContaining({ kind: "service", client: null })]);
    expect(Object.keys(creds[0]!)).toContain("client");

    // Credentials issued without a request (host-side bootstrap, tests) have none either.
    const direct = await issueCredential(ctx.db, { identityId: adminId, kind: "cli" });
    expect((await myCredentials(direct.token)).find((i) => i.current)).toMatchObject({ client: null });
  });

  it("refuses an oversized label at the database", async () => {
    await expect(
      issueCredential(ctx.db, { identityId: adminId, kind: "cli", client: "x".repeat(65) }),
    ).rejects.toThrow();
  });
});
