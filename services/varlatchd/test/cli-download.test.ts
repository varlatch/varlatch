// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { generateKey } from "../src/crypto/aead.js";
import { ensureInstallation } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { buildApp } from "../src/http/app.js";
import { cliDownloadSetting, installPs1, installSh, type CliDownload } from "../src/http/cliDownload.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * The installation serves its CLI (ADR-0058 Decision 3): off unless
 * VARLATCH_SERVE_CLI=on, only for an https: or loopback http: address,
 * the address always from VARLATCH_PUBLIC_URL, and /v1/meta lists
 * cli.download exactly when the paths answer.
 */

const FILE = Buffer.from("console.log('varlatch 0.99.0 (migration 1)')\n");
const read = () => FILE;

describe("cliDownloadSetting", () => {
  const base = { publicUrl: "https://vault.example.com", version: "0.99.0", read };

  it("is off unless turned on", () => {
    expect(cliDownloadSetting({ ...base, serve: undefined })).toEqual({ serving: false, reason: "VARLATCH_SERVE_CLI is not on" });
    expect(cliDownloadSetting({ ...base, serve: "off" }).serving).toBe(false);
  });

  it("serves an https: address, with the file's SHA-256, the version, and the origin only", () => {
    const setting = cliDownloadSetting({ ...base, serve: "on", publicUrl: "https://vault.example.com/" });
    expect(setting).toEqual({
      serving: true,
      download: { file: FILE, sha256: createHash("sha256").update(FILE).digest("hex"), version: "0.99.0", origin: "https://vault.example.com", loopbackHttp: false },
    });
  });

  it("serves loopback http: for a local trial, and refuses any other http: address", () => {
    for (const url of ["http://localhost:8787", "http://127.0.0.1:8787", "http://[::1]:8787"]) {
      const setting = cliDownloadSetting({ ...base, serve: "on", publicUrl: url });
      expect(setting.serving && setting.download.loopbackHttp, url).toBe(true);
    }
    for (const url of ["http://vault.lan", "http://192.168.1.10:8787", "http://localhost.example.com"]) {
      const setting = cliDownloadSetting({ ...base, serve: "on", publicUrl: url });
      expect(setting.serving, url).toBe(false);
      if (!setting.serving) expect(setting.reason).toMatch(/neither https: nor http: on this machine/);
    }
  });

  it("is off, saying why, without an address or a readable file", () => {
    expect(cliDownloadSetting({ ...base, serve: "on", publicUrl: undefined })).toEqual({ serving: false, reason: "VARLATCH_PUBLIC_URL is not set" });
    const missing = cliDownloadSetting({ ...base, serve: "on", read: () => { throw new Error("ENOENT"); } });
    expect(missing).toEqual({ serving: false, reason: "the CLI file cannot be read (ENOENT)" });
  });
});

describe("the scripts", () => {
  const download: CliDownload = { file: FILE, sha256: "a".repeat(64), version: "0.99.0", origin: "https://vault.example.com", loopbackHttp: false };

  it("name the address, the version and the SHA-256, and restrict curl to https for redirects too", () => {
    const sh = installSh(download);
    expect(sh).toContain("ORIGIN='https://vault.example.com'");
    expect(sh).toContain("VERSION='0.99.0'");
    expect(sh).toContain(`SHA256='${"a".repeat(64)}'`);
    expect(sh).toContain("curl -q -sS --proto '=https' --tlsv1.2 -w '%{http_code}'");
    expect(sh).toContain('[ "$status" = 200 ]');
    expect(sh).not.toMatch(/curl[^\n]* -L/);
    expect(sh).toContain("Next: varlatch login --server $ORIGIN");
    expect(sh).not.toMatch(/sudo/);
    const local = installSh({ ...download, origin: "http://localhost:8787", loopbackHttp: true });
    expect(local).toContain("curl -q -sS --proto '=http' -w '%{http_code}'");
    const ps1 = installPs1(download);
    expect(ps1).toContain("$Origin = 'https://vault.example.com'");
    expect(ps1).toContain("-MaximumRedirection 0");
    // The user PATH is edited as stored (ADR-0058; see test-installers.mjs).
    expect(ps1).toContain("$Key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)");
    expect(ps1).not.toContain("SetEnvironmentVariable('Path'");
    expect(ps1).toContain("[Environment]::SetEnvironmentVariable($Refresh, [NullString]::Value, 'User')");
  });

  it("refuse a value that could break out of its quotes", () => {
    expect(() => installSh({ ...download, origin: "https://x.example'; rm -rf ~; '" })).toThrow(/refusing/);
    expect(() => installPs1({ ...download, version: "1$(whoami)" })).toThrow(/refusing/);
  });
});

describe("the routes", () => {
  let ctx: AppCtx;
  let close: () => Promise<void>;
  beforeEach(async () => {
    const db = await migratedTestDb();
    ctx = { db, rootKek: generateKey() };
    close = db.close;
    await ensureInstallation(ctx);
  });
  afterEach(async () => close());

  const capabilities = async (app: ReturnType<typeof buildApp>) => ((await (await app.request("/v1/meta")).json()) as { capabilities: string[] }).capabilities;

  it("answer 404 when off, and /v1/meta does not list cli.download", async () => {
    const app = buildApp(ctx);
    for (const path of ["/cli/varlatch.cjs", "/install.sh", "/install.ps1"]) {
      const res = await app.request(path);
      expect(res.status, path).toBe(404);
      expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    }
    expect(await capabilities(app)).not.toContain("cli.download");
  });

  it("serve the file and the scripts when on, whatever Host the request claims", async () => {
    const setting = cliDownloadSetting({ serve: "on", publicUrl: "https://vault.example.com", version: "0.99.0", read });
    if (!setting.serving) throw new Error(setting.reason);
    const app = buildApp(ctx, { cliDownload: setting.download });
    const file = await app.request("/cli/varlatch.cjs");
    expect(file.status).toBe(200);
    expect(Buffer.from(await file.arrayBuffer())).toEqual(FILE);
    expect(file.headers.get("content-type")).toBe("application/octet-stream");
    expect(file.headers.get("cache-control")).toBe("no-cache");
    const sh = await app.request("/install.sh", { headers: { Host: "evil.example", "X-Forwarded-Host": "evil.example" } });
    expect(sh.status).toBe(200);
    expect(sh.headers.get("content-type")).toBe("text/plain; charset=utf-8");
    const text = await sh.text();
    expect(text).toContain("ORIGIN='https://vault.example.com'");
    expect(text).toContain(`SHA256='${setting.download.sha256}'`);
    expect(text).not.toContain("evil.example");
    expect((await app.request("/install.ps1")).status).toBe(200);
    expect(await capabilities(app)).toContain("cli.download");
  });
});

describe("varlatch doctor's cli.download check", () => {
  it("reports off as a choice, on with the address, and on without serving as an advisory failure with the reason", async () => {
    const { checkCliDownload } = await import("../src/doctor.js");
    const off = checkCliDownload({ serve: "off", setting: cliDownloadSetting({ serve: "off", publicUrl: "https://v.example", version: "0.99.0", read }) });
    expect(off).toMatchObject({ id: "cli.download", class: "advisory", status: "pass" });
    expect(off.detail).toMatch(/^off/);
    const on = checkCliDownload({ serve: "on", setting: cliDownloadSetting({ serve: "on", publicUrl: "https://v.example", version: "0.99.0", read }) });
    expect(on).toMatchObject({ status: "pass", detail: "on: https://v.example/install.sh and /install.ps1 install CLI 0.99.0" });
    const broken = checkCliDownload({ serve: "on", setting: cliDownloadSetting({ serve: "on", publicUrl: "http://vault.lan", version: "0.99.0", read }) });
    expect(broken).toMatchObject({ status: "fail", class: "advisory" });
    expect(broken.detail).toMatch(/nothing is served: http:\/\/vault\.lan is neither https:/);
  });
});
