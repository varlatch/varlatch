// SPDX-License-Identifier: Apache-2.0
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { bootstrapAction, ensureSecrets, escrowComplete, parseEnrollLink, renderEnv, SECRET_FILES, SetupError, validatePublicUrl, validatePublicHost, composeFiles, tailnetUrl, TAILNET_MACHINE } from "../src/setup.js";

const config = { schemaVersion: 1 as const, publicUrl: "https://vault.example.com", webPort: 8787, bindAddress: "127.0.0.1" };

describe("validatePublicUrl", () => {
  it("accepts HTTPS origins and http://localhost", () => {
    expect(validatePublicUrl("https://vault.example.com/")).toBe("https://vault.example.com");
    expect(validatePublicUrl("http://localhost:8787")).toBe("http://localhost:8787");
  });
  it("rejects paths, plain HTTP on real hosts, and garbage", () => {
    expect(() => validatePublicUrl("https://example.com/varlatch")).toThrow(SetupError);
    expect(() => validatePublicUrl("http://vault.example.com")).toThrow(/HTTPS/);
    expect(() => validatePublicUrl("vault")).toThrow(SetupError);
  });
});

describe("renderEnv", () => {
  it("derives every origin from the public URL and carries paths, not secrets", () => {
    const env = renderEnv(config);
    expect(env).toContain("VARLATCH_PUBLIC_URL=https://vault.example.com\n");
    expect(env).toContain("CONVEX_CLOUD_ORIGIN=https://vault.example.com/convex\n");
    expect(env).toContain("CONVEX_INSTANCE_SECRET_HOST_PATH=./secrets/convex-instance-secret\n");
    expect(env).not.toMatch(/^(POSTGRES_SUPERUSER_PASSWORD|VARLATCH_RUNTIME_PASSWORD|CONVEX_INSTANCE_SECRET|CONVEX_ADMIN_KEY)=/m);
  });
  it("keeps the operator's additions below the marker", () => {
    expect(renderEnv(config, "VARLATCH_SYNC=off\n").endsWith("VARLATCH_SYNC=off\n")).toBe(true);
  });
});

describe("ensureSecrets", () => {
  it("creates missing secrets once and never rewrites them", () => {
    const dir = mkdtempSync(join(tmpdir(), "setup-"));
    expect(ensureSecrets(dir, { existingInstallation: false }).created).toHaveLength(SECRET_FILES.length);
    const kek = readFileSync(join(dir, "secrets/varlatch-kek"), "utf8");
    expect(kek).toMatch(/^[0-9a-f]{64}\n$/);
    expect(statSync(join(dir, "secrets")).mode & 0o777).toBe(0o700);
    expect(statSync(join(dir, "secrets/backup-key")).mode & 0o777).toBe(0o600);
    expect(ensureSecrets(dir, { existingInstallation: true }).created).toEqual([]);
    expect(readFileSync(join(dir, "secrets/varlatch-kek"), "utf8")).toBe(kek);
  });
  it("refuses to invent keys or passwords for an existing database", () => {
    const dir = mkdtempSync(join(tmpdir(), "setup-"));
    expect(() => ensureSecrets(dir, { existingInstallation: true })).toThrow(/never generates keys/);
  });
  it("generates nothing for an existing installation, not even a backup key", () => {
    const dir = mkdtempSync(join(tmpdir(), "setup-"));
    ensureSecrets(dir, { existingInstallation: false });
    rmSync(join(dir, "secrets/backup-key"));
    expect(ensureSecrets(dir, { existingInstallation: true }).created).toEqual([]);
  });
  it("uses an adopted installation's recorded secret paths", () => {
    const dir = mkdtempSync(join(tmpdir(), "setup-"));
    const elsewhere = mkdtempSync(join(tmpdir(), "setup-kek-"));
    ensureSecrets(dir, { existingInstallation: false });
    const kek = join(elsewhere, "varlatch-kek");
    writeFileSync(kek, "k\n");
    rmSync(join(dir, "secrets/varlatch-kek"));
    expect(() => ensureSecrets(dir, { existingInstallation: true })).toThrow(/missing/);
    expect(ensureSecrets(dir, { existingInstallation: true, paths: { VARLATCH_KEK_HOST_PATH: kek } }).created).toEqual([]);
    expect(renderEnv({ ...config, secretPaths: { VARLATCH_KEK_HOST_PATH: kek } })).toContain(`VARLATCH_KEK_HOST_PATH=${kek}\n`);
  });
});

describe("bootstrapAction", () => {
  const admin = (id: string, enabled: boolean, hasPasskey: boolean) => ({ id, enabled, hasPasskey });
  it("is done only when an enabled admin has a passkey", () => {
    expect(bootstrapAction({ initialized: true, bootstrapped: true, admins: [admin("idn_a", true, true)] })).toEqual({ kind: "done", adminId: "idn_a" });
    expect(bootstrapAction({ initialized: true, bootstrapped: true, admins: [admin("idn_a", false, true)] }).kind).not.toBe("done");
  });
  it("bootstraps a fresh installation", () => {
    expect(bootstrapAction({ initialized: false, bootstrapped: false, admins: [] })).toEqual({ kind: "bootstrap" });
  });
  it("recovers an admin whose enrollment never finished (or a headless bootstrap)", () => {
    expect(bootstrapAction({ initialized: true, bootstrapped: true, admins: [admin("idn_b", true, false)] })).toEqual({ kind: "recover", identityId: "idn_b" });
  });
  it("creates a new admin only when no enabled admin exists", () => {
    expect(bootstrapAction({ initialized: true, bootstrapped: true, admins: [admin("idn_c", false, false)] })).toEqual({ kind: "recover-new-admin" });
  });
});

describe("parseEnrollLink", () => {
  it("finds the link in bootstrap and recovery output", () => {
    expect(parseEnrollLink("Open this one-time enrollment URL...\n  https://vault.example.com/enroll#vlt_setup_abc\nExpires: x")).toBe("https://vault.example.com/enroll#vlt_setup_abc");
    expect(parseEnrollLink("Open this one-time recovery URL to enroll a new passkey:\n  http://localhost:8787/enroll#vlt_recover_x\n")).toBe("http://localhost:8787/enroll#vlt_recover_x");
    expect(parseEnrollLink("nothing here")).toBeNull();
  });
});

describe("escrowComplete", () => {
  const a = { method: "copy", at: "2026-09-24T00:00:00.000Z" };
  it("requires a current attestation for both recovery keys", () => {
    expect(escrowComplete({ rootKekVersion: 1, attestations: { "root-kek": a, "backup-key": a } })).toBe(true);
    expect(escrowComplete({ rootKekVersion: 1, attestations: { "root-kek": a, "backup-key": null } })).toBe(false);
    expect(escrowComplete({ rootKekVersion: 2, attestations: { "root-kek": null, "backup-key": a } })).toBe(false);
  });
});

describe("ingress (ADR-0035 D6, Q6)", () => {
  it("accepts only public DNS names for the public ingress", () => {
    expect(validatePublicHost("https://vault.example.com")).toBe("https://vault.example.com");
    for (const bad of ["http://vault.example.com", "https://vault.example.com:8443", "https://localhost", "https://10.0.0.5", "https://vault", "https://varlatch.tail1.ts.net"]) {
      expect(() => validatePublicHost(bad)).toThrow(SetupError);
    }
  });

  it("renders the Compose files and host for each ingress; external stays unchanged", () => {
    const external = renderEnv({ ...config });
    expect(external).not.toContain("COMPOSE_FILE");
    expect(renderEnv({ ...config, ingress: "external" })).toBe(external);
    const pub = renderEnv({ ...config, publicUrl: "https://vault.example.com", ingress: "public" });
    expect(pub).toContain("COMPOSE_FILE=docker-compose.yml:docker-compose.caddy.yml\n");
    expect(pub).toContain("VARLATCH_PUBLIC_HOST=vault.example.com\n");
    const tail = renderEnv({ ...config, publicUrl: "", ingress: "tailnet", tailnetMachine: "vault" });
    expect(tail).toContain("COMPOSE_FILE=docker-compose.yml:docker-compose.tailscale.yml:docker-compose.tailnet-https.yml\n");
    expect(tail).toContain("VARLATCH_TAILNET_MACHINE=vault\n");
    expect(tail).toContain("VARLATCH_TAILNET_NAME=pending.invalid\n");
    expect(tail).toContain("TS_AUTHKEY_HOST_PATH=./secrets/tailscale-authkey\n");
    expect(renderEnv({ ...config, publicUrl: "https://vault.tail1.ts.net", ingress: "tailnet", tailnetMachine: "vault", tailnetName: "tail1.ts.net" }))
      .toContain("VARLATCH_TAILNET_NAME=tail1.ts.net\n");
    expect(composeFiles("external")).toEqual(["docker-compose.yml"]);
  });

  it("reads the tailnet URL the node actually got, and requires HTTPS certificates", () => {
    const joined = { BackendState: "Running", MagicDNSSuffix: "tail1.ts.net", CertDomains: ["vault-1.tail1.ts.net"], Self: { DNSName: "vault-1.tail1.ts.net." } };
    expect(tailnetUrl(joined)).toEqual({ url: "https://vault-1.tail1.ts.net", tailnet: "tail1.ts.net" });
    expect(tailnetUrl({ ...joined, BackendState: "NeedsLogin" })).toBeNull();
    expect(tailnetUrl({ BackendState: "Running" })).toBeNull();
    expect(() => tailnetUrl({ ...joined, CertDomains: null })).toThrow(/enable HTTPS certificates/);
    expect(TAILNET_MACHINE.test("varlatch")).toBe(true);
    expect(TAILNET_MACHINE.test("Varlatch_1")).toBe(false);
  });
});

describe("shipped Compose files", () => {
  // Setup keeps passwords in secret files and leaves their variables unset on
  // purpose; a reference without a default makes Compose warn on every command.
  it("give every interpolated variable a default", () => {
    const dir = new URL("../../../infra/compose/", import.meta.url);
    const files = readdirSync(dir).filter((f) => f.endsWith(".yml"));
    expect(files).toContain("docker-compose.tailscale.yml");
    for (const file of files) {
      expect(readFileSync(new URL(file, dir), "utf8").match(/(?<!\$)\$\{[A-Za-z_][A-Za-z0-9_]*\}/g) ?? [], file).toEqual([]);
    }
  });
});
