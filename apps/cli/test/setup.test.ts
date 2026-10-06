// SPDX-License-Identifier: Apache-2.0
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  bootstrapAction, checkComposeOverride, COMPOSE_OVERRIDE, composeFileSetting, ensureSecrets, escrowComplete, parseEnrollLink, renderEnv,
  requireComposeVersion, runSetup, SECRET_FILES, SetupError, validatePublicUrl, validatePublicHost, composeFiles, tailnetUrl, TAILNET_MACHINE,
} from "../src/setup.js";

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

describe("Docker Compose floor (2.24, every ingress)", () => {
  it("accepts 2.24.0 and newer and returns the version it found", () => {
    expect(requireComposeVersion("2.24.0")).toBe("2.24.0");
    expect(requireComposeVersion("v2.29.7")).toBe("2.29.7");
    expect(requireComposeVersion("2.29.7-desktop.1")).toBe("2.29.7");
    expect(requireComposeVersion("5.5.1")).toBe("5.5.1");
  });
  it("refuses older, missing, or unreadable Compose, naming what it found and what it needs", () => {
    expect(() => requireComposeVersion("2.23.3")).toThrow(SetupError);
    expect(() => requireComposeVersion("2.23.3")).toThrow(
      "Setup needs Docker Compose 2.24 or newer: found 2.23.3. Nothing was changed. Update Docker Compose to 2.24 or newer, then run `varlatch setup` again.",
    );
    expect(() => requireComposeVersion("v2.9.0")).toThrow(/found 2\.9\.0/);
    expect(() => requireComposeVersion(null)).toThrow(/Setup needs Docker Compose 2\.24 or newer: .*Compose plugin is missing\. Nothing was changed\. Install Docker/);
    expect(() => requireComposeVersion("dev")).toThrow(/found "dev", not a version number/);
  });
});

// runSetup against a stand-in `docker` on PATH: it answers `compose version`
// as told and fails every other command, so a run stops at its first real
// Docker step (`docker compose up`) with everything before it in place.
describe("runSetup preflight and COMPOSE_FILE", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
  });

  function useDocker(version: string | null): string {
    const bin = mkdtempSync(join(tmpdir(), "setup-bin-"));
    const calls = join(bin, "calls.log");
    const answer = version === null ? `echo "docker: 'compose' is not a docker command." >&2; exit 1` : `echo "${version}"; exit 0`;
    writeFileSync(join(bin, "docker"), `#!/bin/sh\necho "$*" >> "${calls}"\nif [ "$1" = compose ] && [ "$2" = version ]; then ${answer}; fi\nexit 1\n`, { mode: 0o755 });
    vi.stubEnv("PATH", `${bin}:${process.env.PATH}`);
    return calls;
  }
  function installDir(extra: string[] = []): string {
    const dir = mkdtempSync(join(tmpdir(), "setup-run-"));
    writeFileSync(join(dir, "docker-compose.yml"), "name: vltest\nservices: {}\n");
    for (const file of ["docker-compose.caddy.yml", "Caddyfile", ...extra]) writeFileSync(join(dir, file), "");
    return dir;
  }
  const options = (dir: string, ingress: "public" | "external" = "public") =>
    ({ dir, ingress, publicUrl: "https://vault.example.com", noWait: true, enrollTimeoutMs: 0, attest: false });
  const composeFileLine = (dir: string) => readFileSync(join(dir, ".env"), "utf8").match(/^COMPOSE_FILE=.*$/m)?.[0] ?? null;
  const quiet = () => vi.spyOn(console, "log").mockImplementation(() => {});

  it("refuses Compose 2.23 before it changes anything", async () => {
    quiet();
    const calls = useDocker("2.23.3");
    const dir = installDir();
    const before = readdirSync(dir).sort();
    await expect(runSetup(options(dir))).rejects.toThrow(/^Setup needs Docker Compose 2\.24 or newer: found 2\.23\.3\. Nothing was changed\./);
    expect(readdirSync(dir).sort()).toEqual(before);
    expect(readFileSync(calls, "utf8")).toBe("compose version --short\n");
  });

  it("refuses a Docker without the Compose plugin, and no Docker at all, the same way", async () => {
    quiet();
    const dir = installDir();
    const before = readdirSync(dir).sort();
    useDocker(null);
    await expect(runSetup(options(dir))).rejects.toThrow(/Compose plugin is missing\. Nothing was changed\./);
    vi.stubEnv("PATH", mkdtempSync(join(tmpdir(), "setup-empty-path-")));
    await expect(runSetup(options(dir))).rejects.toThrow(/Compose plugin is missing\. Nothing was changed\./);
    expect(readdirSync(dir).sort()).toEqual(before);
  });

  it("refuses an unreadable version instead of guessing", async () => {
    quiet();
    useDocker("dev");
    const dir = installDir();
    await expect(runSetup(options(dir))).rejects.toThrow(/found "dev", not a version number\. Nothing was changed\./);
    expect(readdirSync(dir)).not.toContain(".env");
  });

  it("starts with 2.24.0, and lists docker-compose.override.yml last only while it exists", async () => {
    const log = quiet();
    useDocker("2.24.0");
    const dir = installDir();
    await expect(runSetup(options(dir))).rejects.toThrow(/docker compose up -d --remove-orphans failed/);
    expect(log).toHaveBeenCalledWith("  ✓ Docker Compose 2.24.0");
    expect(composeFileLine(dir)).toBe("COMPOSE_FILE=docker-compose.yml:docker-compose.caddy.yml");
    // The documented step: create the file, then run setup again.
    writeFileSync(join(dir, COMPOSE_OVERRIDE), "services: {}\n");
    expect(checkComposeOverride(dir, {})).toMatchObject({ status: "fail" });
    await expect(runSetup(options(dir))).rejects.toThrow(/up -d --remove-orphans failed/);
    expect(composeFileLine(dir)).toBe("COMPOSE_FILE=docker-compose.yml:docker-compose.caddy.yml:docker-compose.override.yml");
    expect(log).toHaveBeenCalledWith("  ✓ docker-compose.override.yml applies (last in COMPOSE_FILE)");
    expect(checkComposeOverride(dir, {})).toMatchObject({ status: "pass" });
    // Deleted again: the rerun drops it, since Compose refuses a listed file that is missing.
    rmSync(join(dir, COMPOSE_OVERRIDE));
    await expect(runSetup(options(dir))).rejects.toThrow(/up -d --remove-orphans failed/);
    expect(composeFileLine(dir)).toBe("COMPOSE_FILE=docker-compose.yml:docker-compose.caddy.yml");
  });

  it("starts with Compose 5.x and leaves COMPOSE_FILE unset for the external ingress, where Compose reads the override itself", async () => {
    const log = quiet();
    useDocker("5.5.1");
    const dir = installDir([COMPOSE_OVERRIDE]);
    await expect(runSetup(options(dir, "external"))).rejects.toThrow(/up -d --remove-orphans failed/);
    expect(log).toHaveBeenCalledWith("  ✓ Docker Compose 5.5.1");
    expect(composeFileLine(dir)).toBeNull();
    expect(log).toHaveBeenCalledWith("  ✓ docker-compose.override.yml applies");
    expect(checkComposeOverride(dir, {})).toMatchObject({ status: "pass", detail: "COMPOSE_FILE is not set, so Compose reads it" });
  });
});

describe("docker-compose.override.yml", () => {
  const publicConfig = { ...config, ingress: "public" as const };
  const tailnetConfig = { ...config, publicUrl: "https://vault.tail1.ts.net", ingress: "tailnet" as const, tailnetMachine: "vault", tailnetName: "tail1.ts.net" };
  const dirWith = (files: Record<string, string>) => {
    const dir = mkdtempSync(join(tmpdir(), "setup-override-"));
    for (const [file, text] of Object.entries(files)) writeFileSync(join(dir, file), text);
    return dir;
  };

  it("comes last in COMPOSE_FILE for the public and tailnet ingress when it exists", () => {
    expect(composeFiles("public", true)).toEqual(["docker-compose.yml", "docker-compose.caddy.yml", COMPOSE_OVERRIDE]);
    expect(composeFiles("tailnet", true).at(-1)).toBe(COMPOSE_OVERRIDE);
    expect(renderEnv(publicConfig, "", { override: true })).toContain("COMPOSE_FILE=docker-compose.yml:docker-compose.caddy.yml:docker-compose.override.yml\n");
    expect(renderEnv(tailnetConfig, "", { override: true }))
      .toContain("COMPOSE_FILE=docker-compose.yml:docker-compose.tailscale.yml:docker-compose.tailnet-https.yml:docker-compose.override.yml\n");
    expect(renderEnv(publicConfig, "", { override: false })).toBe(renderEnv(publicConfig));
    // External: no COMPOSE_FILE, so Compose reads the file by itself.
    expect(renderEnv(config, "", { override: true })).toBe(renderEnv(config));
  });

  it("reads COMPOSE_FILE the way Compose does", () => {
    expect(composeFileSetting(dirWith({}), {})).toBeNull();
    // Last line wins; export, quotes, and comments as in a dotenv file.
    const dir = dirWith({ ".env": 'COMPOSE_FILE=a.yml\nexport COMPOSE_FILE="docker-compose.yml:b.yml" # mine\n' });
    expect(composeFileSetting(dir, {})).toEqual({ files: ["docker-compose.yml", "b.yml"], source: ".env", setupLine: false, replacesSetup: false });
    expect(composeFileSetting(relative(process.cwd(), dir), {})?.source).toBe(".env");
    // The environment wins over .env, with its own separator.
    expect(composeFileSetting(dir, { COMPOSE_FILE: "x.yml;y.yml", COMPOSE_PATH_SEPARATOR: ";" }))
      .toEqual({ files: ["x.yml", "y.yml"], source: "the environment", setupLine: false, replacesSetup: false });
    // COMPOSE_ENV_FILES replaces .env, and may set the separator itself.
    const other = dirWith({ ".env": "COMPOSE_FILE=ignored.yml\n", "other.env": "COMPOSE_PATH_SEPARATOR=;\nCOMPOSE_FILE=a.yml;b.yml\n" });
    expect(composeFileSetting(other, { COMPOSE_ENV_FILES: "other.env" })).toMatchObject({ files: ["a.yml", "b.yml"], source: join(other, "other.env") });
  });

  it("tells setup's own COMPOSE_FILE from one an operator added below the keep marker", () => {
    expect(composeFileSetting(dirWith({ ".env": renderEnv(publicConfig) }), {})).toMatchObject({ setupLine: true, replacesSetup: false });
    expect(composeFileSetting(dirWith({ ".env": renderEnv(publicConfig, "COMPOSE_FILE=docker-compose.yml\n") }), {}))
      .toMatchObject({ files: ["docker-compose.yml"], setupLine: false, replacesSetup: true });
    // The only COMPOSE_FILE (external ingress): the operator's own list, replacing nothing.
    expect(composeFileSetting(dirWith({ ".env": renderEnv(config, "COMPOSE_FILE=docker-compose.yml:mine.yml\n") }), {}))
      .toMatchObject({ setupLine: false, replacesSetup: false });
  });

  it("is a doctor finding only where the file exists, and passes where Compose reads it", () => {
    expect(checkComposeOverride(dirWith({ ".env": renderEnv(publicConfig) }), {})).toBeNull();
    expect(checkComposeOverride(dirWith({ [COMPOSE_OVERRIDE]: "" }), {})).toMatchObject({ id: "compose.override", status: "pass", class: "advisory" });
    expect(checkComposeOverride(dirWith({ [COMPOSE_OVERRIDE]: "", ".env": renderEnv(publicConfig, "", { override: true }) }), {}))
      .toMatchObject({ status: "pass", detail: "listed in COMPOSE_FILE (.env)" });
    const dir = dirWith({ [COMPOSE_OVERRIDE]: "" });
    expect(checkComposeOverride(dir, { COMPOSE_FILE: `docker-compose.yml:${join(dir, COMPOSE_OVERRIDE)}` })).toMatchObject({ status: "pass" });
  });

  it("warns, advisory, when COMPOSE_FILE leaves it out, with the remedy that fits where COMPOSE_FILE comes from", () => {
    const warn = (files: Record<string, string>, env: NodeJS.ProcessEnv = {}) => {
      const check = checkComposeOverride(dirWith({ [COMPOSE_OVERRIDE]: "", ...files }), env);
      expect(check).toMatchObject({ id: "compose.override", status: "fail", class: "advisory" });
      return check!;
    };
    const managed = warn({ ".env": renderEnv(publicConfig) });
    expect(managed.detail).toBe("COMPOSE_FILE (.env) lists docker-compose.yml, docker-compose.caddy.yml, so Compose does not read docker-compose.override.yml");
    expect(managed.remedy).toBe("Run `varlatch setup` again: it lists docker-compose.override.yml last in COMPOSE_FILE");
    // Never advise writing a COMPOSE_FILE below the marker: one there pins its list across upgrades.
    expect(warn({ ".env": renderEnv(publicConfig, "COMPOSE_FILE=docker-compose.yml:docker-compose.caddy.yml\n") }).remedy)
      .toBe("Remove the COMPOSE_FILE line below the keep marker in .env, which replaces the one setup writes, then run `varlatch setup` again");
    expect(warn({ ".env": "POSTGRES_PASSWORD=x\nCOMPOSE_FILE=docker-compose.yml:docker-compose.tailscale.yml\n" }).remedy)
      .toBe("List docker-compose.override.yml last in COMPOSE_FILE (.env)");
    expect(warn({}, { COMPOSE_FILE: "docker-compose.yml" }).remedy).toBe("List docker-compose.override.yml last in COMPOSE_FILE (the environment)");
  });

  it("is unknown, not passed, when the env file cannot be read", () => {
    const dir = dirWith({ [COMPOSE_OVERRIDE]: "" });
    mkdirSync(join(dir, ".env"));
    expect(checkComposeOverride(dir, {})).toMatchObject({ status: "unknown", class: "advisory" });
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
