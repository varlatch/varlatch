// SPDX-License-Identifier: Apache-2.0
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { checkTailnetBrowser } from "../src/doctor.js";
import {
  composeFiles,
  CONFIG_FILE,
  endpointRule,
  renderEnv,
  requiredFiles,
  runSetup,
  tailnetUrl,
  usesTailscale,
  type InstallConfig,
} from "../src/setup.js";

/**
 * `varlatch setup --tailnet-endpoint` and the doctor's view of it (ADR-0046
 * Decision 9): setup writes the settings varlatchd, the dashboard and the
 * sidecar need, adds the sidecar where the ingress has none, prints the
 * access rule without editing the tailnet policy, and removes the settings
 * again with --no-tailnet-endpoint.
 */

const base: InstallConfig = { schemaVersion: 1, publicUrl: "https://vault.example.com", webPort: 8787, bindAddress: "127.0.0.1" };
const HOST = "vault.tail1.ts.net";
const line = (env: string, name: string) => env.match(new RegExp(`^${name}=(.*)$`, "m"))?.[1] ?? null;

describe("the managed .env with the tailnet browser endpoint", () => {
  it("writes nothing of it while it is off, as before", () => {
    const tailnet = renderEnv({ ...base, publicUrl: `https://${HOST}`, ingress: "tailnet", tailnetMachine: "vault", tailnetName: "tail1.ts.net", tailnetHost: HOST });
    for (const name of ["VARLATCH_TAILNET_HTTPS_PORT", "VARLATCH_TAILNET_NODE", "VARLATCH_TAILNET_ENDPOINT", "VARLATCH_TAILNET_CERT_UID"]) {
      expect(line(tailnet, name), name).toBeNull();
    }
    expect(line(renderEnv({ ...base }), "COMPOSE_FILE")).toBeNull();
  });

  it("with the tailnet ingress: the endpoint on the node's actual name, cert permission for varlatchd's uid", () => {
    const env = renderEnv({
      ...base,
      publicUrl: "https://vault-1.tail1.ts.net",
      ingress: "tailnet",
      tailnetMachine: "vault",
      tailnetName: "tail1.ts.net",
      tailnetHost: "vault-1.tail1.ts.net",
      tailnetEndpoint: { port: 8688 },
    });
    expect(line(env, "COMPOSE_FILE")).toBe("docker-compose.yml:docker-compose.tailscale.yml:docker-compose.tailnet-https.yml");
    expect(line(env, "VARLATCH_TAILNET_HTTPS_PORT")).toBe("8688");
    expect(line(env, "VARLATCH_TAILNET_NODE")).toBe("vault-1");
    expect(line(env, "VARLATCH_TAILNET_ENDPOINT")).toBe("https://vault-1.tail1.ts.net:8688");
    expect(line(env, "VARLATCH_TAILNET_CERT_UID")).toBe("999");
  });

  it("with the public or external ingress: adds the sidecar, keeps the public address", () => {
    for (const ingress of ["public", "external"] as const) {
      const config: InstallConfig = { ...base, ingress, tailnetMachine: "vault", tailnetName: "tail1.ts.net", tailnetHost: HOST, tailnetEndpoint: { port: 8688 } };
      expect(usesTailscale(config)).toBe(true);
      const env = renderEnv(config);
      expect(line(env, "VARLATCH_PUBLIC_URL")).toBe("https://vault.example.com");
      expect(line(env, "COMPOSE_FILE")).toBe(
        ingress === "public"
          ? "docker-compose.yml:docker-compose.caddy.yml:docker-compose.tailscale.yml"
          : "docker-compose.yml:docker-compose.tailscale.yml",
      );
      expect(line(env, "VARLATCH_TAILNET_MACHINE")).toBe("vault");
      expect(line(env, "TS_AUTHKEY_HOST_PATH")).toBe("./secrets/tailscale-authkey");
      expect(line(env, "VARLATCH_TAILNET_ENDPOINT")).toBe(`https://${HOST}:8688`);
      expect(requiredFiles(config)).toContain("docker-compose.tailscale.yml");
    }
    expect(composeFiles("external", true, true)).toEqual(["docker-compose.yml", "docker-compose.tailscale.yml", "docker-compose.override.yml"]);
  });

  it("waits for the node's name before it writes an endpoint", () => {
    const env = renderEnv({ ...base, ingress: "external", tailnetMachine: "vault", tailnetEndpoint: { port: 8688 } });
    expect(line(env, "VARLATCH_TAILNET_NAME")).toBe("pending.invalid");
    expect(line(env, "VARLATCH_TAILNET_HTTPS_PORT")).toBeNull();
  });

  it("needs HTTPS certificates for the sidecar only when the endpoint is on", () => {
    const joined = { BackendState: "Running", MagicDNSSuffix: "tail1.ts.net", CertDomains: null, Self: { DNSName: `${HOST}.` } };
    expect(() => tailnetUrl(joined)).toThrow(/enable HTTPS certificates/);
    expect(tailnetUrl(joined, { requireCertificates: false })).toEqual({ url: `https://${HOST}`, tailnet: "tail1.ts.net" });
  });

  it("prints a grant for the endpoint's port to the node's tag or address, never editing the policy", () => {
    const tagged = JSON.parse(endpointRule(`https://${HOST}:8688`, { Self: { Tags: ["tag:varlatch"], TailscaleIPs: ["100.64.0.9", "fd7a::9"] } }));
    expect(tagged).toEqual({ src: ["autogroup:member"], dst: ["tag:varlatch"], ip: ["tcp:8688"] });
    const untagged = JSON.parse(endpointRule(`https://${HOST}:8688`, { Self: { TailscaleIPs: ["fd7a::9", "100.64.0.9"] } }));
    expect(untagged.dst).toEqual(["100.64.0.9"]);
  });
});

describe("setup --tailnet-endpoint / --no-tailnet-endpoint", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
  });

  function installDir(config: InstallConfig, files: string[]): string {
    const dir = mkdtempSync(join(tmpdir(), "setup-endpoint-"));
    writeFileSync(join(dir, "docker-compose.yml"), "name: vltest\nservices: {}\n");
    for (const file of files) writeFileSync(join(dir, file), "");
    writeFileSync(join(dir, CONFIG_FILE), JSON.stringify(config));
    // Docker answers the version check and fails everything after it.
    const bin = mkdtempSync(join(tmpdir(), "setup-bin-"));
    writeFileSync(join(bin, "docker"), `#!/bin/sh\nif [ "$1" = compose ] && [ "$2" = version ]; then echo 2.30.0; exit 0; fi\nexit 1\n`, { mode: 0o755 });
    vi.stubEnv("PATH", `${bin}:${process.env.PATH}`);
    vi.spyOn(console, "log").mockImplementation(() => {});
    return dir;
  }
  const saved = (dir: string) => JSON.parse(readFileSync(join(dir, CONFIG_FILE), "utf8")) as InstallConfig;
  const options = (dir: string, tailnetEndpoint: boolean | undefined) => ({ dir, noWait: true, enrollTimeoutMs: 0, attest: false, tailnetEndpoint });

  it("turns it on: records it and the machine name, and asks for the sidecar's files with the external ingress", async () => {
    const dir = installDir({ ...base, ingress: "external" }, []);
    await expect(runSetup(options(dir, true))).rejects.toThrow(/needs docker-compose\.tailscale\.yml/);
    expect(saved(dir)).toMatchObject({ tailnetEndpoint: { port: 8688 }, tailnetMachine: "varlatch" });
  });

  it("turns it off: the settings go, the sidecar's machine stays", async () => {
    const dir = installDir({ ...base, ingress: "external", tailnetMachine: "vault", tailnetName: "tail1.ts.net", tailnetHost: HOST, tailnetEndpoint: { port: 8688 } }, [
      "docker-compose.tailscale.yml",
    ]);
    // Without Docker the sidecar cannot join; the configuration is already written.
    await expect(runSetup(options(dir, false))).rejects.toThrow();
    expect(saved(dir).tailnetEndpoint).toBeUndefined();
    expect(saved(dir).tailnetMachine).toBe("vault");
    const env = readFileSync(join(dir, ".env"), "utf8");
    expect(line(env, "VARLATCH_TAILNET_HTTPS_PORT")).toBeNull();
    expect(line(env, "VARLATCH_TAILNET_ENDPOINT")).toBeNull();
  });

  /** A Docker whose sidecar has joined as `dnsName`; everything after the join fails. */
  function joinedDocker(dnsName: string, extra: Record<string, unknown> = {}): void {
    const bin = mkdtempSync(join(tmpdir(), "setup-bin-"));
    const status = JSON.stringify({ BackendState: "Running", MagicDNSSuffix: "tail1.ts.net", CertDomains: [dnsName], Self: { DNSName: `${dnsName}.`, Tags: ["tag:varlatch"] }, ...extra });
    writeFileSync(
      join(bin, "docker"),
      [
        "#!/bin/sh",
        'case "$*" in',
        '  "compose version --short") echo 2.30.0; exit 0;;',
        '  "volume inspect "*_tailscale-state) exit 0;;',
        '  "compose up -d tailscale") exit 0;;',
        `  "compose exec -T tailscale tailscale status --json") echo '${status}'; exit 0;;`,
        "esac",
        "exit 1",
        "",
      ].join("\n"),
      { mode: 0o755 },
    );
    vi.stubEnv("PATH", `${bin}:${process.env.PATH}`);
  }

  it("with the external ingress: the sidecar joins, the public address stays, the node's actual name is recorded", async () => {
    const dir = installDir({ ...base, ingress: "external" }, ["docker-compose.tailscale.yml"]);
    joinedDocker("varlatch-1.tail1.ts.net");
    await expect(runSetup(options(dir, true))).rejects.toThrow(/up -d --remove-orphans failed/);
    expect(saved(dir)).toMatchObject({
      publicUrl: "https://vault.example.com",
      tailnetMachine: "varlatch",
      tailnetName: "tail1.ts.net",
      tailnetHost: "varlatch-1.tail1.ts.net",
      tailnetEndpoint: { port: 8688 },
    });
    const env = readFileSync(join(dir, ".env"), "utf8");
    expect(line(env, "VARLATCH_PUBLIC_URL")).toBe("https://vault.example.com");
    expect(line(env, "VARLATCH_TAILNET_NODE")).toBe("varlatch-1");
    expect(line(env, "VARLATCH_TAILNET_ENDPOINT")).toBe("https://varlatch-1.tail1.ts.net:8688");
  });

  it("stops when the sidecar's node was renamed since, and when the tailnet has no HTTPS certificates", async () => {
    const renamed = installDir({ ...base, ingress: "external", tailnetMachine: "varlatch", tailnetHost: "varlatch.tail1.ts.net", tailnetEndpoint: { port: 8688 } }, [
      "docker-compose.tailscale.yml",
    ]);
    joinedDocker("varlatch-2.tail1.ts.net");
    await expect(runSetup(options(renamed, undefined))).rejects.toThrow(/was varlatch\.tail1\.ts\.net, but it is now varlatch-2\.tail1\.ts\.net/);
    const noCerts = installDir({ ...base, ingress: "external" }, ["docker-compose.tailscale.yml"]);
    joinedDocker("varlatch.tail1.ts.net", { CertDomains: null });
    await expect(runSetup(options(noCerts, true))).rejects.toThrow(/enable HTTPS certificates/);
  });

  it("leaves the configuration alone without either flag", async () => {
    const config = { ...base, ingress: "external" as const };
    const dir = installDir(config, []);
    await expect(runSetup(options(dir, undefined))).rejects.toThrow();
    expect(saved(dir)).toEqual(config);
  });
});

describe("doctor: the endpoint from the host's side", () => {
  const endpoint = `https://${HOST}:8688`;
  const csp = (connect: string) => `add_header Content-Security-Policy "default-src 'none'; connect-src ${connect}; frame-ancestors 'none'" always;\n`;
  const serve = (extra: Record<string, unknown> = {}) => JSON.stringify({ TCP: { "443": { HTTPS: true }, ...extra }, Web: {} });

  it("passes when the dashboard allows the endpoint and nothing proxies its port", () => {
    expect(checkTailnetBrowser(endpoint, csp(`'self' https://${HOST} wss://${HOST} ${endpoint}`), endpoint, serve()).map((c) => [c.id, c.status])).toEqual([
      ["tailnet.browser-policy", "pass"],
      ["tailnet.browser-direct", "pass"],
    ]);
  });

  it("fails when the dashboard's security policy leaves the endpoint out", () => {
    const [policy] = checkTailnetBrowser(endpoint, csp(`'self' https://${HOST} wss://${HOST}`), null, serve());
    expect(policy).toMatchObject({ status: "fail", class: "advisory" });
    expect(policy!.remedy).toContain("--tailnet-endpoint");
  });

  it("fails, mandatory, when Tailscale Serve claims the endpoint's port", () => {
    const checks = checkTailnetBrowser(endpoint, csp(`'self' ${endpoint}`), endpoint, serve({ "8688": { TCPForward: "127.0.0.1:8687" } }));
    expect(checks[1]).toMatchObject({ id: "tailnet.browser-direct", status: "fail", class: "mandatory" });
    const web = checkTailnetBrowser(endpoint, csp(`'self' ${endpoint}`), endpoint, JSON.stringify({ Web: { [`${HOST}:8688`]: {} } }));
    expect(web[1]).toMatchObject({ status: "fail" });
  });

  it("is unknown when an older web image has no policy file, and flags a web setting varlatchd does not back", () => {
    expect(checkTailnetBrowser(endpoint, null, null, null)[0]).toMatchObject({ status: "unknown" });
    expect(checkTailnetBrowser(null, csp(`'self' ${endpoint}`), endpoint, null)).toEqual([
      expect.objectContaining({ id: "tailnet.browser-policy", status: "fail" }),
    ]);
    // A tailnet-ingress dashboard whose Convex origin is on ts.net is no finding.
    expect(checkTailnetBrowser(null, csp(`'self' https://${HOST} wss://${HOST}`), null, serve())).toEqual([]);
  });
});
