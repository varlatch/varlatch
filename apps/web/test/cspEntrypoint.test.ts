// SPDX-License-Identifier: AGPL-3.0-or-later
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * The web container's entrypoint writes the runtime config and the
 * dashboard's Content-Security-Policy (ADR-0046 rollout step 4), from
 * values an operator sets: what it allows, and what it refuses to write.
 */

const SCRIPT = fileURLToPath(new URL("../docker-entrypoint.d/10-varlatch-config.sh", import.meta.url));

function run(env: Record<string, string>) {
  const dir = mkdtempSync(join(tmpdir(), "varlatch-web-"));
  const csp = join(dir, "nginx", "csp.conf");
  const result = spawnSync("sh", [SCRIPT], {
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin", VARLATCH_HTML_DIR: dir, VARLATCH_CSP_FILE: csp, ...env },
    encoding: "utf8",
  });
  const config = join(dir, "varlatch-config.js");
  return {
    status: result.status,
    stderr: result.stderr,
    conf: existsSync(csp) ? readFileSync(csp, "utf8") : null,
    config: existsSync(config) ? readFileSync(config, "utf8") : null,
  };
}

const policyOf = (conf: string | null) => /add_header Content-Security-Policy "([^"]*)" always;/.exec(conf ?? "")?.[1] ?? "";
const directive = (policy: string, name: string) => policy.split("; ").find((d) => d.startsWith(`${name} `));

describe("the dashboard's Content-Security-Policy", () => {
  it("allows scripts and styles from the dashboard only, nothing inline, no framing", () => {
    const { status, conf } = run({ CONVEX_URL: "https://varlatch.example.com/convex" });
    expect(status).toBe(0);
    const policy = policyOf(conf);
    expect(directive(policy, "default-src")).toBe("default-src 'none'");
    expect(directive(policy, "script-src")).toBe("script-src 'self'");
    expect(directive(policy, "style-src")).toBe("style-src 'self'");
    expect(directive(policy, "frame-ancestors")).toBe("frame-ancestors 'none'");
    expect(directive(policy, "base-uri")).toBe("base-uri 'none'");
    expect(directive(policy, "object-src")).toBe("object-src 'none'");
    expect(policy).not.toMatch(/unsafe-inline|unsafe-eval|\*/);
  });

  it("connects only to the dashboard, its Convex origin (HTTP and WebSocket), and the tailnet endpoint when set", () => {
    expect(directive(policyOf(run({ CONVEX_URL: "https://convex.example.com" }).conf), "connect-src")).toBe(
      "connect-src 'self' https://convex.example.com wss://convex.example.com",
    );
    const withEndpoint = run({ CONVEX_URL: "https://varlatch.example.com/convex", VARLATCH_TAILNET_ENDPOINT: "https://varlatch.example.ts.net:8688" });
    expect(directive(policyOf(withEndpoint.conf), "connect-src")).toBe(
      "connect-src 'self' https://varlatch.example.com wss://varlatch.example.com https://varlatch.example.ts.net:8688",
    );
    // No Convex origin configured: the dashboard's local development fallback.
    expect(directive(policyOf(run({}).conf), "connect-src")).toBe("connect-src 'self' http://localhost:3210 ws://localhost:3210");
  });

  it("still writes the runtime config the dashboard reads", () => {
    expect(run({ CONVEX_URL: "https://varlatch.example.com/convex" }).config).toBe('window.__VARLATCH__ = { convexUrl: "https://varlatch.example.com/convex" };\n');
    expect(run({}).config).toBeNull();
  });

  it("refuses values that could leave the policy or the script, and writes nothing then", () => {
    for (const bad of [
      'https://x.example.com"; script-src *',
      "https://x.example.com; script-src *",
      "https://x.example.com $host",
      "https://x.example.com\nadd_header X 1",
      "javascript:alert(1)",
      "https://x.example.com/`id`",
    ]) {
      const result = run({ CONVEX_URL: bad });
      expect(result.status, bad).not.toBe(0);
      expect(result.conf, bad).toBeNull();
      expect(result.config, bad).toBeNull();
    }
    for (const bad of [
      "http://varlatch.example.ts.net:8688",
      "https://varlatch.example.ts.net:8688/",
      "https://*.example.ts.net",
      "https://varlatch.example.ts.net:8688 https://evil.example.com",
      "https://varlatch.example.ts.net:8688\nhttps://evil.example.com",
      "https://Varlatch.example.ts.net:8688",
    ]) {
      const result = run({ CONVEX_URL: "https://varlatch.example.com/convex", VARLATCH_TAILNET_ENDPOINT: bad });
      expect(result.status, bad).not.toBe(0);
      expect(result.stderr, bad).toContain("VARLATCH_TAILNET_ENDPOINT");
      expect(result.conf, bad).toBeNull();
    }
  });
});
