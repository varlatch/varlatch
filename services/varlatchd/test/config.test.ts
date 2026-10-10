// SPDX-License-Identifier: AGPL-3.0-or-later
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ConfigError, loadConfig, withPasswordFile } from "../src/config.js";

const base = { VARLATCH_DATABASE_URL: "postgres://x/varlatch" };

describe("loadConfig", () => {
  it("requires a KEK source", () => {
    expect(() => loadConfig({ ...base })).toThrow(ConfigError);
  });

  it("loads a hex KEK from a file", () => {
    const dir = mkdtempSync(join(tmpdir(), "varlatch-test-"));
    const path = join(dir, "kek");
    writeFileSync(path, "a".repeat(64) + "\n");
    const cfg = loadConfig({ ...base, VARLATCH_KEK_FILE: path });
    const kek = cfg.loadRootKek();
    expect(kek.length).toBe(32);
  });

  it("loads a base64 KEK from the environment fallback", () => {
    const cfg = loadConfig({
      ...base,
      VARLATCH_KEK: Buffer.alloc(32, 7).toString("base64"),
    });
    expect(cfg.loadRootKek().length).toBe(32);
  });

  it("rejects wrong-length key material", () => {
    const cfg = loadConfig({ ...base, VARLATCH_KEK: Buffer.alloc(16).toString("base64") });
    expect(() => cfg.loadRootKek()).toThrow(ConfigError);
  });

  it("rejects a missing KEK file at load time, not at parse time", () => {
    const cfg = loadConfig({ ...base, VARLATCH_KEK_FILE: "/nonexistent/kek" });
    expect(() => cfg.loadRootKek()).toThrow(ConfigError);
  });

  it("derives one token issuer from VARLATCH_PUBLIC_URL, with a localhost fallback (#110)", () => {
    const kek = { VARLATCH_KEK: Buffer.alloc(32).toString("base64") };
    expect(loadConfig({ ...base, ...kek, VARLATCH_PUBLIC_URL: "https://vault.example.com" }).issuer).toBe("https://vault.example.com");
    // Compose passes an unset optional variable as an empty string.
    expect(loadConfig({ ...base, ...kek, VARLATCH_PUBLIC_URL: "" }).issuer).toBe("http://localhost:8686");
    expect(loadConfig({ ...base, ...kek, VARLATCH_PORT: "9000" }).issuer).toBe("http://localhost:9000");
  });

  it("defaults the port and validates ranges", () => {
    const cfg = loadConfig({ ...base, VARLATCH_KEK: Buffer.alloc(32).toString("base64") });
    expect(cfg.port).toBe(8686);
    expect(() =>
      loadConfig({ ...base, VARLATCH_KEK: "x", VARLATCH_PORT: "70000" }),
    ).toThrow(ConfigError);
  });
});

describe("database password file (#28)", () => {
  const dir = mkdtempSync(join(tmpdir(), "varlatch-dbpw-"));
  const file = (name: string, content: string) => { const p = join(dir, name); writeFileSync(p, content); return p; };
  const bare = "postgres://varlatchd_runtime:@postgres:5432/varlatch";
  it("fills a password-less URL from a non-empty file, trailing newline stripped", () => {
    expect(withPasswordFile(bare, file("pw", "s3cret\n"))).toBe("postgres://varlatchd_runtime:s3cret@postgres:5432/varlatch");
  });
  it("lets a password already in the URL win (environment-based installations)", () => {
    const url = "postgres://varlatchd_runtime:from-env@postgres:5432/varlatch";
    expect(withPasswordFile(url, file("pw2", "from-file"))).toBe(url);
  });
  it("ignores unset, missing, and empty files (the /dev/null default)", () => {
    expect(withPasswordFile(bare, undefined)).toBe(bare);
    expect(withPasswordFile(bare, join(dir, "missing"))).toBe(bare);
    expect(withPasswordFile(bare, file("empty", ""))).toBe(bare);
    expect(withPasswordFile(bare, "/dev/null")).toBe(bare);
  });
  it("URL-encodes the password", () => {
    expect(withPasswordFile(bare, file("pw3", "a@b:c/d"))).toBe("postgres://varlatchd_runtime:a%40b%3Ac%2Fd@postgres:5432/varlatch");
  });
  it("is applied by loadConfig", () => {
    const cfg = loadConfig({ VARLATCH_DATABASE_URL: bare, VARLATCH_DATABASE_PASSWORD_FILE: file("pw4", "x"), VARLATCH_KEK: "a".repeat(64) });
    expect(cfg.databaseUrl).toBe("postgres://varlatchd_runtime:x@postgres:5432/varlatch");
  });
});

describe("tailnet browser endpoint (ADR-0046)", () => {
  const tailnet = {
    ...base,
    VARLATCH_KEK: "a".repeat(64),
    VARLATCH_PUBLIC_URL: "https://varlatch.example.com",
    VARLATCH_TAILSCALE_SOCKET: "/var/run/tailscale/tailscaled.sock",
    VARLATCH_TAILSCALE_TAILNET: "example.ts.net",
    VARLATCH_TAILNET_PORT: "8687",
  };
  const on = { ...tailnet, VARLATCH_TAILNET_HTTPS_PORT: "8688", VARLATCH_TAILNET_MACHINE: "varlatch" };

  it("is off unless its port is set, even with the other settings present", () => {
    expect(loadConfig(tailnet).tailscale?.browser).toBeNull();
    expect(
      loadConfig({ ...tailnet, VARLATCH_TAILNET_MACHINE: "varlatch", VARLATCH_TAILNET_BROWSER_ORIGINS: "https://a.example.com", VARLATCH_TAILNET_HTTPS_PORT: "" })
        .tailscale?.browser,
    ).toBeNull();
  });

  it("serves the node's name and, by default, exactly the dashboard's origin", () => {
    expect(loadConfig({ ...on, VARLATCH_TAILNET_MACHINE: "varlatch", VARLATCH_TAILSCALE_TAILNET: "Example.ts.net" }).tailscale?.browser).toEqual({
      host: "varlatch.example.ts.net",
      port: 8688,
      origins: ["https://varlatch.example.com"],
    });
    expect(loadConfig({ ...on, VARLATCH_PUBLIC_URL: "https://varlatch.example.com:8443/app/" }).tailscale?.browser?.origins).toEqual([
      "https://varlatch.example.com:8443",
    ]);
  });

  it("adds listed origins, each exactly an https origin", () => {
    const extra = (v: string) => loadConfig({ ...on, VARLATCH_TAILNET_BROWSER_ORIGINS: v }).tailscale?.browser?.origins;
    expect(extra(" https://varlatch.example.ts.net , http://localhost:5173")).toEqual([
      "https://varlatch.example.com",
      "https://varlatch.example.ts.net",
      "http://localhost:5173",
    ]);
    for (const bad of ["*", "null", "https://a.example.com/", "https://a.example.com/path", "http://a.example.com", "HTTPS://a.example.com", "a.example.com", "https://*.example.com"]) {
      expect(() => extra(bad), bad).toThrow(ConfigError);
    }
  });

  it("never allows a plain-http dashboard by default, and needs some origin", () => {
    const plain = { ...on, VARLATCH_PUBLIC_URL: "http://varlatch.internal:8080" };
    expect(() => loadConfig(plain)).toThrow(/needs a dashboard origin/);
    expect(loadConfig({ ...plain, VARLATCH_TAILNET_BROWSER_ORIGINS: "https://varlatch.example.ts.net" }).tailscale?.browser?.origins).toEqual([
      "https://varlatch.example.ts.net",
    ]);
    expect(() => loadConfig({ ...on, VARLATCH_PUBLIC_URL: "" })).toThrow(/needs a dashboard origin/);
  });

  it("needs the tailnet listener, a machine name, and a port of its own", () => {
    expect(() => loadConfig({ ...base, VARLATCH_KEK: "a".repeat(64), VARLATCH_TAILNET_HTTPS_PORT: "8688", VARLATCH_TAILNET_MACHINE: "varlatch" })).toThrow(
      /needs the tailnet listener/,
    );
    expect(() => loadConfig({ ...on, VARLATCH_TAILNET_MACHINE: "" })).toThrow(/VARLATCH_TAILNET_MACHINE/);
    for (const bad of ["Varlatch", "varlatch.example.ts.net", "-varlatch", "var latch"]) {
      expect(() => loadConfig({ ...on, VARLATCH_TAILNET_MACHINE: bad }), bad).toThrow(/VARLATCH_TAILNET_MACHINE/);
    }
    expect(() => loadConfig({ ...on, VARLATCH_TAILNET_HTTPS_PORT: "8687" })).toThrow(/must differ/);
    expect(() => loadConfig({ ...on, VARLATCH_TAILNET_HTTPS_PORT: "8686" })).toThrow(/must differ/);
  });

  it("is ignored by an entrypoint that serves no listener (migrate on Coolify)", () => {
    // What Coolify hands varlatch-migrate with the endpoint on: every variable of the
    // app, so the endpoint's port and origins, but none of the listener settings that
    // only varlatchd's own environment sets (2026-10-10 production incident).
    const migrate = {
      ...base,
      VARLATCH_PUBLIC_URL: "https://varlatch.example.com",
      VARLATCH_TAILNET_HTTPS_PORT: "8688",
      VARLATCH_TAILNET_BROWSER_ORIGINS: "https://a.example.com",
      VARLATCH_TAILNET_NODE: "varlatch",
    };
    expect(() => loadConfig(migrate, { requireKek: false })).toThrow(/needs the tailnet listener/);
    const cfg = loadConfig(migrate, { requireKek: false, listeners: false });
    expect(cfg.tailscale).toBeNull();
    expect(cfg.databaseUrl).toBe("postgres://x/varlatch");
    // A partial listener configuration is not migrate's concern either.
    expect(() => loadConfig({ ...migrate, VARLATCH_TAILNET_PORT: "8687" }, { requireKek: false })).toThrow(/Partial Tailscale/);
    expect(loadConfig({ ...migrate, VARLATCH_TAILNET_PORT: "8687" }, { requireKek: false, listeners: false }).tailscale).toBeNull();
  });

  it("is still checked by default, as varlatchd serve loads it", () => {
    expect(loadConfig(on).tailscale?.browser).toMatchObject({ host: "varlatch.example.ts.net", port: 8688 });
    expect(() => loadConfig({ ...on, VARLATCH_TAILSCALE_SOCKET: "" })).toThrow(/Partial Tailscale|needs the tailnet listener/);
  });
});
