// SPDX-License-Identifier: Apache-2.0
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CANONICAL_JWKS, checkAdoption, differingPaths, editEnv, plan, SECRETS, type Observed } from "../src/adopt.js";
import { renderEnv } from "../src/setup.js";

const spec = (variable: string) => SECRETS.find((s) => s.variable === variable)!;
const legacy: Observed = {
  platform: "compose", publicUrl: "https://vault.example.com", convexOrigin: "https://convex.example.com",
  webPort: 8787, bindAddress: "127.0.0.1",
  variables: [{ spec: spec("VARLATCH_RUNTIME_PASSWORD"), value: "x" }, { spec: spec("CONVEX_INSTANCE_SECRET"), value: "y" }],
  mounted: [], jwksUrl: "http://tailscale:8686/.well-known/jwks.json", adminKeyProvided: true,
  instanceSecretAvailable: true, custodyComplete: false, configRecorded: false, managedEnv: false,
};
const status = (o: Observed) => Object.fromEntries(plan(o).map((s) => [s.id, s.status]));

describe("adopt plan (ADR-0035 D13)", () => {
  it("lays out every step for a hand-configured installation, in order", () => {
    expect(plan(legacy).map((s) => s.id)).toEqual(["config", "secret-files", "remove-variables", "trust", "deploy-authority", "custody", "managed-env"]);
    expect(status(legacy)).toEqual({
      config: "pending", "secret-files": "pending", "remove-variables": "blocked", trust: "pending",
      "deploy-authority": "pending", custody: "pending", "managed-env": "blocked",
    });
  });
  it("keeps a separate Convex origin (ingress is a separate migration)", () => {
    expect(plan(legacy)[0]!.summary).toContain("Convex origin https://convex.example.com kept");
  });
  it("removes variables only once their files are mounted", () => {
    const mounted = { ...legacy, mounted: ["varlatch-runtime-password", "convex-instance-secret"] };
    expect(status(mounted)["secret-files"]).toBe("done");
    expect(status(mounted)["remove-variables"]).toBe("pending");
  });
  it("blocks dropping CONVEX_ADMIN_KEY while the deploy job has no instance secret", () => {
    const s = plan({ ...legacy, instanceSecretAvailable: false }).find((x) => x.id === "deploy-authority")!;
    expect(s).toMatchObject({ status: "blocked" });
  });
  it("treats Coolify's env settings as the source of truth", () => {
    const c = status({ ...legacy, platform: "coolify" });
    expect(c.config).toBe("n/a");
    expect(c["managed-env"]).toBe("n/a");
  });
  it("is complete for a managed installation", () => {
    const adopted: Observed = { ...legacy, variables: [], mounted: ["varlatch-runtime-password"], jwksUrl: CANONICAL_JWKS,
      adminKeyProvided: false, custodyComplete: true, configRecorded: true, managedEnv: true };
    expect(plan(adopted).every((s) => s.status === "done")).toBe(true);
  });
  it("marks the trust step forward-only", () => {
    expect(plan(legacy).find((s) => s.id === "trust")!.reversibility).toMatch(/forward only/);
  });
});

describe("editEnv", () => {
  const text = "# comment\nA=1\nB=2\n\nC=3\n";
  it("replaces, removes, and appends while keeping other lines and order", () => {
    expect(editEnv(text, { B: "20", C: null, D: "4" })).toBe("# comment\nA=1\nB=20\nD=4\n");
  });
  it("collapses duplicate definitions of an edited key", () => {
    expect(editEnv("A=1\nA=2\n", { A: "3" })).toBe("A=3\n");
  });
  it("leaves untouched text byte-identical", () => {
    expect(editEnv(text, {})).toBe(text);
  });
});

describe("differingPaths", () => {
  it("names paths, never values", () => {
    expect(differingPaths({ a: { b: "secret1", c: 1 } }, { a: { b: "secret2", c: 1 } })).toEqual(["a.b"]);
    expect(differingPaths({ x: 1 }, { x: 1 })).toEqual([]);
  });
});

describe("renderEnv for adopted installations", () => {
  const base = { schemaVersion: 1 as const, publicUrl: "https://vault.example.com", webPort: 8787, bindAddress: "127.0.0.1" };
  it("keeps a separate Convex origin and leaves its port lines to the operator", () => {
    const env = renderEnv({ ...base, convexOrigin: "https://convex.example.com" });
    expect(env).toContain("CONVEX_CLOUD_ORIGIN=https://convex.example.com\n");
    expect(env).not.toMatch(/^CONVEX_PORT=/m);
  });
  it("unpublishes internal ports for one-origin installations", () => {
    expect(renderEnv(base)).toMatch(/^CONVEX_PORT=0$/m);
  });
});

describe("checkAdoption (doctor's advisory finding)", () => {
  const dir = mkdtempSync(join(tmpdir(), "adopt-check-"));
  const cfg = (varlatchd: Record<string, string>, deploy: Record<string, string>) => ({
    services: {
      varlatchd: { environment: { VARLATCH_PUBLIC_URL: "https://vault.example.com", ...varlatchd } },
      "varlatch-web": { environment: { CONVEX_URL: "https://vault.example.com/convex" } },
      "convex-deploy": { environment: { VARLATCH_JWKS_URL: CANONICAL_JWKS, ...deploy } },
      postgres: { environment: {} },
      "convex-backend": { environment: {} },
    },
  });
  it("is unknown without a resolved configuration", () => {
    expect(checkAdoption(null, dir)).toMatchObject({ status: "unknown", class: "advisory" });
  });
  it("names the open steps of a hand-configured Coolify installation, never a value", () => {
    const c = cfg({ COOLIFY_RESOURCE_UUID: "x" }, { CONVEX_SELF_HOSTED_ADMIN_KEY: "admin-key-value", CONVEX_INSTANCE_SECRET: "instance-value" });
    c.services.postgres.environment = { POSTGRES_PASSWORD: "pg-value" } as Record<string, string>;
    const check = checkAdoption(c, dir);
    expect(check).toMatchObject({ status: "fail", class: "advisory" });
    expect(check.detail).toBe("not adopted: secret-files, remove-variables, deploy-authority open");
    expect(JSON.stringify(check)).not.toMatch(/value/);
  });
  it("passes once a Coolify installation holds no secret variable", () => {
    expect(checkAdoption(cfg({ COOLIFY_RESOURCE_UUID: "x" }, {}), dir)).toMatchObject({ status: "pass" });
  });
});
