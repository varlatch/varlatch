// SPDX-License-Identifier: AGPL-3.0-or-later
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
// @ts-expect-error — plain ESM script shipped in the deploy image
import { parseEnvList, plan, readSecret } from "../scripts/reconcile.mjs";
// @ts-expect-error — plain ESM script shipped in the deploy image
import { fingerprint, stamp } from "../scripts/fingerprint.mjs";

const desired = {
  fingerprint: "a".repeat(64),
  env: { VARLATCH_ISSUER: "https://vault.example.com", VARLATCH_JWKS_URL: "http://varlatchd:8686/.well-known/jwks.json" },
};

describe("reconciliation plan (ADR-0035 D4)", () => {
  it("changes nothing when observed matches desired", () => {
    expect(plan({ fingerprint: desired.fingerprint, env: { ...desired.env, OTHER: "x" } }, desired))
      .toEqual({ setEnv: [], deploy: false, reasons: [] });
  });
  it("deploys when functions differ or report no fingerprint", () => {
    expect(plan({ fingerprint: "b".repeat(64), env: desired.env }, desired).deploy).toBe(true);
    const none = plan({ fingerprint: null, env: desired.env }, desired);
    expect(none).toMatchObject({ deploy: true, setEnv: [] });
    expect(none.reasons[0]).toContain("do not report");
  });
  it("sets only diverging trust variables and redeploys so auth.config picks them up", () => {
    const legacy = plan({ fingerprint: desired.fingerprint, env: { ...desired.env, VARLATCH_JWKS_URL: "http://tailscale:8686/.well-known/jwks.json" } }, desired);
    expect(legacy.setEnv).toEqual([["VARLATCH_JWKS_URL", desired.env.VARLATCH_JWKS_URL]]);
    expect(legacy.deploy).toBe(true);
  });
  it("never unsets trust variables it was not given", () => {
    expect(plan({ fingerprint: desired.fingerprint, env: desired.env }, { ...desired, env: {} }).deploy).toBe(false);
  });
  it("parses `convex env list` output", () => {
    expect(parseEnvList("VARLATCH_ISSUER=https://x\nVARLATCH_JWKS_URL=http://y/.well-known/jwks.json\n\nnoise line\n"))
      .toEqual({ VARLATCH_ISSUER: "https://x", VARLATCH_JWKS_URL: "http://y/.well-known/jwks.json" });
  });
});

describe("function fingerprint", () => {
  const repoRoot = join(__dirname, "..");
  it("is identical for the repository layout and the deploy-image layout", () => {
    const image = mkdtempSync(join(tmpdir(), "fp-image-"));
    cpSync(join(repoRoot, "package.json"), join(image, "package.json"));
    cpSync(join(repoRoot, "convex"), join(image, "convex"), { recursive: true });
    expect(fingerprint(image)).toBe(fingerprint(repoRoot));
  });
  it("ignores the stamp and generated code, and changes with any function source", () => {
    const copy = mkdtempSync(join(tmpdir(), "fp-copy-"));
    cpSync(join(repoRoot, "package.json"), join(copy, "package.json"));
    cpSync(join(repoRoot, "convex"), join(copy, "convex"), { recursive: true });
    const before = fingerprint(copy);
    expect(stamp(copy)).toBe(before);
    expect(readFileSync(join(copy, "convex/releaseStamp.ts"), "utf8")).toContain(before);
    writeFileSync(join(copy, "convex/_generated/extra.d.ts"), "// generated\n");
    expect(fingerprint(copy)).toBe(before);
    writeFileSync(join(copy, "convex/mirror.ts"), readFileSync(join(copy, "convex/mirror.ts"), "utf8") + "\n// changed\n");
    expect(fingerprint(copy)).not.toBe(before);
  });
});

describe("instance secret source (#28)", () => {
  const file = (content: string) => { const p = join(mkdtempSync(join(tmpdir(), "rs-")), "s"); writeFileSync(p, content); return p; };
  it("prefers a set variable, then a non-empty file", () => {
    expect(readSecret({ CONVEX_INSTANCE_SECRET: "env", CONVEX_INSTANCE_SECRET_FILE: file("file") })).toBe("env");
    expect(readSecret({ CONVEX_INSTANCE_SECRET: "", CONVEX_INSTANCE_SECRET_FILE: file("file\n") })).toBe("file");
  });
  it("treats an empty or missing file as unset", () => {
    expect(readSecret({ CONVEX_INSTANCE_SECRET_FILE: file("") })).toBe("");
    expect(readSecret({ CONVEX_INSTANCE_SECRET_FILE: "/nonexistent" })).toBe("");
    expect(readSecret({})).toBe("");
  });
});
