// SPDX-License-Identifier: Apache-2.0
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  checkCliVersion,
  checkRelease,
  checkServices,
  checkSupervisor,
  evaluateGate,
  formatGate,
  checkWebConfig,
  doctorExitCode,
  formatDoctor,
  parseComposePs,
  runDoctor,
  type Runner,
  type ServiceState,
} from "../src/doctor.js";

const healthy: ServiceState[] = [
  { Service: "postgres", State: "running", Health: "healthy", Image: "postgres:17.6" },
  { Service: "varlatchd", State: "running", Health: "healthy", Image: "ghcr.io/x/varlatchd@sha256:aaa" },
  { Service: "varlatch-web", State: "running", Health: "healthy", Image: "ghcr.io/x/varlatch-web@sha256:bbb" },
  { Service: "convex-backend", State: "running", Health: "healthy", Image: "ghcr.io/get-convex/convex-backend@sha256:ccc" },
  { Service: "varlatch-migrate", State: "exited", ExitCode: 0, Image: "ghcr.io/x/varlatchd@sha256:aaa" },
];
const facts = {
  serverVersion: "0.9.0", releaseVersion: "0.9.0", migrationVersion: 19,
  publicUrl: "https://vault.example.com", convexConfigured: true, installationId: "ins_1",
};
const manifest = {
  schemaVersion: 1, version: "0.9.0", apiMajor: 1,
  images: {
    varlatchd: { tag: "ghcr.io/x/varlatchd:0.9.0", digest: "ghcr.io/x/varlatchd@sha256:aaa" },
    "varlatch-web": { tag: null, digest: "ghcr.io/x/varlatch-web@sha256:bbb" },
    "convex-backend": { tag: null, digest: "ghcr.io/get-convex/convex-backend@sha256:ccc" },
    postgres: { tag: "docker.io/library/postgres:17.6", digest: null },
  },
};

describe("parseComposePs", () => {
  it("accepts both the JSON-array and NDJSON output of docker compose ps", () => {
    const rows = [{ Service: "a", State: "running" }, { Service: "b", State: "exited", ExitCode: 1 }];
    expect(parseComposePs(JSON.stringify(rows))).toEqual(rows);
    expect(parseComposePs(rows.map((r) => JSON.stringify(r)).join("\n"))).toEqual(rows);
    expect(parseComposePs("")).toEqual([]);
  });
});

describe("checkServices", () => {
  it("passes a healthy canonical stack", () => {
    expect(checkServices(healthy)).toMatchObject([{ id: "services.running", status: "pass" }]);
  });
  it("fails on missing, stopped, unhealthy, or failed-migration services", () => {
    const broken = healthy
      .filter((s) => s.Service !== "convex-backend")
      .map((s) => (s.Service === "varlatch-web" ? { ...s, Health: "unhealthy" } : s.Service === "varlatch-migrate" ? { ...s, ExitCode: 1 } : s));
    const [check] = checkServices(broken);
    expect(check).toMatchObject({ status: "fail", class: "mandatory" });
    expect(check!.detail).toContain("convex-backend: not created");
    expect(check!.detail).toContain("varlatch-web: unhealthy");
    expect(check!.detail).toContain("varlatch-migrate: exited 1");
  });
  it("reports a failed Application Plane deploy job", () => {
    const checks = checkServices([...healthy, { Service: "convex-deploy", State: "exited", ExitCode: 2 }]);
    expect(checks[1]).toMatchObject({ id: "application-plane.deploy", status: "fail", class: "mandatory" });
  });
});

describe("checkRelease", () => {
  it("is unknown, not failed, without a release manifest", () => {
    const checks = checkRelease(null, null, healthy, facts);
    expect(checks.find((c) => c.id === "release.consistency")).toMatchObject({ status: "unknown", class: "mandatory" });
    expect(checks.find((c) => c.id === "release.pending-upgrade")).toMatchObject({ status: "pass" });
  });
  it("passes when running images and server version match the manifest", () => {
    expect(checkRelease(manifest, null, healthy, facts)).toMatchObject([{ status: "pass" }, { status: "pass" }]);
  });
  it("fails on a digest or version mismatch and on an unfinished upgrade", () => {
    const drifted = healthy.map((s) => (s.Service === "varlatch-web" ? { ...s, Image: "varlatch-varlatch-web" } : s));
    const checks = checkRelease(manifest, { ...manifest, version: "0.10.0" }, drifted, { ...facts, serverVersion: "0.8.0" });
    expect(checks[0]).toMatchObject({ id: "release.pending-upgrade", status: "fail" });
    expect(checks[1]!.detail).toContain("varlatchd reports 0.8.0");
    expect(checks[1]!.detail).toContain("varlatch-web runs varlatch-varlatch-web");
  });
  it("judges a pending upgrade against the pending release", () => {
    const checks = checkRelease(manifest, { ...manifest, version: "0.10.0" }, healthy, { ...facts, serverVersion: "0.10.0" });
    expect(checks[1]).toMatchObject({ id: "release.consistency", status: "pass", detail: "release 0.10.0 (pending)" });
    expect(checkRelease(manifest, { ...manifest, version: "0.10.0" }, healthy, facts)[1]).toMatchObject({ status: "fail" });
  });
});

describe("checkSupervisor", () => {
  const changed = Date.parse("2026-09-24T10:00:00Z");
  it("passes when convex-backend started after the file changed", () => {
    expect(checkSupervisor(changed, "2026-09-24T10:00:05.123456789Z")).toMatchObject({ status: "pass", class: "mandatory" });
  });
  it("fails when convex-backend still runs the previous supervisor", () => {
    const check = checkSupervisor(changed, "2026-09-23T17:12:00.5Z");
    expect(check).toMatchObject({ status: "fail", id: "application-plane.supervisor" });
    expect(check!.remedy).toContain("--force-recreate convex-backend");
  });
  it("does not apply without the file or a running container", () => {
    expect(checkSupervisor(null, "2026-09-24T10:00:05Z")).toBeNull();
    expect(checkSupervisor(changed, null)).toBeNull();
  });
  it("judges by content when the supervisor recorded what it loaded", () => {
    const sha = "a".repeat(64);
    // Rewritten unchanged after the container started, as Coolify does on every deploy.
    expect(checkSupervisor(changed, "2026-09-23T17:12:00.5Z", { file: sha, loaded: sha }))
      .toMatchObject({ status: "pass", detail: expect.stringContaining("same content") });
    const stale = checkSupervisor(changed, "2026-09-24T10:00:05Z", { file: sha, loaded: "b".repeat(64) });
    expect(stale).toMatchObject({ status: "fail" });
    expect(stale!.remedy).toContain("--force-recreate convex-backend");
  });
  it("falls back to times for a supervisor that recorded no hash", () => {
    expect(checkSupervisor(changed, "2026-09-23T17:12:00.5Z", { file: "a".repeat(64), loaded: null })).toMatchObject({ status: "fail" });
  });
});

describe("evaluateGate (ADR-0035 D11)", () => {
  const check = (id: string, status: "pass" | "fail" | "unknown", cls: "mandatory" | "advisory" = "mandatory") =>
    ({ id, title: id, class: cls, status });
  const passing = ["services.running", "secret-plane.ready", "release.consistency", "config.public-url", "mirror.catch-up", "application-plane.functions"]
    .map((id) => check(id, "pass"));
  const report = (checks: ReturnType<typeof check>[]) => ({ dir: "/x", facts, checks });
  it("passes when every gate check passes; pending, browser realtime and advisories do not block", () => {
    const verdict = evaluateGate(report([...passing, check("release.pending-upgrade", "fail"), check("realtime.browser", "unknown"),
      check("backups.status", "unknown", "advisory"), check("custody.attestations", "fail", "advisory")]));
    expect(verdict.pass).toBe(true);
    expect(verdict.outsideGate.map((c) => c.id)).toEqual(["realtime.browser"]);
    expect(verdict.advisory.map((c) => c.id)).toEqual(["backups.status", "custody.attestations"]);
    expect(formatGate(verdict)).toContain("Upgrade gate: PASS");
  });
  it("blocks on unknown exactly like fail", () => {
    const verdict = evaluateGate(report(passing.map((c) => (c.id === "mirror.catch-up" ? { ...c, status: "unknown" as const } : c))));
    expect(verdict.pass).toBe(false);
    expect(verdict.blocking.map((c) => c.id)).toEqual(["mirror.catch-up"]);
  });
  it("treats a missing required check as unknown", () => {
    const verdict = evaluateGate(report(passing.filter((c) => c.id !== "application-plane.functions")));
    expect(verdict.blocking).toEqual([expect.objectContaining({ id: "application-plane.functions", status: "unknown" })]);
    expect(formatGate(verdict)).toContain("BLOCKED");
  });
  it("gates conditional checks only where they apply", () => {
    expect(evaluateGate(report([...passing, check("application-plane.supervisor", "fail")])).pass).toBe(false);
    expect(evaluateGate(report([...passing, check("web.live-updates-reachable", "pass")])).pass).toBe(true);
  });
});

describe("checkCliVersion", () => {
  it("is advisory", () => {
    expect(checkCliVersion(facts, "0.9.0")).toMatchObject({ status: "pass" });
    expect(checkCliVersion(facts, "0.8.0")).toMatchObject({ status: "fail", class: "advisory" });
    expect(checkCliVersion(null, "0.9.0")).toMatchObject({ status: "unknown" });
  });
});

describe("checkWebConfig", () => {
  const js = (url: string) => `window.__VARLATCH__ = { convexUrl: "${url}" };\n`;
  it("passes a public HTTPS Convex origin", () => {
    expect(checkWebConfig(js("https://convex.example.com"), facts.publicUrl)).toMatchObject([{ status: "pass" }, { status: "pass" }]);
  });
  it("flags a loopback Convex origin behind a public dashboard", () => {
    const checks = checkWebConfig(js("http://127.0.0.1:3210"), facts.publicUrl);
    expect(checks[1]).toMatchObject({ status: "fail", class: "mandatory" });
    expect(checks[1]!.detail).toContain("only reachable on this host");
  });
  it("flags mixed content", () => {
    expect(checkWebConfig(js("http://convex.example.com"), facts.publicUrl)[1]!.detail).toContain("mixed content");
  });
  it("treats a missing Convex URL as advisory", () => {
    expect(checkWebConfig(null, facts.publicUrl)).toMatchObject([{ status: "fail", class: "advisory" }]);
  });
  it("accepts loopback everywhere for local installations", () => {
    expect(checkWebConfig(js("http://127.0.0.1:3210"), "http://localhost:8787")[1]).toMatchObject({ status: "pass" });
  });
});

describe("runDoctor", () => {
  const serverReport = {
    facts,
    checks: [{ id: "secret-plane.ready", title: "Secret Plane ready", class: "mandatory", status: "pass" }],
  };
  function fakeRunner(overrides: Record<string, { code: number; stdout: string }> = {}): { run: Runner; calls: string[][] } {
    const calls: string[][] = [];
    const run: Runner = async (args) => {
      calls.push(args);
      const key = args.slice(0, 4).join(" ");
      if (overrides[key]) return overrides[key]!;
      if (key === "compose ps --all --format") return { code: 0, stdout: JSON.stringify(healthy) };
      if (key === "compose exec -T varlatchd") return { code: 0, stdout: JSON.stringify(serverReport) };
      if (key === "compose exec -T varlatch-web") return { code: 0, stdout: 'window.__VARLATCH__ = { convexUrl: "https://convex.example.com" };' };
      return { code: 1, stdout: "" };
    };
    return { run, calls };
  }

  it("only lists and execs read-only commands", async () => {
    const dir = mkdtempSync(join(tmpdir(), "doctor-"));
    const { run, calls } = fakeRunner();
    const report = await runDoctor({ dir, run, waitSeconds: 0 });
    for (const args of calls) {
      const command = args[0] === "inspect" ? "inspect" : args[args[1] === "--profile" ? 3 : 1];
      expect(["ps", "exec", "config", "inspect"]).toContain(command);
    }
    expect(calls.find((a) => a[3] === "varlatchd")).toEqual(["compose", "exec", "-T", "varlatchd", "node", "dist/cli.js", "admin", "doctor", "--wait", "0"]);
    expect(doctorExitCode(report)).toBe(0);
    expect(report.checks.find((c) => c.id === "realtime.browser")).toMatchObject({ status: "unknown" });
  });

  it("reads the release manifest and a pending upgrade from the Compose directory", async () => {
    const dir = mkdtempSync(join(tmpdir(), "doctor-"));
    writeFileSync(join(dir, "varlatch-release.json"), JSON.stringify(manifest));
    writeFileSync(join(dir, "varlatch-release.json.pending"), JSON.stringify({ ...manifest, version: "0.10.0" }));
    const report = await runDoctor({ dir, run: fakeRunner().run, waitSeconds: 0 });
    // The pending release is what should run; this server still reports the installed one.
    expect(report.checks.find((c) => c.id === "release.consistency")).toMatchObject({ status: "fail" });
    expect(report.checks.find((c) => c.id === "release.consistency")!.detail).toContain("manifest pins 0.10.0");
    expect(report.checks.find((c) => c.id === "release.pending-upgrade")).toMatchObject({ status: "fail" });
    expect(doctorExitCode(report)).toBe(1);
  });

  it("stops with one clear failure when Compose is unreachable", async () => {
    const { run } = fakeRunner({ "compose ps --all --format": { code: 1, stdout: "" } });
    const report = await runDoctor({ dir: tmpdir(), run });
    expect(report.checks).toEqual([expect.objectContaining({ id: "docker.compose", status: "fail" })]);
    expect(doctorExitCode(report)).toBe(1);
  });

  it("reports the Secret Plane as unknown when varlatchd cannot be queried", async () => {
    const { run } = fakeRunner({ "compose exec -T varlatchd": { code: 1, stdout: "" } });
    const report = await runDoctor({ dir: mkdtempSync(join(tmpdir(), "doctor-")), run, waitSeconds: 0 });
    expect(report.checks.find((c) => c.id === "secret-plane.ready")).toMatchObject({ status: "unknown", class: "mandatory" });
    expect(formatDoctor(report)).toContain("? Secret Plane ready  [mandatory, unknown]");
  });
});
