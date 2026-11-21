#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Checks infra/coolify/varlatchd.compose.yml (the single-container Go 0.50+
 * Coolify Compose file):
 *
 *   - `docker compose config` renders with VARLATCH_VARLATCHD_DIGEST set,
 *     default and custom VARLATCH_IMAGE_REGISTRY, user 65532:65532, read-only
 *     root filesystem, unless-stopped restart policy, no published host ports,
 *     no container healthcheck (distroless), no environment block, and the
 *     three bind mounts `varlatch migrate` expects (/var/lib/varlatch, /keys,
 *     /etc/varlatch/varlatchd.conf);
 *   - custom VARLATCH_DATA_DIR, VARLATCH_KEYS_DIR and VARLATCH_CONFIG_FILE
 *     override the three host bind paths;
 *   - `docker compose config` fails when VARLATCH_VARLATCHD_DIGEST is unset or
 *     empty, naming the variable;
 *   - infra/coolify/README.md documents the file and every variable it uses.
 *
 *   node infra/coolify/check-varlatchd-compose.mjs   (part of `pnpm compose:check`)
 */
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "../..");
const FILE = "infra/coolify/varlatchd.compose.yml";
const DIGEST = `sha256:${"1".repeat(64)}`;
const problems = [];

const BASE_ENV = {
  PATH: process.env.PATH ?? "",
  HOME: process.env.HOME ?? "",
  DOCKER_HOST: process.env.DOCKER_HOST ?? "",
};

function render(env) {
  return spawnSync("docker", ["compose", "-f", join(ROOT, FILE), "config", "--format", "json"], {
    cwd: ROOT,
    env,
    encoding: "utf8",
  });
}

// 1. Default and custom registry render with digest pinned and expected service contract.
for (const registry of [undefined, "registry.pins.test/fork"]) {
  const env = {
    ...BASE_ENV,
    VARLATCH_VARLATCHD_DIGEST: DIGEST,
    ...(registry ? { VARLATCH_IMAGE_REGISTRY: registry } : {}),
  };
  const r = render(env);
  if (r.status !== 0) {
    problems.push(`${FILE}: failed to render (${registry ?? "default registry"}): ${r.stderr.trim().split("\n").pop()}`);
    continue;
  }
  const cfg = JSON.parse(r.stdout);
  const serviceNames = Object.keys(cfg.services ?? {});
  if (JSON.stringify(serviceNames) !== JSON.stringify(["varlatchd"])) {
    problems.push(`${FILE}: services are [${serviceNames.join(", ")}], expected [varlatchd]`);
    continue;
  }
  const svc = cfg.services.varlatchd;
  const wantImage = `${registry ?? "ghcr.io/varlatch"}/varlatchd@${DIGEST}`;
  if (svc.image !== wantImage) problems.push(`${FILE}: image is ${svc.image}, expected ${wantImage}`);
  if (svc.build) problems.push(`${FILE}: varlatchd must not build from source`);
  if (svc.user !== "65532:65532") problems.push(`${FILE}: user is ${svc.user}, expected 65532:65532`);
  if (svc.read_only !== true) problems.push(`${FILE}: read_only must be true`);
  if (svc.restart !== "unless-stopped") problems.push(`${FILE}: restart is ${svc.restart}, expected unless-stopped`);
  if ((svc.ports ?? []).length > 0) problems.push(`${FILE}: must not publish host ports by default`);
  if (svc.healthcheck) problems.push(`${FILE}: distroless image must omit container healthcheck`);
  if (svc.environment && Object.keys(svc.environment).length > 0) {
    problems.push(`${FILE}: varlatchd must not set environment variables in the compose file`);
  }

  const mounts = (svc.volumes ?? []).map((v) => ({ source: v.source, target: v.target, read_only: Boolean(v.read_only) }));
  const expectedMounts = [
    { source: "/srv/varlatch/data", target: "/var/lib/varlatch", read_only: false },
    { source: "/srv/varlatch/keys", target: "/keys", read_only: true },
    { source: "/srv/varlatch/varlatchd.conf", target: "/etc/varlatch/varlatchd.conf", read_only: true },
  ];
  for (const want of expectedMounts) {
    const found = mounts.find((m) => m.target === want.target);
    if (!found) {
      problems.push(`${FILE}: missing bind mount for ${want.target}`);
    } else if (found.source !== want.source || found.read_only !== want.read_only) {
      problems.push(`${FILE}: mount ${want.target} is ${found.source} (ro=${found.read_only}), expected ${want.source} (ro=${want.read_only})`);
    }
  }
  if (mounts.length !== expectedMounts.length) {
    problems.push(`${FILE}: has ${mounts.length} mounts, expected ${expectedMounts.length}`);
  }
}

// 2. Host bind path overrides.
{
  const r = render({
    ...BASE_ENV,
    VARLATCH_VARLATCHD_DIGEST: DIGEST,
    VARLATCH_DATA_DIR: "/data/custom/data",
    VARLATCH_KEYS_DIR: "/data/custom/keys",
    VARLATCH_CONFIG_FILE: "/data/custom/varlatchd.conf",
  });
  if (r.status !== 0) {
    problems.push(`${FILE}: failed to render with custom host paths: ${r.stderr.trim().split("\n").pop()}`);
  } else {
    const mounts = JSON.parse(r.stdout).services.varlatchd.volumes ?? [];
    for (const [target, source] of [
      ["/var/lib/varlatch", "/data/custom/data"],
      ["/keys", "/data/custom/keys"],
      ["/etc/varlatch/varlatchd.conf", "/data/custom/varlatchd.conf"],
    ]) {
      const found = mounts.find((m) => m.target === target);
      if (found?.source !== source) problems.push(`${FILE}: custom override for ${target} rendered ${found?.source}, expected ${source}`);
    }
  }
}

// 3. Unset or empty digest must fail and name VARLATCH_VARLATCHD_DIGEST.
for (const [label, env] of [
  ["unset", { ...BASE_ENV }],
  ["empty", { ...BASE_ENV, VARLATCH_VARLATCHD_DIGEST: "" }],
]) {
  const r = render(env);
  if (r.status === 0) {
    problems.push(`${FILE}: rendered with VARLATCH_VARLATCHD_DIGEST ${label}`);
  } else if (!r.stderr.includes("VARLATCH_VARLATCHD_DIGEST")) {
    problems.push(`${FILE}: refused ${label} digest without naming VARLATCH_VARLATCHD_DIGEST: ${r.stderr.trim()}`);
  }
}

// 4. Documentation names the file and every variable it interpolates.
const readme = readFileSync(join(ROOT, "infra/coolify/README.md"), "utf8");
for (const token of [
  "varlatchd.compose.yml",
  "VARLATCH_VARLATCHD_DIGEST",
  "VARLATCH_IMAGE_REGISTRY",
  "VARLATCH_DATA_DIR",
  "VARLATCH_KEYS_DIR",
  "VARLATCH_CONFIG_FILE",
]) {
  if (!readme.includes(token)) problems.push(`infra/coolify/README.md does not name ${token}`);
}

if (problems.length > 0) {
  for (const p of problems) console.error(p);
  process.exit(1);
}
console.log("Coolify Go Compose file: varlatchd.compose.yml renders with digest, refuses without it, and matches image target mounts.");
