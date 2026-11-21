#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Checks the Coolify files' image pins (infra/coolify/compose.images.yml):
 *
 *   - each generated Coolify file interpolates exactly the release's digest
 *     variables (infra/release/coolify-digests.mjs) and the registry;
 *   - `docker compose config` renders it with the digests set, every built
 *     service on `<registry>/<repository>@<digest>`, and fails without each
 *     digest, naming the variable;
 *   - infra/coolify/README.md, which the operator follows, names every
 *     variable and the release file they come from.
 *
 * With --release-dir <dir> (the release files, as build-release-artifacts.mjs
 * wrote them), it also checks that coolify-image-digests.env holds the
 * digests varlatch-release.json pins, and that SHA256SUMS lists it.
 *
 *   node infra/coolify/check-image-pins.mjs [--release-dir <dir>]   (part of `pnpm compose:check`)
 */
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { COOLIFY_IMAGES, DIGEST_FILE, REGISTRY_VARIABLE, coolifyImageDigests, variablesIn } from "../release/coolify-digests.mjs";
import { FILES } from "./generate-compose.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "../..");
const problems = [];
const expected = [REGISTRY_VARIABLE, ...Object.values(COOLIFY_IMAGES).map((i) => i.variable)].sort();

// What the files need besides the digests to render; placeholders only.
const BASE_ENV = {
  PATH: process.env.PATH ?? "",
  HOME: process.env.HOME ?? "",
  DOCKER_HOST: process.env.DOCKER_HOST ?? "",
  VARLATCH_PUBLIC_URL: "https://vault.pins.test",
  VARLATCH_TAILNET_NAME: "pins.ts.net",
  TS_AUTHKEY: "pins-test",
};
const hex = (c) => c.repeat(64);
const DIGESTS = {
  varlatchd: `sha256:${hex("1")}`,
  "varlatch-web": `sha256:${hex("2")}`,
  "convex-deploy": `sha256:${hex("3")}`,
};
const digestEnv = Object.fromEntries(Object.entries(COOLIFY_IMAGES).map(([name, { variable }]) => [variable, DIGESTS[name]]));
const SERVICE_IMAGE = { "varlatch-migrate": "varlatchd", varlatchd: "varlatchd", "varlatch-web": "varlatch-web", "convex-deploy": "convex-deploy" };

function render(output, env) {
  return spawnSync("docker", ["compose", "-f", join(ROOT, output), "--profile", "deploy", "config", "--format", "json"], {
    cwd: ROOT, env: Object.fromEntries(Object.entries(env).filter(([, v]) => v !== "")), encoding: "utf8",
  });
}

for (const { output } of FILES) {
  const text = readFileSync(join(ROOT, output), "utf8");
  const used = variablesIn(text).sort();
  if (JSON.stringify(used) !== JSON.stringify(expected)) problems.push(`${output}: interpolates ${used.join(", ")}, expected ${expected.join(", ")}`);

  for (const registry of [undefined, "registry.pins.test/fork"]) {
    const env = { ...BASE_ENV, ...digestEnv, ...(registry ? { [REGISTRY_VARIABLE]: registry } : {}) };
    const r = render(output, env);
    if (r.status !== 0) {
      problems.push(`${output}: does not render with the digests set: ${r.stderr.trim().split("\n").pop()}`);
      continue;
    }
    const services = JSON.parse(r.stdout).services ?? {};
    for (const [service, image] of Object.entries(SERVICE_IMAGE)) {
      const want = `${registry ?? "ghcr.io/varlatch"}/${COOLIFY_IMAGES[image].repository}@${DIGESTS[image]}`;
      if (services[service]?.image !== want) problems.push(`${output}: ${service} renders image ${services[service]?.image}, expected ${want}`);
      if (services[service]?.build) problems.push(`${output}: ${service} still builds`);
    }
  }
  for (const { variable } of Object.values(COOLIFY_IMAGES)) {
    const r = render(output, { ...BASE_ENV, ...digestEnv, [variable]: "" });
    if (r.status === 0) problems.push(`${output}: renders without ${variable}`);
    else if (!r.stderr.includes(variable)) problems.push(`${output}: refuses a missing ${variable} without naming it: ${r.stderr.trim()}`);
  }
}

const readme = readFileSync(join(ROOT, "infra/coolify/README.md"), "utf8");
for (const name of [...expected, DIGEST_FILE, ...FILES.map((f) => f.output.split("/").pop())]) {
  if (!readme.includes(name)) problems.push(`infra/coolify/README.md does not name ${name}`);
}

const at = process.argv.indexOf("--release-dir");
if (at >= 0) {
  const dir = process.argv[at + 1];
  const manifest = JSON.parse(readFileSync(join(dir, "varlatch-release.json"), "utf8"));
  const published = readFileSync(join(dir, DIGEST_FILE), "utf8");
  // From the manifest's own references: what the release pins is what the file says.
  const refs = Object.fromEntries(Object.keys(COOLIFY_IMAGES).map((name) => [name, `${manifest.images[name].tag}@${manifest.images[name].digest.split("@")[1]}`]));
  if (published !== coolifyImageDigests(refs)) problems.push(`${DIGEST_FILE} differs from the digests in varlatch-release.json`);
  for (const [name, { variable }] of Object.entries(COOLIFY_IMAGES)) {
    const line = published.split("\n").find((l) => l.startsWith(`${variable}=`));
    if (line !== `${variable}=${manifest.images[name].digest.split("@")[1]}`) problems.push(`${DIGEST_FILE}: ${variable} is not ${name}'s digest in varlatch-release.json`);
  }
  if (!readFileSync(join(dir, "SHA256SUMS"), "utf8").split("\n").some((l) => l.endsWith(`  ${DIGEST_FILE}`))) problems.push(`SHA256SUMS does not list ${DIGEST_FILE}`);
}

if (problems.length) {
  for (const p of problems) console.error(p);
  process.exit(1);
}
console.log(`Coolify image pins: ${FILES.length} files render with the digests and refuse without them${at >= 0 ? `; ${DIGEST_FILE} matches varlatch-release.json` : ""}.`);
