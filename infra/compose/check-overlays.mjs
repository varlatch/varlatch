#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Checks the merged Compose configuration of every documented overlay
 * chain, as `docker compose config` reads it (placeholders uninterpolated),
 * so an overlay edit that lands a key on the wrong service fails here
 * instead of in a deployment:
 *
 *   - a service that points a program at a file (TS_SERVE_CONFIG for
 *     Tailscale serve, Caddy's Caddyfile) owns the mount at that path, and
 *     no other service mounts those files;
 *   - varlatchd's VARLATCH_TRUSTED_PROXIES default names the dashboard's
 *     nginx and the chain's TLS proxy.
 *
 *   node infra/compose/check-overlays.mjs   (part of `pnpm compose:check`)
 */
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "../..");
const C = "infra/compose";

export const CHAINS = [
  { name: "canonical", files: [`${C}/docker-compose.yml`], trusted: "varlatch-web" },
  { name: "Caddy ingress", files: [`${C}/docker-compose.yml`, `${C}/docker-compose.caddy.yml`], trusted: "varlatch-web,caddy" },
  { name: "Tailscale", files: [`${C}/docker-compose.yml`, `${C}/docker-compose.tailscale.yml`], trusted: "varlatch-web" },
  {
    name: "tailnet HTTPS ingress",
    files: [`${C}/docker-compose.yml`, `${C}/docker-compose.tailscale.yml`, `${C}/docker-compose.tailnet-https.yml`],
    trusted: "varlatch-web,tailscale",
  },
  { name: "Coolify (generated)", files: [`${C}/docker-compose.coolify-tailscale.yml`], trusted: "varlatch-web,coolify-proxy" },
];

/** Files a program reads at a fixed path, by the mount's source file name. */
const CONFIG_FILES = { "tailscale-serve.json": "TS_SERVE_CONFIG", Caddyfile: "/etc/caddy/Caddyfile" };

function environmentOf(service) {
  const env = service.environment ?? {};
  if (!Array.isArray(env)) return env;
  return Object.fromEntries(env.map((e) => (e.includes("=") ? [e.slice(0, e.indexOf("=")), e.slice(e.indexOf("=") + 1)] : [e, null])));
}

function mountsOf(service) {
  return (service.volumes ?? []).map((v) =>
    typeof v === "string" ? { source: v.split(":")[0], target: v.split(":")[1] } : { source: v.source ?? "", target: v.target },
  );
}

const baseName = (path) => path.split("/").pop();

/** The problems in one merged configuration; empty when it is sound. */
export function problemsIn(config, chain) {
  const problems = [];
  const services = config.services ?? {};
  for (const [name, service] of Object.entries(services)) {
    const env = environmentOf(service);
    const mounts = mountsOf(service);
    if (env.TS_SERVE_CONFIG && !mounts.some((m) => m.target === env.TS_SERVE_CONFIG)) {
      problems.push(`${chain.name}: ${name} sets TS_SERVE_CONFIG=${env.TS_SERVE_CONFIG} but mounts nothing there`);
    }
    for (const mount of mounts) {
      const wanted = CONFIG_FILES[baseName(mount.source)];
      if (!wanted) continue;
      const owner = wanted.startsWith("/") ? mount.target === wanted : env[wanted] === mount.target;
      if (!owner) problems.push(`${chain.name}: ${name} mounts ${baseName(mount.source)} at ${mount.target}, which nothing in ${name} reads`);
    }
  }
  if (services.caddy && !mountsOf(services.caddy).some((m) => m.target === "/etc/caddy/Caddyfile")) {
    problems.push(`${chain.name}: caddy does not mount its Caddyfile`);
  }
  const trusted = environmentOf(services.varlatchd ?? {}).VARLATCH_TRUSTED_PROXIES;
  const expected = `\${VARLATCH_TRUSTED_PROXIES:-${chain.trusted}}`;
  if (trusted !== expected) problems.push(`${chain.name}: varlatchd VARLATCH_TRUSTED_PROXIES is ${trusted}, expected ${expected}`);
  return problems;
}

function composeConfig(files) {
  const args = ["compose", ...files.flatMap((f) => ["-f", join(ROOT, f)]), "config", "--no-interpolate", "--no-path-resolution", "--format", "json"];
  return JSON.parse(execFileSync("docker", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const problems = CHAINS.flatMap((chain) => problemsIn(composeConfig(chain.files), chain));
  for (const problem of problems) console.error(problem);
  if (problems.length > 0) process.exit(1);
  console.log(`Compose overlays: ${CHAINS.length} documented chains checked (config mounts, trusted proxies).`);
}
