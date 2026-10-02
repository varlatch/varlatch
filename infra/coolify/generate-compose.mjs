#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Generates infra/compose/docker-compose.coolify-tailscale.yml (ADR-0035
 * design note, "Generated Coolify/Tailscale Compose file").
 *
 * Coolify deploys exactly one Compose file, so the Tailscale variant used to
 * be a hand-merged copy of the canonical file and the Tailscale overlay — and
 * it drifted: fixes landed in the copy but not in the overlay. This script
 * applies, in order,
 *
 *   infra/compose/docker-compose.yml          canonical contract (ADR-0019)
 *   infra/compose/docker-compose.tailscale.yml Tailscale overlay (ADR-0014)
 *   infra/coolify/compose.overlay.yml          Coolify-only deltas
 *
 * with Compose's overlay semantics for the constructs these files use —
 * mappings merge recursively, sequences append items not already present,
 * scalars replace, and `!reset` removes the key — on the YAML document tree,
 * so comments survive. `${VAR}` placeholders are text and are never
 * interpolated: no values, and never secrets, enter the artifact.
 *
 *   node infra/coolify/generate-compose.mjs                 write the file
 *   node infra/coolify/generate-compose.mjs --check         exit 1 if stale
 *   node infra/coolify/generate-compose.mjs --verify-docker also prove that
 *     `docker compose config` reads the generated file exactly as it reads
 *     the -f overlay chain (placeholders uninterpolated)
 */
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { isMap, isScalar, isSeq, parseDocument } from "yaml";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "../..");
export const INPUTS = [
  "infra/compose/docker-compose.yml",
  "infra/compose/docker-compose.tailscale.yml",
  "infra/coolify/compose.overlay.yml",
];
export const OUTPUT = "infra/compose/docker-compose.coolify-tailscale.yml";

const HEADER = ` GENERATED FILE — do not edit. Regenerate with \`pnpm compose:generate\`
 from ${INPUTS.join(",\n      ")}.

 Coolify deployment WITH the Tailscale sidecar (ADR-0014/0019): Coolify
 deploys exactly one Compose file (no overlay -f chaining), so this is the
 canonical contract with the Tailscale overlay and the Coolify-only deltas
 applied.

 Topology (ADR-0014): the tailscale sidecar owns the network namespace and
 varlatchd joins it, so connections to the tailnet listener (8687) arrive
 with their TRUE tailnet socket peer address and WhoIs runs over the shared
 LocalAPI socket. The sidecar carries the network alias \`varlatchd\` so the
 dashboard's same-origin nginx proxy (proxy_pass http://varlatchd:8686)
 keeps resolving after varlatchd gives up its own network identity.

 Requires in .env (Coolify env settings):
   TS_AUTHKEY               tailnet auth key for the sidecar node
   VARLATCH_TAILNET_NAME    the tailnet, e.g. example.ts.net`;

const RESET = "!reset";

function keyOf(pair) {
  return isScalar(pair.key) ? String(pair.key.value) : String(pair.key);
}

function sameItem(a, b) {
  return JSON.stringify(a?.toJSON?.() ?? a) === JSON.stringify(b?.toJSON?.() ?? b);
}

/** Compose overlay merge of `over` into `base` (both YAMLMap nodes). */
export function mergeInto(base, over, path = "") {
  // A comment above a map's first key belongs to the map node itself, which
  // is discarded when it merges into an existing map: hand it to that key.
  const first = over.items[0];
  if (over.commentBefore && first && isScalar(first.key) && !first.key.commentBefore) {
    first.key.commentBefore = over.commentBefore;
  }
  for (const pair of over.items) {
    const key = keyOf(pair);
    const at = `${path}.${key}`;
    const index = base.items.findIndex((p) => keyOf(p) === key);
    if (pair.value?.tag === RESET) {
      if (index >= 0) base.items.splice(index, 1);
      continue;
    }
    if (pair.value?.tag) throw new Error(`${at}: unsupported tag ${pair.value.tag}`);
    if (index < 0) {
      base.items.push(pair); // keeps the overlay's comments with the key
      continue;
    }
    const target = base.items[index].value;
    if (isMap(target) && isMap(pair.value)) {
      mergeInto(target, pair.value, at);
    } else if (isSeq(target) && isSeq(pair.value)) {
      for (const item of pair.value.items) {
        if (!target.items.some((existing) => sameItem(existing, item))) target.items.push(item);
      }
    } else if ((isMap(target) || isSeq(target)) !== (isMap(pair.value) || isSeq(pair.value))) {
      throw new Error(`${at}: overlay changes the node type; use !reset first`);
    } else {
      base.items[index].value = pair.value;
    }
  }
}

function load(path) {
  const doc = parseDocument(readFileSync(join(ROOT, path), "utf8"), { keepSourceTokens: false });
  if (doc.errors.length) throw new Error(`${path}: ${doc.errors[0].message}`);
  return doc;
}

export function generate() {
  const [base, ...overlays] = INPUTS.map(load);
  for (const overlay of overlays) mergeInto(base.contents, overlay.contents, "");
  base.commentBefore = HEADER;
  return base.toString({ lineWidth: 0 });
}

/** Normalizes `docker compose config` JSON so list/map spellings compare equal. */
function normalize(config) {
  const services = {};
  for (const [name, svc] of Object.entries(config.services ?? {})) {
    const s = { ...svc };
    if (Array.isArray(s.environment)) {
      s.environment = Object.fromEntries(s.environment.map((e) => {
        const i = e.indexOf("=");
        return i < 0 ? [e, null] : [e.slice(0, i), e.slice(i + 1)];
      }));
    }
    // A mapping has no order, and docker places a key an overlay sets differently in the two spellings.
    if (s.environment && typeof s.environment === "object") {
      s.environment = Object.fromEntries(Object.entries(s.environment).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
    }
    for (const list of ["volumes", "ports", "secrets"]) {
      if (Array.isArray(s[list])) s[list] = [...s[list]].map((v) => JSON.stringify(v)).sort();
    }
    services[name] = s;
  }
  return { ...config, services };
}

function composeConfig(files) {
  const args = ["compose", ...files.flatMap((f) => ["-f", join(ROOT, f)]), "config", "--no-interpolate", "--no-path-resolution", "--format", "json"];
  return normalize(JSON.parse(execFileSync("docker", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })));
}

/**
 * Coolify moves every service without a `networks` key onto its own network
 * only, away from the default network where the sidecar carries the
 * `varlatchd` alias. The services that address varlatchd by that name must
 * therefore join `default` explicitly (Coolify still adds its own network).
 */
const ALIAS_CONSUMERS = ["varlatch-web", "convex-backend"];

export function checkAliasReachability(text) {
  const services = parseDocument(text).toJS().services ?? {};
  const aliases = services.tailscale?.networks?.default?.aliases ?? [];
  if (!aliases.includes("varlatchd")) throw new Error("tailscale no longer carries the varlatchd alias on the default network");
  for (const name of ALIAS_CONSUMERS) {
    const networks = services[name]?.networks;
    const joined = Array.isArray(networks) ? networks.includes("default") : Boolean(networks && "default" in networks);
    if (!joined) throw new Error(`${name} must join the default network explicitly on Coolify to resolve varlatchd`);
  }
}

function main() {
  const args = process.argv.slice(2);
  const generated = generate();
  checkAliasReachability(generated);
  const outPath = join(ROOT, OUTPUT);
  if (args.includes("--check")) {
    const current = readFileSync(outPath, "utf8");
    if (current !== generated) {
      console.error(`${OUTPUT} is stale or hand-edited. Edit its inputs, then run \`pnpm compose:generate\`:\n  ${INPUTS.join("\n  ")}`);
      process.exit(1);
    }
    console.log(`${OUTPUT} is current.`);
  } else {
    writeFileSync(outPath, generated);
    console.log(`Wrote ${relative(process.cwd(), outPath)}`);
  }
  if (args.includes("--verify-docker")) {
    const chain = composeConfig(INPUTS);
    const single = composeConfig([OUTPUT]);
    if (JSON.stringify(chain) !== JSON.stringify(single)) {
      console.error("docker compose reads the generated file differently from the -f overlay chain");
      process.exit(1);
    }
    console.log("docker compose config: generated file == overlay chain (uninterpolated).");
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
