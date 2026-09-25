#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Release artifact builder (ADR-0019 §26). From the canonical compose file it
 * produces the deployment unit self-hosters actually consume:
 *
 *   varlatch-release.json                 machine-readable digest manifest
 *   docker-compose.release.yml            canonical compose, `build:` blocks
 *                                         replaced with digest-pinned images
 *   varlatch-compose-<version>.tar.gz     first-install bundle (release
 *                                         compose + overlays + postgres-init +
 *                                         .env.example + README + manifest)
 *   docker-compose.tailscale.yml, docker-compose.tailnet-https.yml,
 *   tailscale-serve.json, docker-compose.caddy.yml, Caddyfile
 *                                         ingress overlays (ADR-0035 D6), each
 *                                         an asset so `varlatch upgrade` can
 *                                         refresh the ones an installation has
 *   varlatch-cli-<version>.cjs            single-file operator CLI (backup,
 *                                         upgrade); needs only Node 22+.
 *                                         Requires `pnpm build` beforehand.
 *   THIRD-PARTY-NOTICES.md                third-party components and licenses
 *                                         (ADR-0037 D1); the bundle also
 *                                         carries it, LICENSE and LICENSES/
 *   SHA256SUMS                            checksums of every asset above
 *
 * Digests are the canonical runtime pin; tags are for humans. Self-hosters
 * never resolve digests manually — CI resolves them here at release time.
 *
 * Usage:
 *   build-release-artifacts.mjs <version> \
 *     --image varlatchd=ghcr.io/owner/varlatchd:0.7.0@sha256:... \
 *     --image varlatch-web=ghcr.io/owner/varlatch-web:0.7.0@sha256:... \
 *     --image convex-deploy=ghcr.io/owner/varlatch-convex-deploy:0.7.0@sha256:... \
 *     [--postgres docker.io/library/postgres:17.6@sha256:...] \
 *     [--caddy docker.io/library/caddy:2.10.2@sha256:...] \
 *     [--tailscale docker.io/tailscale/tailscale:v1.102.3@sha256:...] \
 *     [--out <dir>]
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const composeDir = join(repoRoot, "infra/compose");

const [version, ...rest] = process.argv.slice(2);
if (!version || version.startsWith("-")) {
  console.error("Usage: build-release-artifacts.mjs <version> --image name=ref@digest ... [--postgres ref@digest] [--out dir]");
  process.exit(1);
}
const images = {};
let postgresRef, caddyRef, tailscaleRef;
let outDir = process.cwd();
for (let i = 0; i < rest.length; i += 2) {
  const [flag, value] = [rest[i], rest[i + 1]];
  if (value === undefined) fail(`Missing value for ${flag}`);
  if (flag === "--image") {
    const eq = value.indexOf("=");
    if (eq < 0) fail(`--image expects name=ref, got: ${value}`);
    images[value.slice(0, eq)] = value.slice(eq + 1);
  } else if (flag === "--postgres") postgresRef = value;
  else if (flag === "--caddy") caddyRef = value;
  else if (flag === "--tailscale") tailscaleRef = value;
  else if (flag === "--out") outDir = resolve(value);
  else fail(`Unknown flag: ${flag}`);
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

/** "repo:tag@sha256:..." -> { tag: "repo:tag", digest: "repo@sha256:..." } */
function splitRef(ref) {
  const at = ref.indexOf("@sha256:");
  if (at < 0) fail(`Not digest-pinned: ${ref}`);
  const tagged = ref.slice(0, at);
  const repo = tagged.includes(":") ? tagged.slice(0, tagged.lastIndexOf(":")) : tagged;
  return { tag: tagged, digest: `${repo}${ref.slice(at)}` };
}

const IMAGE_FOR_DOCKERFILE = {
  "services/varlatchd/Dockerfile": "varlatchd",
  "apps/web/Dockerfile": "varlatch-web",
  "infra/compose/convex-deploy.Dockerfile": "convex-deploy",
};
for (const name of new Set(Object.values(IMAGE_FOR_DOCKERFILE))) {
  if (!images[name]) fail(`Missing --image ${name}=...`);
}

const canonical = readFileSync(join(composeDir, "docker-compose.yml"), "utf8");

// Replace every `build:` block with its digest-pinned release image. The
// canonical compose is the single deployment contract (ADR-0019); this stays
// a mechanical transform so the two can never diverge structurally.
let release = canonical.replace(
  /build:\n\s+context: \.\.\/\.\.\n\s+dockerfile: (\S+)\n/g,
  (match, dockerfile) => {
    const name = IMAGE_FOR_DOCKERFILE[dockerfile];
    if (!name) fail(`No release image mapped for ${dockerfile}`);
    return `image: ${images[name]}\n`;
  },
);
if (/^\s+build:/m.test(release)) fail("A build: block survived the transform — update IMAGE_FOR_DOCKERFILE");

if (postgresRef) release = release.replace(/image: postgres:\S+/, `image: ${postgresRef}`);

const convexBackendMatch = release.match(/image: (ghcr\.io\/get-convex\/convex-backend\S+)/);
if (!convexBackendMatch) fail("convex-backend image not found in canonical compose");

release = release.replace(
  /^#.*\n(#.*\n)*/,
  `# Varlatch ${version} — digest-pinned release set (ADR-0019 §26), generated\n` +
    `# from the canonical infra/compose/docker-compose.yml by release CI.\n` +
    `# Do not edit: local customization belongs in .env or a compose override\n` +
    `# file. Upgrade with \`varlatch upgrade\` (see infra/compose/README.md).\n`,
);

const backupRelease = JSON.parse(readFileSync(join(repoRoot, "packages/backup/src/release.json"), "utf8"));
if (backupRelease.version !== version) fail("Release version differs from the embedded backup compatibility manifest");
const manifest = {
  schemaVersion: 1,
  version,
  apiMajor: 1,
  migrationVersion: backupRelease.migrationVersion,
  supportedRestoreSources: backupRelease.supportedRestoreSources,
  generatedAt: new Date().toISOString(),
  supportedPostgresMajor: 17,
  images: {
    ...Object.fromEntries(Object.entries(images).map(([name, ref]) => [name, splitRef(ref)])),
    "convex-backend": { tag: null, digest: convexBackendMatch[1] },
    postgres: postgresRef ? splitRef(postgresRef) : { tag: "docker.io/library/postgres:17.6", digest: null },
    ...(caddyRef ? { caddy: splitRef(caddyRef) } : {}),
    ...(tailscaleRef ? { tailscale: splitRef(tailscaleRef) } : {}),
  },
};

// Ingress overlays, with their images pinned like the rest of the release.
const OVERLAYS = ["docker-compose.tailscale.yml", "docker-compose.tailnet-https.yml", "tailscale-serve.json", "docker-compose.caddy.yml", "Caddyfile"];
const overlay = name => {
  let text = readFileSync(join(composeDir, name), "utf8");
  if (name === "docker-compose.caddy.yml" && caddyRef) text = text.replace(/image: caddy:\S+/, `image: ${caddyRef}`);
  if (name === "docker-compose.tailscale.yml" && tailscaleRef) text = text.replace(/image: tailscale\/tailscale:\S+/, `image: ${tailscaleRef}`);
  return text;
};

mkdirSync(outDir, { recursive: true });
cpSync(join(composeDir, "convex-supervisor.cjs"), join(outDir, "convex-supervisor.cjs"));
for (const name of OVERLAYS) writeFileSync(join(outDir, name), overlay(name));
writeFileSync(join(outDir, "docker-compose.release.yml"), release);
writeFileSync(join(outDir, "varlatch-release.json"), `${JSON.stringify(manifest, null, 2)}\n`);

// First-install bundle: everything a self-hoster needs besides their .env,
// KEK, and reverse proxy. postgres-init only runs on first database init,
// so upgrades need just the compose file + manifest (varlatch upgrade).
const staging = mkdtempSync(join(tmpdir(), "varlatch-release-"));
try {
  const bundle = join(staging, `varlatch-${version}`);
  mkdirSync(bundle);
  writeFileSync(join(bundle, "docker-compose.yml"), release);
  // Ingress overlays (ADR-0035 D6): `varlatch setup --ingress` selects them.
  for (const name of OVERLAYS) writeFileSync(join(bundle, name), overlay(name));
  for (const entry of ["convex-supervisor.cjs", "postgres-init", ".env.example", "README.md"]) {
    cpSync(join(composeDir, entry), join(bundle, entry), { recursive: true });
  }
  for (const entry of ["LICENSE", "LICENSES", "THIRD-PARTY-NOTICES.md"]) {
    cpSync(join(repoRoot, entry), join(bundle, entry), { recursive: true });
  }
  writeFileSync(join(bundle, "varlatch-release.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  execFileSync("tar", ["-czf", join(outDir, `varlatch-compose-${version}.tar.gz`), "-C", staging, `varlatch-${version}`]);
} finally {
  rmSync(staging, { recursive: true, force: true });
}

// Operator CLI: the esbuild bundle from `pnpm build`. It embeds the backup
// compatibility manifest, so it must report exactly this release.
const cliBundle = join(repoRoot, "apps/cli/dist/varlatch.cjs");
if (!existsSync(cliBundle)) fail("apps/cli/dist/varlatch.cjs missing — run pnpm build first");
const cliVersion = execFileSync(process.execPath, [cliBundle, "--version"], { encoding: "utf8" }).trim();
if (!cliVersion.startsWith(`varlatch ${version} `)) fail(`CLI bundle reports "${cliVersion}", expected ${version}`);
const cliAsset = `varlatch-cli-${version}.cjs`;
cpSync(cliBundle, join(outDir, cliAsset));
cpSync(join(repoRoot, "THIRD-PARTY-NOTICES.md"), join(outDir, "THIRD-PARTY-NOTICES.md"));

const assets = ["varlatch-release.json", "docker-compose.release.yml", "convex-supervisor.cjs", ...OVERLAYS, `varlatch-compose-${version}.tar.gz`, cliAsset, "THIRD-PARTY-NOTICES.md"];
const sums = assets.map(name => `${createHash("sha256").update(readFileSync(join(outDir, name))).digest("hex")}  ${name}\n`).join("");
writeFileSync(join(outDir, "SHA256SUMS"), sums);

console.log(`Wrote ${assets.join(", ")}, SHA256SUMS for ${version}`);
