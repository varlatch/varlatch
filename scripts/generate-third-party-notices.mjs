#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * THIRD-PARTY-NOTICES.md generator (ADR-0037 D1). Lists every third-party
 * runtime component of the release set with its version and license:
 *
 *   - the container images the canonical compose file and its ingress
 *     overlays run, with the pins they use;
 *   - the base images Varlatch's own images are built from;
 *   - the npm packages each shipped artifact contains: the varlatchd image
 *     (read from an actual `pnpm deploy --prod`, exactly as its Dockerfile
 *     runs it), the operator CLI bundle, the dashboard bundle, and the
 *     convex-deploy image (`npm ci` from convex/package-lock.json).
 *
 * License texts are copied from each pnpm-installed package's own license
 * file, because bundling (the CLI and dashboard) strips those files.
 *
 * Usage:
 *   generate-third-party-notices.mjs            write THIRD-PARTY-NOTICES.md
 *   generate-third-party-notices.mjs --check    fail if it is out of date
 *
 * Requires `pnpm install`. Platform-specific packages (`os`/`cpu` in their
 * package.json) are native build tooling that no bundle contains; they are
 * skipped so the output is identical on every development platform.
 */
import { execFileSync } from "node:child_process";
import { existsSync, lstatSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const OUTPUT = join(repoRoot, "THIRD-PARTY-NOTICES.md");
const check = process.argv.includes("--check");

function fail(message) {
  console.error(message);
  process.exit(1);
}

// Licenses of third-party images, by repository. A new image in the compose
// files fails generation until someone records its license here.
const IMAGE_LICENSES = {
  postgres: { name: "PostgreSQL", license: "PostgreSQL", source: "https://www.postgresql.org/about/licence/" },
  "ghcr.io/get-convex/convex-backend": {
    name: "Convex backend",
    license: "FSL-1.1-Apache-2.0",
    source: "https://github.com/get-convex/convex-backend/blob/main/LICENSE.md",
  },
  caddy: { name: "Caddy", license: "Apache-2.0", source: "https://github.com/caddyserver/caddy/blob/master/LICENSE" },
  "tailscale/tailscale": { name: "Tailscale", license: "BSD-3-Clause", source: "https://github.com/tailscale/tailscale/blob/main/LICENSE" },
};
const BASE_IMAGE_LICENSES = {
  node: {
    license: "MIT (Node.js)",
    contents: "Node.js, whose LICENSE lists the components it bundles, on Debian; Debian packages are under their own licenses",
  },
  nginx: {
    license: "BSD-2-Clause (nginx)",
    contents: "nginx on Alpine Linux; Alpine packages are under their own licenses",
  },
};
const COMPOSE_FILES = ["docker-compose.yml", "docker-compose.caddy.yml", "docker-compose.tailscale.yml"];
const DOCKERFILES = {
  "services/varlatchd/Dockerfile": "varlatchd",
  "apps/web/Dockerfile": "varlatch-web",
  "infra/compose/convex-deploy.Dockerfile": "convex-deploy",
};

function images() {
  const found = new Map();
  for (const file of COMPOSE_FILES) {
    const text = readFileSync(join(repoRoot, "infra/compose", file), "utf8");
    for (const [, ref] of text.matchAll(/^\s+image:\s*(\S+)\s*$/gm)) {
      const at = ref.indexOf("@");
      const named = at < 0 ? ref : ref.slice(0, at);
      const colon = named.lastIndexOf(":");
      const repo = colon > named.lastIndexOf("/") ? named.slice(0, colon) : named;
      const entry = IMAGE_LICENSES[repo];
      if (!entry) fail(`No license recorded for image ${repo} (${file}); add it to IMAGE_LICENSES`);
      found.set(repo, { ...entry, ref, file });
    }
  }
  return [...found.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function baseImages() {
  const found = new Map();
  for (const [file, image] of Object.entries(DOCKERFILES)) {
    const text = readFileSync(join(repoRoot, file), "utf8");
    const stages = new Set();
    for (const [, ref, stage] of text.matchAll(/^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/gim)) {
      if (stage) stages.add(stage);
      if (stages.has(ref) && ref !== stage) continue;
      const repo = ref.split("@")[0].split(":")[0];
      if (IMAGE_LICENSES[repo]) continue; // a runtime image, listed above
      const entry = BASE_IMAGE_LICENSES[repo];
      if (!entry) fail(`No license recorded for base image ${ref} (${file}); add it to BASE_IMAGE_LICENSES`);
      const current = found.get(ref) ?? { ref, ...entry, usedBy: new Set() };
      current.usedBy.add(image);
      found.set(ref, current);
    }
  }
  return [...found.values()].sort((a, b) => a.ref.localeCompare(b.ref));
}

// ---- npm packages --------------------------------------------------------

// The bundles: each artifact's production dependency closure.
const ARTIFACTS = [
  { label: "CLI", filter: "@varlatch/cli..." },
  { label: "dashboard", filter: "@varlatch/web..." },
];

const packages = new Map(); // "name@version" -> { name, version, license, path, shippedIn }
const key = (name, version) => `${name}@${version}`;

function record(name, version, license, path, label) {
  const id = key(name, version);
  const current = packages.get(id) ?? { name, version, license, path, shippedIn: new Set() };
  current.path ??= path;
  current.shippedIn.add(label);
  packages.set(id, current);
}

function platformSpecific(path) {
  const manifest = JSON.parse(readFileSync(join(path, "package.json"), "utf8"));
  return Boolean(manifest.os || manifest.cpu);
}

function declaredLicense(manifest) {
  if (typeof manifest.license === "string") return manifest.license;
  if (manifest.license?.type) return manifest.license.type;
  if (Array.isArray(manifest.licenses)) return manifest.licenses.map(l => l.type ?? l).join(" OR ");
  return "UNKNOWN";
}

// The varlatchd image: what `pnpm deploy --prod` really installs, optional
// dependencies and resolved peers included. Kept until the texts are read.
const deployDir = mkdtempSync(join(tmpdir(), "varlatch-notices-"));
process.on("exit", () => rmSync(deployDir, { recursive: true, force: true }));
execFileSync("pnpm", ["--filter", "@varlatch/varlatchd", "--prod", "deploy", join(deployDir, "out")], {
  cwd: repoRoot,
  stdio: "ignore",
});
const virtualStore = join(deployDir, "out/node_modules/.pnpm");
for (const entry of readdirSync(virtualStore)) {
  const modules = join(virtualStore, entry, "node_modules");
  if (!existsSync(modules)) continue;
  for (const name of readdirSync(modules)) {
    const names = name.startsWith("@") ? readdirSync(join(modules, name)).map(sub => `${name}/${sub}`) : [name];
    for (const packageName of names) {
      const path = join(modules, packageName);
      if (lstatSync(path).isSymbolicLink() || packageName.startsWith("@varlatch/")) continue;
      const manifest = JSON.parse(readFileSync(join(path, "package.json"), "utf8"));
      if (!platformSpecific(path)) record(manifest.name, manifest.version, declaredLicense(manifest), path, "varlatchd");
    }
  }
}

for (const { label, filter } of ARTIFACTS) {
  const json = execFileSync("pnpm", ["licenses", "list", "--prod", "--json", "--filter", filter], {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  for (const [license, entries] of Object.entries(JSON.parse(json))) {
    for (const entry of entries) {
      if (entry.versions.length !== entry.paths.length) fail(`pnpm reported mismatched paths for ${entry.name}`);
      entry.versions.forEach((version, i) => {
        if (!platformSpecific(entry.paths[i])) record(entry.name, version, license, entry.paths[i], label);
      });
    }
  }
}

// convex-deploy installs with `npm ci --omit=dev`, so its contents come from
// the lock. Its images target linux/amd64 and linux/arm64.
const lock = JSON.parse(readFileSync(join(repoRoot, "convex/package-lock.json"), "utf8"));
const convexManifest = JSON.parse(readFileSync(join(repoRoot, "convex/package.json"), "utf8"));
for (const field of ["dependencies", "devDependencies"]) {
  if (JSON.stringify(lock.packages[""][field] ?? {}) !== JSON.stringify(convexManifest[field] ?? {})) {
    fail(`convex/package-lock.json ${field} differ from convex/package.json: run \`npm install --package-lock-only\` in convex/`);
  }
}
for (const [path, entry] of Object.entries(lock.packages)) {
  if (!path || entry.dev) continue;
  if (entry.os && !entry.os.includes("linux")) continue;
  if (entry.cpu && !entry.cpu.some(cpu => cpu === "x64" || cpu === "arm64")) continue;
  if (entry.libc && !entry.libc.includes("glibc")) continue; // node:26-slim is Debian
  const name = entry.name ?? path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
  if (!entry.license) fail(`convex/package-lock.json has no license for ${name}@${entry.version}`);
  const known = packages.get(key(name, entry.version));
  record(name, entry.version, entry.license, known?.path, "convex-deploy");
}

// ---- license texts -------------------------------------------------------

const LICENSE_FILE = /^(licen[cs]e|copying|unlicense)(\.(md|txt|markdown))?$/i;

function licenseText(path) {
  if (!path || !existsSync(path)) return null;
  const files = readdirSync(path).filter(name => LICENSE_FILE.test(name)).sort();
  if (files.length === 0) return null;
  return files
    .map(name => readFileSync(join(path, name), "utf8").replace(/\r\n?/g, "\n").replace(/[ \t]+$/gm, "").trim())
    .join("\n\n");
}

const sorted = [...packages.values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
const texts = new Map(); // text -> [ids]
const withoutFile = [];
const npmOnly = [];
for (const pkg of sorted) {
  const text = licenseText(pkg.path);
  const id = key(pkg.name, pkg.version);
  if (text) texts.set(text, [...(texts.get(text) ?? []), id]);
  else if (pkg.path) withoutFile.push(pkg);
  else npmOnly.push(pkg);
}

// ---- output --------------------------------------------------------------

const ORDER = ["varlatchd", "CLI", "dashboard", "convex-deploy"];
const shipped = pkg => ORDER.filter(label => pkg.shippedIn.has(label)).join(", ");
const cell = value => String(value).replaceAll("|", "\\|");

const lines = [];
const out = line => lines.push(line);

out("# Third-party notices");
out("");
out("<!-- Generated by scripts/generate-third-party-notices.mjs; do not edit.");
out("     `pnpm notices:check` fails when this file drifts from the release set. -->");
out("");
out("Varlatch's own code is covered by [LICENSE](LICENSE). A Varlatch release");
out("also runs, or contains, the third-party components below. Each is under");
out("its own license.");
out("");
out("**The Convex backend is source-available, not open source.** It is");
out("licensed under FSL-1.1-Apache-2.0: internal use is permitted, making it");
out("available to others as a competing commercial product or service is not,");
out("and each version becomes Apache-2.0 two years after its release.");
out("Self-hosting Varlatch for your own organization is internal use. The");
out("Convex client library and CLI (`convex` on npm) are Apache-2.0.");
out("");
out("## Container images the release runs");
out("");
out("| Component | Image | License |");
out("| --- | --- | --- |");
for (const image of images()) out(`| ${image.name} | \`${image.ref}\` | [${image.license}](${image.source}) |`);
out("");
out("The release manifest (`varlatch-release.json`) pins each of these by digest.");
out("");
out("## Base images of Varlatch's images");
out("");
out("| Base image | Used by | License | Contents |");
out("| --- | --- | --- | --- |");
for (const base of baseImages()) {
  out(`| \`${base.ref}\` | ${[...base.usedBy].sort().join(", ")} | ${base.license} | ${base.contents} |`);
}
out("");
out("The convex-deploy image also contains `generate_key` from the Convex");
out("backend image above, under the same FSL-1.1-Apache-2.0 license.");
out("");
out("## npm packages");
out("");
out("\"Shipped in\" names the artifact that contains each package: the");
out("**varlatchd** image, the operator **CLI** bundle (a release asset, also");
out("inside the varlatchd image), the **dashboard** bundle in the varlatch-web");
out("image, and the **convex-deploy** image. For the CLI and the dashboard the");
out("list is each artifact's full production dependency closure, a superset of");
out("what the bundler includes.");
out("");
out("| Package | Version | License | Shipped in |");
out("| --- | --- | --- | --- |");
for (const pkg of sorted) out(`| ${cell(pkg.name)} | ${pkg.version} | ${cell(pkg.license)} | ${shipped(pkg)} |`);
out("");
out("## License texts");
out("");
out("Copied from each package's own license file. Identical texts are listed");
out("once, with every package that uses them.");
if (npmOnly.length > 0) {
  out("Packages only in the convex-deploy image keep their license files in the");
  out("image, under `/app/node_modules`.");
}
out("");
const groups = [...texts.entries()].sort((a, b) => a[1][0].localeCompare(b[1][0]));
for (const [text, ids] of groups) {
  out(`### ${ids.join(", ")}`);
  out("");
  out("````text");
  out(text);
  out("````");
  out("");
}
if (withoutFile.length > 0) {
  out("### Packages that ship no license file");
  out("");
  out("These packages declare their license in `package.json` only.");
  out("");
  for (const pkg of withoutFile) out(`- ${pkg.name} ${pkg.version}: ${pkg.license}`);
  out("");
}

const generated = `${lines.join("\n").replace(/\n+$/, "")}\n`;
if (check) {
  const current = existsSync(OUTPUT) ? readFileSync(OUTPUT, "utf8") : "";
  if (current !== generated) {
    fail("THIRD-PARTY-NOTICES.md is out of date: run `pnpm notices:generate` and commit the result");
  }
  console.log(`THIRD-PARTY-NOTICES.md is current (${sorted.length} npm packages)`);
} else {
  writeFileSync(OUTPUT, generated);
  console.log(`Wrote THIRD-PARTY-NOTICES.md (${sorted.length} npm packages, ${groups.length} license texts)`);
}
