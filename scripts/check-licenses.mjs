#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Enforces the repository's license map (ADR-0021): the Secret Plane
 * daemon, the dashboard, and the Application Plane functions are
 * AGPL-3.0-or-later, and so are the Go rewrite's daemon packages
 * (go/server/, go/cmd/varlatchd/; ADR-0059); everything else is Apache-2.0.
 *
 *   - every source file carries the SPDX-License-Identifier of its directory;
 *   - every workspace package.json declares that license;
 *   - every workspace package, and every Go license root, has a LICENSE file
 *     with its full text, identical to the one in LICENSES/;
 *   - every release image declares Varlatch's licenses in its OCI label.
 *
 * Usage:
 *   check-licenses.mjs          fail on any deviation
 *   check-licenses.mjs --fix    add missing headers, fields, and files
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const fix = process.argv.includes("--fix");

const AGPL = "AGPL-3.0-or-later";
const APACHE = "Apache-2.0";
// go/licensing_test.go keeps the Go import graph inside the same map.
const AGPL_DIRS = ["services/varlatchd/", "apps/web/", "convex/", "go/server/", "go/cmd/varlatchd/"];
// The Go module has no package.json; these directories carry its LICENSE files.
const GO_LICENSE_ROOTS = ["go/", "go/server/", "go/cmd/varlatchd/"];
const licenseOf = path => (AGPL_DIRS.some(dir => path.startsWith(dir)) ? AGPL : APACHE);

// Third-party code ported into a file (scripts/third-party-code.json) keeps
// its own license as well: that file's SPDX expression is the directory's
// license AND the third-party one, and no other file may name a second
// license. The notices generator lists the same entries.
const portedCode = JSON.parse(readFileSync(join(repoRoot, "scripts/third-party-code.json"), "utf8")).entries;
const portedLicense = new Map(portedCode.flatMap(entry => entry.files.map(file => [file, entry.license])));
const expectedOf = path => (portedLicense.has(path) ? `${licenseOf(path)} AND ${portedLicense.get(path)}` : licenseOf(path));

// Not hand-written: byte-exact copies of published releases, and generator
// output.
const EXCLUDED = [/^scripts\/fixtures\//, /(^|\/)(dist|node_modules|generated|_generated)\//];
const SOURCE = /\.(ts|tsx|js|mjs|cjs|sh|py|go)$/;

const tracked = execFileSync("git", ["ls-files", "-z"], { cwd: repoRoot, encoding: "utf8" })
  .split("\0")
  .filter(Boolean);
const problems = [];

for (const path of tracked) {
  if (!SOURCE.test(path) || EXCLUDED.some(pattern => pattern.test(path))) continue;
  const expected = expectedOf(path);
  const text = readFileSync(join(repoRoot, path), "utf8");
  const lines = text.split("\n");
  const shebang = lines[0].startsWith("#!") ? 1 : 0;
  // The whole expression, to the end of its line (a compound one included).
  const found = lines.slice(0, shebang + 3).join("\n").match(/SPDX-License-Identifier: ([^\n]*?)\s*(?:\*\/)?\s*$/m);
  if (found?.[1] === expected) continue;
  if (found) {
    problems.push(`${path}: declares ${found[1]}, its directory is ${expected}`);
    continue;
  }
  if (!fix) {
    problems.push(`${path}: missing SPDX-License-Identifier: ${expected}`);
    continue;
  }
  const comment = path.endsWith(".sh") || path.endsWith(".py") ? "#" : "//";
  lines.splice(shebang, 0, `${comment} SPDX-License-Identifier: ${expected}`);
  writeFileSync(join(repoRoot, path), lines.join("\n"));
}

for (const entry of portedCode) {
  for (const file of entry.files) {
    if (!tracked.includes(file)) problems.push(`scripts/third-party-code.json: ${entry.name} names ${file}, which is not tracked`);
  }
  if (!tracked.includes(entry.licenseFile)) problems.push(`scripts/third-party-code.json: ${entry.name}'s license file ${entry.licenseFile} is not tracked`);
}

const fullText = {
  [AGPL]: readFileSync(join(repoRoot, "LICENSES", `${AGPL}.txt`), "utf8"),
  [APACHE]: readFileSync(join(repoRoot, "LICENSES", `${APACHE}.txt`), "utf8"),
};
for (const path of tracked.filter(path => path.endsWith("package.json") && path !== "package.json")) {
  if (EXCLUDED.some(pattern => pattern.test(path))) continue;
  const dir = dirname(path);
  const expected = licenseOf(`${dir}/`);
  const manifestText = readFileSync(join(repoRoot, path), "utf8");
  const manifest = JSON.parse(manifestText);
  if (manifest.license !== expected) {
    if (fix) {
      writeFileSync(join(repoRoot, path), manifestText.replace(/"license": "[^"]*"/, `"license": "${expected}"`));
    } else {
      problems.push(`${path}: license is ${manifest.license ?? "(none)"}, expected ${expected}`);
    }
  }
  const licenseFile = join(repoRoot, dir, "LICENSE");
  if (!existsSync(licenseFile) || readFileSync(licenseFile, "utf8") !== fullText[expected]) {
    if (fix) writeFileSync(licenseFile, fullText[expected]);
    else problems.push(`${dir}/LICENSE: missing or not the ${expected} text from LICENSES/`);
  }
}

const goModule = tracked.includes("go/go.mod");
for (const dir of goModule ? GO_LICENSE_ROOTS : []) {
  const expected = licenseOf(dir);
  const licenseFile = join(repoRoot, dir, "LICENSE");
  if (!existsSync(licenseFile) || readFileSync(licenseFile, "utf8") !== fullText[expected]) {
    if (fix) writeFileSync(licenseFile, fullText[expected]);
    else problems.push(`${dir}LICENSE: missing or not the ${expected} text from LICENSES/`);
  }
}

// The label names Varlatch's own licenses; THIRD-PARTY-NOTICES.md, copied
// into each image, covers the third-party contents.
const IMAGE_LICENSES = `${AGPL} AND ${APACHE}`;
for (const path of ["services/varlatchd/Dockerfile", "apps/web/Dockerfile", "infra/compose/convex-deploy.Dockerfile"]) {
  const label = readFileSync(join(repoRoot, path), "utf8").match(/org\.opencontainers\.image\.licenses="([^"]*)"/);
  if (label?.[1] !== IMAGE_LICENSES) problems.push(`${path}: needs LABEL org.opencontainers.image.licenses="${IMAGE_LICENSES}"`);
}

if (problems.length > 0) {
  console.error(problems.join("\n"));
  console.error(`\n${problems.length} license problem(s); \`pnpm license:fix\` repairs missing headers, fields, and files.`);
  process.exit(1);
}
console.log(fix ? "License map applied" : "Every file and package matches the license map");
