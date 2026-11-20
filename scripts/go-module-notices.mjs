// SPDX-License-Identifier: Apache-2.0
/**
 * The Go part of THIRD-PARTY-NOTICES.md (ADR-0037 D1, ADR-0059): every Go
 * module linked into `varlatch` and `varlatchd` for the platforms a release
 * builds them for, with its license and license texts, and the Go standard
 * library and runtime both binaries contain.
 *
 * The modules come from the Go toolchain alone: `go list -deps` of each
 * command for each release platform, CGO off, as go/release/build-assets.sh
 * builds them. Their license texts are each module's own license files
 * (LICENSE, COPYING, NOTICE, PATENTS and their variants) in the module
 * cache.
 *
 * Each module's license is recorded by hand in scripts/go-module-licenses.json,
 * after reading its texts: the SPDX expression and the SHA-256 of the texts
 * as listed here. A module that is not recorded, or whose texts changed
 * (an upgrade), stops generation until someone reads them again and updates
 * the record (`--go-hashes` prints each module's hash). So is a license
 * outside PERMISSIVE: whether it is compatible with Varlatch's licenses
 * (ADR-0021: varlatch Apache-2.0, varlatchd AGPL-3.0-or-later) is the
 * owner's decision, not this script's.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

/** The platforms a release builds each command for (go/release/build-assets.sh). */
export const GO_RELEASE_PLATFORMS = {
  varlatch: ["linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64", "windows/arm64"],
  varlatchd: ["linux/amd64", "linux/arm64"],
};

/**
 * Licenses whose terms are met by listing the component with its texts,
 * compatible with both binaries' licenses. Anything else is reported for
 * the owner. LicenseRef-Public-Domain is a dedication to the public domain
 * (SQLite's).
 */
const PERMISSIVE = new Set([
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "ISC",
  "MIT",
  "0BSD",
  "CC0-1.0",
  "Unlicense",
  "LicenseRef-Public-Domain",
]);

const LICENSE_FILE = /^(licen[cs]e|copying|notice|unlicense|patents)([-._][^/]*)?$/i;

function go(args, goDir, env = {}) {
  try {
    return execFileSync("go", args, {
      cwd: goDir,
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
      env: { ...process.env, CGO_ENABLED: "0", GOFLAGS: "-mod=readonly", ...env },
    });
  } catch (err) {
    if (err.code === "ENOENT") {
      throw new Error("the Go toolchain is needed to list the Go modules (go/go.mod's version, on PATH as `go`)");
    }
    throw err;
  }
}

const normalize = text => text.replace(/\r\n?/g, "\n").replace(/[ \t]+$/gm, "").trim();

/** A module's license files, each under its own name, as one text. */
function moduleTexts(dir) {
  const files = readdirSync(dir)
    .filter(name => LICENSE_FILE.test(name) && !name.endsWith(".go") && statSync(join(dir, name)).isFile())
    .sort();
  if (files.length === 0) return null;
  if (files.length === 1) return normalize(readFileSync(join(dir, files[0]), "utf8"));
  return files.map(name => `--- ${name} ---\n\n${normalize(readFileSync(join(dir, name), "utf8"))}`).join("\n\n");
}

/** The SPDX ids of an expression of ids joined by AND or OR. */
function ids(expression) {
  return expression.split(/\s+(?:AND|OR)\s+/).map(id => id.replace(/^\(|\)$/g, ""));
}

/** The modules each command links, by `path@version`, with their directory. */
function linkedModules(goDir) {
  const modules = new Map(); // "path@version" -> { path, version, dir, linkedInto: Set }
  for (const [command, platforms] of Object.entries(GO_RELEASE_PLATFORMS)) {
    for (const platform of platforms) {
      const [GOOS, GOARCH] = platform.split("/");
      const listed = go(
        ["list", "-deps", "-f", "{{with .Module}}{{if not .Main}}{{.Path}}\t{{.Version}}\t{{.Dir}}\t{{with .Replace}}{{.Path}}@{{.Version}}{{end}}{{end}}{{end}}", `./cmd/${command}`],
        goDir,
        { GOOS, GOARCH },
      );
      for (const line of listed.split("\n")) {
        if (!line) continue;
        const [path, version, dir, replace] = line.split("\t");
        if (replace) throw new Error(`go.mod replaces ${path} with ${replace}: list the replacement's license before releasing`);
        const id = `${path}@${version}`;
        const current = modules.get(id) ?? { path, version, dir, linkedInto: new Set() };
        current.linkedInto.add(command);
        modules.set(id, current);
      }
    }
  }
  return [...modules.values()].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

/**
 * The Go modules, checked against their records. Returns { modules, stdlib }
 * or throws with every problem found, for a person to resolve.
 */
export function goModuleNotices(repoRoot, { hashesOnly = false } = {}) {
  const goDir = join(repoRoot, "go");
  const recorded = JSON.parse(readFileSync(join(repoRoot, "scripts/go-module-licenses.json"), "utf8")).modules;
  const problems = [];
  const modules = linkedModules(goDir).map(module => {
    const text = module.dir && existsSync(module.dir) ? moduleTexts(module.dir) : null;
    if (!text) problems.push(`${module.path}@${module.version} has no license file in its module`);
    const sha256 = text ? createHash("sha256").update(text).digest("hex") : "";
    const record = recorded[module.path];
    if (hashesOnly) return { ...module, text, sha256 };
    if (!record) {
      problems.push(`${module.path}@${module.version} is not in scripts/go-module-licenses.json: read its license files and record its license and sha256 (${sha256})`);
    } else if (record.sha256 !== sha256) {
      problems.push(`${module.path}@${module.version}'s license files changed: read them again and update its record (sha256 ${sha256})`);
    } else {
      for (const id of ids(record.license)) {
        if (!PERMISSIVE.has(id)) {
          problems.push(`${module.path} is under ${record.license}, linked into ${[...module.linkedInto].sort().join(" and ")}: ${id} needs the owner's decision`);
        }
      }
    }
    return { ...module, license: record?.license, text, sha256 };
  });
  if (!hashesOnly) {
    const linked = new Set(modules.map(m => m.path));
    for (const path of Object.keys(recorded)) {
      if (!linked.has(path)) problems.push(`scripts/go-module-licenses.json records ${path}, which no release binary links: remove it`);
    }
  }
  if (problems.length > 0) throw new Error(`Go modules:\n- ${problems.join("\n- ")}`);
  const goroot = go(["env", "GOROOT"], goDir).trim();
  const stdlib = normalize(readFileSync(join(goroot, "LICENSE"), "utf8"));
  return { modules, stdlib };
}
