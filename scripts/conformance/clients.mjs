// SPDX-License-Identifier: Apache-2.0
/**
 * The client axis of a conformance run (scripts/conformance/README.md):
 * the CLI under test and the `packages/sdk` the sdk suite drives.
 *
 * `--cli source` is the CLI built from this checkout. `--cli <version>` is a
 * released CLI pinned in clients.json, downloaded from its GitHub release and
 * verified as docs/operations/verify-release.md says, failing closed:
 *
 *   1. cosign (the binary clients.json pins, checked by hash) verifies
 *      SHA256SUMS against the release's own workflow identity
 *      (release.yml@refs/tags/v<version>) and GitHub's OIDC issuer;
 *   2. SHA256SUMS lists the CLI asset exactly once, with the hash the
 *      download has, and that hash is the one clients.json pins;
 *   3. the CLI's `--version` reports the requested version.
 *
 * Only then is the CLI run by a suite. Each release file is downloaded into
 * a new, empty directory of its own.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  assetProblems,
  cliAsset,
  cosignBinaryFor,
  parseSha256Sums,
  releaseAssetUrl,
  releaseIdentity,
  validateClients,
  versionProblem,
} from "./lib/clients.mjs";

const HERE = new URL(".", import.meta.url).pathname;
const MAX_DOWNLOAD = 512 * 1024 * 1024;

export const sha256 = (data) => createHash("sha256").update(data).digest("hex");

export { cosign as cosignBinary };

export function loadClients() {
  const clients = JSON.parse(readFileSync(join(HERE, "clients.json"), "utf8"));
  const problems = validateClients(clients);
  if (problems.length > 0) throw new Error(`clients.json is not valid:\n  ${problems.join("\n  ")}`);
  return clients;
}

/** Downloads a URL (following redirects) into memory; any non-200 answer fails. */
async function download(url) {
  const res = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(300_000) });
  if (res.status !== 200) throw new Error(`downloading ${url} answered ${res.status}`);
  const length = Number(res.headers.get("content-length") ?? 0);
  if (length > MAX_DOWNLOAD) throw new Error(`${url} is ${length} bytes, more than the ${MAX_DOWNLOAD} allowed`);
  const body = Buffer.from(await res.arrayBuffer());
  if (body.length > MAX_DOWNLOAD) throw new Error(`${url} is more than ${MAX_DOWNLOAD} bytes`);
  return body;
}

/**
 * The pinned cosign binary, from the cache when its hash still matches,
 * otherwise downloaded from cosign's own release and checked by hash.
 */
async function cosign(clients, cacheDir, log, fetchFile = download) {
  const pin = cosignBinaryFor(clients, process.platform, process.arch);
  mkdirSync(cacheDir, { recursive: true });
  const path = join(cacheDir, `cosign-${pin.version}-${pin.key}-${pin.sha256.slice(0, 16)}`);
  if (existsSync(path) && sha256(readFileSync(path)) === pin.sha256) return path;
  const url = `https://github.com/sigstore/cosign/releases/download/v${pin.version}/${pin.asset}`;
  log(`--- downloading cosign ${pin.version} (${pin.asset})`);
  const body = await fetchFile(url);
  const actual = sha256(body);
  if (actual !== pin.sha256) throw new Error(`cosign ${pin.asset} has sha256 ${actual}, but clients.json pins ${pin.sha256}`);
  const partial = `${path}.${process.pid}.partial`;
  writeFileSync(partial, body, { mode: 0o755 });
  chmodSync(partial, 0o755);
  renameSync(partial, path);
  return path;
}

/** Where cosign is kept between runs. */
export function defaultCacheDir() {
  return process.env.CONFORMANCE_CACHE_DIR || join(process.env.XDG_CACHE_HOME || join(homedir(), ".cache"), "varlatch-conformance");
}

/** cosign verify-blob on SHA256SUMS, for one identity and issuer; returns `{ status, output }`. */
function cosignVerifyBlob({ cosignPath, sums, bundle, identity, issuer, cwd }) {
  const r = spawnSync(cosignPath, ["verify-blob", sums, "--bundle", bundle, "--certificate-identity", identity, "--certificate-oidc-issuer", issuer], {
    encoding: "utf8",
    cwd,
    timeout: 180_000,
    env: { PATH: process.env.PATH ?? "", HOME: cwd },
  });
  return { status: r.status, output: `${r.stderr ?? ""}${r.stdout ?? ""}${r.error ? String(r.error) : ""}` };
}

/**
 * cosign verify on one image by digest, for one identity and issuer, with
 * the signatures kept in `signatures` (COSIGN_REPOSITORY); returns
 * `{ status, output }`.
 */
function cosignVerifyImage({ cosignPath, image, identity, issuer, signatures, cwd }) {
  const r = spawnSync(cosignPath, ["verify", image, "--certificate-identity", identity, "--certificate-oidc-issuer", issuer], {
    encoding: "utf8",
    cwd,
    timeout: 300_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { PATH: process.env.PATH ?? "", HOME: cwd, COSIGN_REPOSITORY: signatures },
  });
  return { status: r.status, output: `${r.stderr ?? ""}${r.error ? String(r.error) : ""}` };
}

/**
 * Downloads release files into a new, empty directory and verifies them as
 * docs/operations/verify-release.md says, failing closed:
 *
 *   1. cosign (the pinned binary, checked by hash) verifies SHA256SUMS
 *      against the release's own identity (release.yml@refs/tags/v<version>)
 *      and GitHub's OIDC issuer;
 *   2. SHA256SUMS lists each asset exactly once, with the hash the download
 *      has, and, where `pins` names one, that hash is the pinned one.
 *
 * Returns `{ dir, files, hashes, verified, verifyImage }`: the path of each
 * file, each asset's verified sha256, the record a report keeps, and
 * `verifyImage(digestReference)`, which checks one image's signature for the
 * same identity (or throws).
 *
 * `deps` replaces the network and cosign in unit tests: `clients`,
 * `download(url)`, `verifyBlob(args)` and `verifyImage(args)`.
 */
export async function fetchVerifiedRelease(version, { assets, pins = {}, workDir, cacheDir = defaultCacheDir(), log = console.log, deps = {}, label = "Release" }) {
  const clients = deps.clients ?? loadClients();
  const fetchFile = deps.download ?? download;
  const verifyBlob = deps.verifyBlob ?? cosignVerifyBlob;
  const identity = releaseIdentity(clients.repository, version);
  log(`--- ${label} ${version}: downloading ${assets.join(", ")}, SHA256SUMS and its signature from ${clients.repository}`);
  // A new, empty directory for the release's files, and nothing else in it.
  const dir = mkdtempSync(join(workDir, `${label.toLowerCase()}-${version}-`));
  const files = {};
  for (const name of ["SHA256SUMS", "SHA256SUMS.sigstore.json", ...assets]) {
    files[name] = join(dir, name);
    writeFileSync(files[name], await fetchFile(releaseAssetUrl(clients.repository, version, name)), { mode: 0o600 });
  }
  const unexpected = readdirSync(dir).filter((f) => !(f in files));
  if (unexpected.length > 0) throw new Error(`unexpected files in ${dir}: ${unexpected.join(", ")}`);

  const needsCosign = !deps.verifyBlob || !deps.verifyImage;
  const cosignPath = needsCosign ? await cosign(clients, cacheDir, log, fetchFile) : null;
  const verify = verifyBlob({ cosignPath, sums: files.SHA256SUMS, bundle: files["SHA256SUMS.sigstore.json"], identity, issuer: clients.issuer, cwd: dir });
  if (verify.status !== 0) {
    throw new Error(`cosign could not verify SHA256SUMS of v${version} for ${identity}: ${verify.output.trim().slice(-600)}`);
  }
  const entries = parseSha256Sums(readFileSync(files.SHA256SUMS, "utf8"));
  const hashes = {};
  const problems = [];
  for (const asset of assets) {
    hashes[asset] = sha256(readFileSync(files[asset]));
    problems.push(...assetProblems({ entries, asset, actual: hashes[asset], pinned: pins[asset] }));
  }
  if (problems.length > 0) throw new Error(`${label} ${version} failed verification: ${problems.join("; ")}`);
  const checkImage = deps.verifyImage ?? cosignVerifyImage;
  const verifyImage = (image) => {
    const r = checkImage({ cosignPath, image, identity, issuer: clients.issuer, signatures: clients.imageSignatures, cwd: dir });
    if (r.status !== 0) throw new Error(`cosign could not verify ${image} for ${identity} (signatures in ${clients.imageSignatures}): ${r.output.trim().slice(-600)}`);
  };
  return {
    dir,
    files,
    hashes,
    verifyImage,
    verified: {
      repository: clients.repository,
      identity,
      issuer: clients.issuer,
      sha256sums: sha256(readFileSync(files.SHA256SUMS)),
      cosign: clients.cosign.version,
    },
  };
}

/**
 * The CLI under test. Returns `{ spec, path, version, sha256, commit,
 * verified }`; `version` and `commit` are null for `source`.
 *
 * `deps` replaces the network and cosign in unit tests: `clients` (the
 * parsed clients.json), `download(url)` and `verifyBlob(args)`.
 */
export async function resolveCli(spec, { repoRoot, workDir, cacheDir = defaultCacheDir(), log = console.log, deps = {} }) {
  if (spec === "source") {
    const path = join(repoRoot, "apps/cli/dist/varlatch.cjs");
    if (!existsSync(path)) throw new Error(`${path} does not exist: build the CLI first (pnpm build)`);
    return { spec, path, version: null, commit: null, sha256: sha256(readFileSync(path)), verified: null };
  }
  const clients = deps.clients ?? loadClients();
  const pinned = Object.hasOwn(clients.cli, spec) ? clients.cli[spec] : undefined;
  if (!pinned) {
    const error = new Error(`--cli ${spec}: not a pinned CLI; clients.json pins ${Object.keys(clients.cli).join(", ")} (or use --cli source)`);
    error.usage = true;
    throw error;
  }
  const version = spec;
  const asset = cliAsset(version);
  const release = await fetchVerifiedRelease(version, {
    assets: [asset],
    pins: { [asset]: pinned.sha256 },
    workDir,
    cacheDir,
    log,
    // Only SHA256SUMS is checked here: the CLI has no image.
    deps: { ...deps, clients, verifyImage: deps.verifyImage ?? (() => ({ status: 1, output: "no image" })) },
    label: "CLI",
  });
  const path = release.files[asset];

  // Only now, with every other check passed, run the downloaded CLI.
  const printed = spawnSync(process.execPath, [path, "--version"], {
    encoding: "utf8",
    cwd: release.dir,
    timeout: 60_000,
    env: { PATH: process.env.PATH ?? "", HOME: release.dir, VARLATCH_CONFIG_DIR: join(release.dir, "config"), VARLATCH_ASSISTED: "0" },
  });
  const wrong = printed.status === 0 ? versionProblem(printed.stdout, version) : `--version exited ${printed.status}: ${(printed.stderr || "").trim().slice(-300)}`;
  if (wrong) throw new Error(`CLI ${version}: ${wrong}`);
  log(`--- CLI ${version}: verified (signed SHA256SUMS for ${release.verified.identity}; sha256 ${release.hashes[asset]}; ${printed.stdout.trim()})`);
  return {
    spec,
    path,
    version,
    commit: pinned.commit,
    sha256: release.hashes[asset],
    verified: { ...release.verified, versionOutput: printed.stdout.trim() },
  };
}

function git(repoRoot, args, options = {}) {
  return spawnSync("git", args, { cwd: repoRoot, maxBuffer: 512 * 1024 * 1024, ...options });
}

/**
 * Bundles `packages/sdk` into one ES module for the sdk suite: from this
 * checkout for `--cli source`, otherwise from the pinned release's commit
 * (its own sources, fetched by hash when a shallow checkout lacks it, as
 * apps/cli/test/controlCli.ts builds the 0.13.0 CLI), with this checkout's
 * third-party dependencies. Returns `{ path, commit, sha256 }`.
 */
export async function buildSdk(cli, { repoRoot, workDir }) {
  const require = createRequire(join(repoRoot, "apps", "cli", "package.json"));
  const { build } = require("esbuild");
  let sourceRoot = repoRoot;
  if (cli.commit) {
    const have = () => git(repoRoot, ["cat-file", "-e", `${cli.commit}^{commit}`]).status === 0;
    for (let attempt = 0; attempt < 3 && !have(); attempt++) git(repoRoot, ["fetch", "--quiet", "--depth=1", "origin", cli.commit]);
    if (!have()) throw new Error(`the sdk of CLI ${cli.version} needs commit ${cli.commit}: git fetch origin ${cli.commit}`);
    sourceRoot = mkdtempSync(join(workDir, `sdk-${cli.version}-`));
    const archive = git(repoRoot, ["archive", "--format=tar", cli.commit, "packages"]);
    if (archive.status !== 0) throw new Error(`git archive ${cli.commit} failed: ${String(archive.stderr).trim()}`);
    const untar = spawnSync("tar", ["-x", "-C", sourceRoot], { input: archive.stdout });
    if (untar.status !== 0) throw new Error(`extracting the sdk sources failed: ${String(untar.stderr).trim()}`);
  }
  const workspace = {
    name: "conformance-sdk-workspace",
    setup(b) {
      b.onResolve({ filter: /^@varlatch\// }, (args) => {
        const [, pkg, sub] = /^@varlatch\/([^/]+)(?:\/(.+))?$/.exec(args.path) ?? [];
        const candidate = join(sourceRoot, "packages", pkg ?? "", "src", `${sub ?? "index"}.ts`);
        if (!existsSync(candidate)) return { errors: [{ text: `${args.path} has no source at ${candidate}` }] };
        return { path: candidate };
      });
    },
  };
  const nodePaths = [join(repoRoot, "node_modules"), ...readdirSync(join(repoRoot, "packages")).map((p) => join(repoRoot, "packages", p, "node_modules"))].filter(existsSync);
  const outfile = join(workDir, `sdk-${cli.version ?? "source"}.mjs`);
  rmSync(outfile, { force: true });
  await build({
    entryPoints: [join(sourceRoot, "packages", "sdk", "src", "index.ts")],
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node22",
    outfile,
    nodePaths,
    plugins: [workspace],
    // Paths in the bundle's comments are relative to the sources, so the
    // same commit gives the same bytes wherever it was extracted.
    absWorkingDir: sourceRoot,
    logLevel: "silent",
  });
  return { path: outfile, commit: cli.commit, sha256: sha256(readFileSync(outfile)) };
}
