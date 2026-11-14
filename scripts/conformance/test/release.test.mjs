// SPDX-License-Identifier: Apache-2.0
/**
 * The ts-release target: which releases can be selected, the bundle and
 * manifest rules, the Compose file's images, and the verification of a
 * release, each failure path failing closed before anything runs. The
 * network and cosign are replaced; nothing here downloads anything.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { sha256 } from "../clients.mjs";
import {
  bundleAsset,
  bundleListingProblems,
  composeImageProblems,
  digestReference,
  manifestProblems,
  releaseVersionProblem,
} from "../lib/release.mjs";
import { loadTarget } from "../targets/index.mjs";
import { verifyRelease } from "../targets/ts-release.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const clientsJson = JSON.parse(readFileSync(join(here, "..", "clients.json"), "utf8"));
const D = (c) => `sha256:${c.repeat(64)}`;

test("only a signed release can be selected: 0.15.1 and later, by x.y.z", () => {
  assert.equal(releaseVersionProblem("0.22.0"), null);
  assert.equal(releaseVersionProblem("0.15.1"), null);
  assert.match(releaseVersionProblem("0.15.0"), /releases before 0\.15\.1 are not signed and cannot be selected/);
  assert.match(releaseVersionProblem("0.7.0"), /not signed/);
  assert.match(releaseVersionProblem("latest"), /ts-release needs a version/);
  assert.match(releaseVersionProblem(""), /ts-release needs a version/);
  assert.match(releaseVersionProblem(undefined), /ts-release needs a version/);
});

test("the bundle holds only files and directories under its own directory", () => {
  const ok = ["varlatch-0.22.0/", "varlatch-0.22.0/docker-compose.yml", "varlatch-0.22.0/postgres-init/01-init.sh"];
  assert.deepEqual(bundleListingProblems(ok, ["d", "-", "-"], "0.22.0"), []);
  assert.match(bundleListingProblems([...ok, "varlatch-0.22.0/x"], ["d", "-", "-", "l"], "0.22.0").join(), /varlatch-0\.22\.0\/x, which is not a regular file/);
  assert.match(bundleListingProblems(["varlatch-0.22.0/../etc/passwd"], ["-"], "0.22.0").join(), /outside varlatch-0\.22\.0\//);
  assert.match(bundleListingProblems(["/etc/passwd"], ["-"], "0.22.0").join(), /outside/);
  assert.match(bundleListingProblems(["varlatch-0.21.0/docker-compose.yml"], ["-"], "0.22.0").join(), /outside varlatch-0\.22\.0\//);
  assert.match(bundleListingProblems(["varlatch-0.22.0x/a"], ["-"], "0.22.0").join(), /outside/);
  assert.match(bundleListingProblems([], [], "0.22.0").join(), /empty/);
  assert.match(bundleListingProblems(ok, ["d", "-"], "0.22.0").join(), /listings disagree/);
});

const manifest = (version = "0.22.0") => ({
  version,
  images: {
    varlatchd: { digest: `ghcr.io/varlatch/varlatchd@${D("1")}` },
    "varlatch-web": { digest: `ghcr.io/varlatch/varlatch-web@${D("2")}` },
    "convex-deploy": { digest: `ghcr.io/varlatch/varlatch-convex-deploy@${D("3")}` },
    postgres: { digest: `docker.io/library/postgres@${D("4")}` },
  },
});

test("the manifest is for the version, and pins Varlatch's images (and every other) by digest", () => {
  assert.deepEqual(manifestProblems(manifest(), "0.22.0"), []);
  assert.match(manifestProblems(manifest("0.21.0"), "0.22.0").join(), /is for "0\.21\.0", not 0\.22\.0/);
  const missing = manifest();
  delete missing.images["varlatch-web"];
  assert.match(manifestProblems(missing, "0.22.0").join(), /pins no varlatch-web image/);
  const tagged = manifest();
  tagged.images.postgres.digest = "docker.io/library/postgres:17.6";
  assert.match(manifestProblems(tagged, "0.22.0").join(), /postgres is not pinned by digest/);
  assert.match(manifestProblems(null, "0.22.0").join(), /not a JSON object/);
});

test("a Compose image reference, with or without its tag, compared by name and digest", () => {
  assert.equal(digestReference(`ghcr.io/varlatch/varlatchd:0.22.0@${D("1")}`), `ghcr.io/varlatch/varlatchd@${D("1")}`);
  assert.equal(digestReference(`localhost:5000/x@${D("1")}`), `localhost:5000/x@${D("1")}`);
  assert.equal(digestReference(`localhost:5000/x:1@${D("1")}`), `localhost:5000/x@${D("1")}`);
  assert.equal(digestReference("postgres:17.6"), null);
  assert.equal(digestReference(undefined), null);
});

test("the bundle's Compose file runs only images the manifest pins, by digest, and builds nothing", () => {
  const services = {
    varlatchd: { image: `ghcr.io/varlatch/varlatchd:0.22.0@${D("1")}` },
    "varlatch-migrate": { image: `ghcr.io/varlatch/varlatchd:0.22.0@${D("1")}` },
    postgres: { image: `docker.io/library/postgres:17.6@${D("4")}` },
  };
  assert.deepEqual(composeImageProblems(services, manifest()), []);
  assert.match(composeImageProblems({ ...services, x: { image: "busybox:latest" } }, manifest()).join(), /x runs "busybox:latest", which is not pinned by digest/);
  assert.match(composeImageProblems({ ...services, x: { image: `ghcr.io/varlatch/varlatchd@${D("9")}` } }, manifest()).join(), /does not pin/);
  assert.match(composeImageProblems({ ...services, varlatchd: { ...services.varlatchd, build: { context: "." } } }, manifest()).join(), /built from source/);
  assert.match(composeImageProblems({}, manifest()).join(), /no services/);
});

test("targets: ts-release needs a version, go-binary a path, ts-source nothing; each has its expectations key", async () => {
  const release = await loadTarget("ts-release:0.22.0");
  assert.equal(release.argument, "0.22.0");
  assert.equal(release.expectKey, "ts-release:0.22.0");
  assert.equal((await loadTarget("ts-source")).expectKey, "ts-source");
  assert.equal((await loadTarget("go-binary:/opt/varlatchd")).expectKey, "go-binary");
  await assert.rejects(loadTarget("ts-release"), /needs an argument: ts-release:<version>/);
  await assert.rejects(loadTarget("go-binary"), /needs an argument: go-binary:<path>/);
  await assert.rejects(loadTarget("ts-source:x"), /takes no argument/);
  await assert.rejects(loadTarget("constructor"), /unknown target/);
  // A release before signing is refused before anything is created.
  let created = false;
  await assert.rejects(release.target.up({ argument: "0.15.0", onState: () => (created = true) }), /not signed and cannot be selected/);
  assert.equal(created, false);
});

/**
 * A fake signed release 9.9.9: a bundle (built with tar from `layout`),
 * its manifest, and SHA256SUMS listing both. `change` edits the parts
 * before SHA256SUMS is written; `sums` replaces SHA256SUMS's text.
 */
function fakeRelease({ change = () => {}, sums } = {}) {
  const version = "9.9.9";
  const work = mkdtempSync(join(tmpdir(), "conformance-release-test-"));
  const parts = { manifest: manifest(version), bundleManifest: null, extra: null, link: false };
  change(parts);
  const root = join(work, `varlatch-${version}`);
  mkdirSync(root);
  const manifestBytes = Buffer.from(JSON.stringify(parts.manifest));
  writeFileSync(join(root, "docker-compose.yml"), "services: {}\n");
  writeFileSync(join(root, "varlatch-release.json"), parts.bundleManifest ?? manifestBytes);
  if (parts.link) symlinkSync("/etc/passwd", join(root, "passwd"));
  const bundlePath = join(work, "bundle.tar.gz");
  const made = spawnSync("tar", ["-czf", bundlePath, "-C", work, `varlatch-${version}`, ...(parts.extra ? [parts.extra] : [])]);
  assert.equal(made.status, 0, String(made.stderr));
  const bundle = readFileSync(bundlePath);
  rmSync(work, { recursive: true, force: true });
  const files = {
    [bundleAsset(version)]: bundle,
    "varlatch-release.json": manifestBytes,
    "SHA256SUMS.sigstore.json": Buffer.from("{}"),
  };
  files.SHA256SUMS = Buffer.from(sums ?? `${sha256(bundle)}  ${bundleAsset(version)}\n${sha256(manifestBytes)}  varlatch-release.json\n`);
  return { version, files };
}

async function verifyWith(release, overrides = {}) {
  const workDir = mkdtempSync(join(tmpdir(), "conformance-release-work-"));
  const calls = { blob: [], images: [] };
  try {
    const download = async (url) => {
      assert.ok(url.startsWith(`https://github.com/varlatch/varlatch/releases/download/v${release.version}/`), url);
      const name = decodeURIComponent(url.split("/").pop());
      if (!(name in release.files)) throw new Error(`downloading ${name} answered 404`);
      return release.files[name];
    };
    const deps = {
      clients: clientsJson,
      download,
      verifyBlob: (args) => (calls.blob.push(args), { status: 0, output: "Verified OK" }),
      verifyImage: (args) => (calls.images.push(args), { status: 0, output: "" }),
      ...overrides,
    };
    const out = await verifyRelease(release.version, { workDir, log: () => {}, deps });
    return { out, calls };
  } finally {
    rmSync(workDir, { recursive: true, force: true });
  }
}

test("a verified release: the signed sums, the bundle and manifest, and each Varlatch image by digest for the release's identity", async () => {
  const release = fakeRelease();
  const { out, calls } = await verifyWith(release);
  const identity = "https://github.com/varlatch/varlatch/.github/workflows/release.yml@refs/tags/v9.9.9";
  assert.equal(calls.blob.length, 1);
  assert.equal(calls.blob[0].identity, identity);
  assert.equal(calls.blob[0].issuer, "https://token.actions.githubusercontent.com");
  assert.deepEqual(calls.images.map((c) => c.image), [`ghcr.io/varlatch/varlatchd@${D("1")}`, `ghcr.io/varlatch/varlatch-web@${D("2")}`, `ghcr.io/varlatch/varlatch-convex-deploy@${D("3")}`]);
  for (const c of calls.images) {
    assert.equal(c.identity, identity);
    assert.equal(c.signatures, "ghcr.io/varlatch/varlatch-signatures");
  }
  assert.equal(out.record.identity, identity);
  assert.equal(out.record.assets[bundleAsset("9.9.9")], sha256(release.files[bundleAsset("9.9.9")]));
  assert.equal(out.record.assets["varlatch-release.json"], sha256(release.files["varlatch-release.json"]));
  assert.equal(out.record.sha256sums, sha256(release.files.SHA256SUMS));
  assert.match(out.record.images.varlatchd.verified, /cosign signature/);
  assert.match(out.record.images.postgres.verified, /pinned by digest in the signed manifest/);
  assert.match(out.dir, /varlatch-9\.9\.9$/);
});

test("each failed check stops the release before anything runs", async () => {
  await assert.rejects(verifyWith(fakeRelease(), { verifyBlob: () => ({ status: 1, output: "none of the expected identities matched" }) }), /cosign could not verify SHA256SUMS of v9\.9\.9 .*none of the expected identities/);
  // Every asset used has its own entry, with its hash.
  const noBundleEntry = fakeRelease();
  noBundleEntry.files.SHA256SUMS = Buffer.from(`${sha256(noBundleEntry.files["varlatch-release.json"])}  varlatch-release.json\n`);
  await assert.rejects(verifyWith(noBundleEntry), /SHA256SUMS has no entry for varlatch-compose-9\.9\.9\.tar\.gz/);
  const noManifestEntry = fakeRelease();
  noManifestEntry.files.SHA256SUMS = Buffer.from(`${sha256(noManifestEntry.files[bundleAsset("9.9.9")])}  ${bundleAsset("9.9.9")}\n`);
  await assert.rejects(verifyWith(noManifestEntry), /SHA256SUMS has no entry for varlatch-release\.json/);
  const tampered = fakeRelease();
  tampered.files["varlatch-release.json"] = Buffer.from("{}");
  await assert.rejects(verifyWith(tampered), /varlatch-release\.json has sha256 .* but SHA256SUMS lists/);
  const twice = fakeRelease();
  twice.files.SHA256SUMS = Buffer.concat([twice.files.SHA256SUMS, Buffer.from(`${sha256(twice.files[bundleAsset("9.9.9")])}  ${bundleAsset("9.9.9")}\n`)]);
  await assert.rejects(verifyWith(twice), /lists varlatch-compose-9\.9\.9\.tar\.gz 2 times/);
  // The manifest, the bundle and its copy of the manifest.
  await assert.rejects(verifyWith(fakeRelease({ change: (p) => (p.manifest.version = "9.9.8") })), /is for "9\.9\.8", not 9\.9\.9/);
  await assert.rejects(verifyWith(fakeRelease({ change: (p) => (p.bundleManifest = Buffer.from("{}")) })), /its varlatch-release\.json differs from the release's signed/);
  await assert.rejects(verifyWith(fakeRelease({ change: (p) => (p.link = true) })), /varlatch-9\.9\.9\/passwd, which is not a regular file or directory/);
  // An image whose signature does not verify.
  await assert.rejects(
    verifyWith(fakeRelease(), { verifyImage: ({ image }) => (image.includes("varlatch-web") ? { status: 1, output: "no signatures found" } : { status: 0, output: "" }) }),
    /cosign could not verify ghcr\.io\/varlatch\/varlatch-web@sha256:2+ .*no signatures found/,
  );
  // A release file that cannot be downloaded.
  const gone = fakeRelease();
  delete gone.files[bundleAsset("9.9.9")];
  await assert.rejects(verifyWith(gone), /answered 404/);
});

test("ts-source's Compose override: built here, built and labeled once, or prebuilt with nothing left to build", async () => {
  const { buildOverride, COMMIT_LABEL } = await import("../targets/ts-source.mjs");
  const built = buildOverride("/repo", { mode: "build" });
  assert.equal(built.file, "build.json");
  assert.deepEqual(JSON.parse(built.text).services["convex-deploy"], { build: { context: "/repo" } });
  const tagged = JSON.parse(buildOverride("/repo", { mode: "tagged", tag: "ci", commit: "c".repeat(40) }).text).services;
  assert.deepEqual(tagged["varlatch-migrate"], { image: "varlatch-conformance/varlatchd:ci", build: { context: "/repo", labels: { [COMMIT_LABEL]: "c".repeat(40) } } });
  const prebuilt = buildOverride("/repo", { mode: "prebuilt", tag: "ci" });
  assert.equal(prebuilt.file, "prebuilt.yml");
  for (const [service, image] of [["varlatchd", "varlatchd"], ["varlatch-migrate", "varlatchd"], ["varlatch-web", "varlatch-web"], ["convex-deploy", "convex-deploy"]]) {
    assert.ok(prebuilt.text.includes(`  ${service}:\n    image: "varlatch-conformance/${image}:ci"\n    pull_policy: never\n    build: !reset null\n`), service);
  }
  assert.throws(() => buildOverride("/repo", { mode: "prebuilt" }), /needs an image tag/);
});

test("prebuilt images are refused for a checkout that differs from their commit: build, then edit or add a file", async () => {
  const { prebuiltProblems, worktreeChanges, checkoutCommit } = await import("../targets/ts-source.mjs");
  const repo = mkdtempSync(join(tmpdir(), "conformance-prebuilt-test-"));
  const git = (...args) => {
    const r = spawnSync("git", ["-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", ...args], { cwd: repo, encoding: "utf8" });
    assert.equal(r.status, 0, `git ${args.join(" ")}: ${r.stderr}`);
  };
  try {
    git("init", "-q");
    mkdirSync(join(repo, "services", "varlatchd", "src"), { recursive: true });
    writeFileSync(join(repo, "services", "varlatchd", "src", "server.ts"), "export const v = 1;\n");
    writeFileSync(join(repo, ".gitignore"), "node_modules/\n");
    git("add", ".");
    git("commit", "-q", "-m", "built");
    const commit = checkoutCommit(repo);
    // The images were built from this commit (as source-images.mjs labels them).
    const labeled = () => commit;
    assert.deepEqual(prebuiltProblems({ repoRoot: repo, tag: "ci", commit, inspect: labeled }), []);
    // An ignored file is not a change.
    mkdirSync(join(repo, "node_modules"));
    writeFileSync(join(repo, "node_modules", "x.js"), "");
    assert.deepEqual(worktreeChanges(repo), []);

    // Edited after the build: a tracked server file.
    writeFileSync(join(repo, "services", "varlatchd", "src", "server.ts"), "export const v = 2;\n");
    let problems = prebuiltProblems({ repoRoot: repo, tag: "ci", commit, inspect: labeled }).join();
    assert.match(problems, new RegExp(`the checkout differs from ${commit} \\(1 changed or untracked files: services/varlatchd/src/server\\.ts\\)`));
    git("checkout", "--", ".");
    // A new, untracked file in a nested directory.
    mkdirSync(join(repo, "apps", "web", "src"), { recursive: true });
    writeFileSync(join(repo, "apps", "web", "src", "new-page.tsx"), "x");
    problems = prebuiltProblems({ repoRoot: repo, tag: "ci", commit, inspect: labeled }).join();
    assert.match(problems, /apps\/web\/src\/new-page\.tsx/);
    rmSync(join(repo, "apps"), { recursive: true });
    assert.deepEqual(prebuiltProblems({ repoRoot: repo, tag: "ci", commit, inspect: labeled }), []);

    // Images from another commit, or missing.
    assert.match(prebuiltProblems({ repoRoot: repo, tag: "ci", commit, inspect: () => "f".repeat(40) }).join(), /was built from f{40}, not/);
    assert.match(prebuiltProblems({ repoRoot: repo, tag: "ci", commit, inspect: () => null }).join(), /varlatch-conformance\/varlatchd:ci is not loaded/);
    assert.match(prebuiltProblems({ repoRoot: repo, tag: "ci", commit, inspect: () => "" }).join(), /built from an unlabeled tree/);
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});
