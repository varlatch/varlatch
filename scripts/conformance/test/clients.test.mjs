// SPDX-License-Identifier: Apache-2.0
/**
 * Pinned CLIs: clients.json's rules, SHA256SUMS parsing, and the
 * verification of a downloaded CLI, each failure path failing closed. The
 * network and cosign are replaced; nothing here downloads anything.
 */
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { cosignBinary, resolveCli, sha256 } from "../clients.mjs";
import {
  assetProblems,
  cliAsset,
  cosignBinaryFor,
  parseSha256Sums,
  releaseAssetUrl,
  releaseIdentity,
  validateClients,
  versionProblem,
} from "../lib/clients.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const clientsJson = JSON.parse(readFileSync(join(here, "..", "clients.json"), "utf8"));
const H = (c) => c.repeat(64);

test("clients.json is valid and pins 0.21.0 and 0.22.0 by version, commit and hash", () => {
  assert.deepEqual(validateClients(clientsJson), []);
  assert.deepEqual(Object.keys(clientsJson.cli).sort(), ["0.21.0", "0.22.0"]);
  assert.equal(clientsJson.repository, "varlatch/varlatch");
});

test("clients.json: no name such as latest, and every pin complete", () => {
  const good = () => structuredClone(clientsJson);
  const problems = (change) => {
    const c = good();
    change(c);
    return validateClients(c).join("\n");
  };
  assert.match(problems((c) => (c.cli.latest = c.cli["0.22.0"])), /cli\.latest: a CLI is pinned by its x\.y\.z version/);
  assert.match(problems((c) => delete c.cli["0.22.0"].commit), /cli\.0\.22\.0: commit must be/);
  assert.match(problems((c) => (c.cli["0.22.0"].sha256 = "ABC")), /cli\.0\.22\.0: sha256 must be/);
  assert.match(problems((c) => (c.cli = {})), /cli: expected at least one pinned CLI/);
  assert.match(problems((c) => (c.issuer = "https://example.com")), /issuer/);
  assert.match(problems((c) => (c.repository = "varlatch")), /repository/);
  assert.match(problems((c) => (c.cosign.version = "latest")), /cosign\.version/);
  assert.match(problems((c) => (c.cosign.binaries["linux-x64"].sha256 = "")), /cosign\.binaries\.linux-x64: sha256/);
  assert.match(problems((c) => (c.cosign.binaries = {})), /cosign\.binaries: expected at least one platform/);
  assert.deepEqual(validateClients({ schema: 2 }), ["schema: expected 1"]);
});

test("the release's identity, asset and URL", () => {
  assert.equal(releaseIdentity("varlatch/varlatch", "0.22.0"), "https://github.com/varlatch/varlatch/.github/workflows/release.yml@refs/tags/v0.22.0");
  assert.equal(cliAsset("0.21.0"), "varlatch-cli-0.21.0.cjs");
  assert.equal(releaseAssetUrl("varlatch/varlatch", "0.21.0", "SHA256SUMS"), "https://github.com/varlatch/varlatch/releases/download/v0.21.0/SHA256SUMS");
});

test("SHA256SUMS: both separators are read, any other line makes the file unusable", () => {
  assert.deepEqual(parseSha256Sums(`${H("a")}  varlatch-cli-0.22.0.cjs\n${H("b")} *varlatch-release.json\n\n`), [
    { sha256: H("a"), name: "varlatch-cli-0.22.0.cjs" },
    { sha256: H("b"), name: "varlatch-release.json" },
  ]);
  assert.throws(() => parseSha256Sums(`${H("a")}  ok\nnot a line\n`), /line 2/);
  assert.throws(() => parseSha256Sums(`${H("A")}  upper-case\n`), /line 1/);
  assert.throws(() => parseSha256Sums(`${"a".repeat(63)}  short\n`), /line 1/);
});

test("an asset is usable only when SHA256SUMS lists it once, with its hash, which is the pinned one", () => {
  const asset = "varlatch-cli-0.22.0.cjs";
  const entries = [{ sha256: H("a"), name: asset }, { sha256: H("b"), name: "other" }];
  assert.deepEqual(assetProblems({ entries, asset, actual: H("a"), pinned: H("a") }), []);
  assert.match(assetProblems({ entries: entries.slice(1), asset, actual: H("a"), pinned: H("a") }).join(), /no entry for varlatch-cli-0\.22\.0\.cjs/);
  assert.match(assetProblems({ entries: [...entries, entries[0]], asset, actual: H("a"), pinned: H("a") }).join(), /lists .* 2 times/);
  assert.match(assetProblems({ entries, asset, actual: H("c"), pinned: H("c") }).join(), /but SHA256SUMS lists/);
  assert.match(assetProblems({ entries, asset, actual: H("a"), pinned: H("d") }).join(), /but clients\.json pins/);
});

test("--version must report exactly the requested version", () => {
  assert.equal(versionProblem("varlatch 0.22.0 (migration 52)\n", "0.22.0"), null);
  assert.equal(versionProblem("varlatch 0.22.0", "0.22.0"), null);
  assert.match(versionProblem("varlatch 0.21.0 (migration 42)", "0.22.0"), /reports 0\.21\.0, not the requested 0\.22\.0/);
  assert.match(versionProblem("varlatch 0.22.01 (migration 52)", "0.22.0"), /reports 0\.22\.01/);
  assert.match(versionProblem("0.22.0", "0.22.0"), /not "varlatch <version> \.\.\."/);
  assert.match(versionProblem("", "0.22.0"), /not "varlatch <version> \.\.\."/);
});

test("cosign is pinned per platform; an unpinned platform cannot verify", () => {
  assert.equal(cosignBinaryFor(clientsJson, "linux", "x64").asset, "cosign-linux-amd64");
  assert.throws(() => cosignBinaryFor(clientsJson, "darwin", "arm64"), /pins no cosign binary for darwin-arm64/);
});

test("a cosign download with another hash is refused and not kept", async () => {
  const cache = mkdtempSync(join(tmpdir(), "conformance-cosign-test-"));
  try {
    const clients = structuredClone(clientsJson);
    clients.cosign.binaries[`${process.platform}-${process.arch}`] = { asset: "cosign-test", sha256: sha256("the real binary") };
    await assert.rejects(cosignBinary(clients, cache, () => {}, async () => Buffer.from("something else")), /cosign cosign-test has sha256 .* but clients\.json pins/);
    const kept = await cosignBinary(clients, cache, () => {}, async () => Buffer.from("the real binary"));
    assert.equal(readFileSync(kept, "utf8"), "the real binary");
    // Cached, and checked by hash again before use: no download the second time.
    assert.equal(await cosignBinary(clients, cache, () => {}, async () => assert.fail("downloaded again")), kept);
  } finally {
    rmSync(cache, { recursive: true, force: true });
  }
});

/** A fake release: SHA256SUMS listing a CLI that prints `printed` for --version. */
function fakeRelease({ version = "9.9.9", printed = `varlatch ${version} (migration 1)`, listed = true, sumsHash } = {}) {
  const cli = Buffer.from(`process.stdout.write(${JSON.stringify(`${printed}\n`)});\n`);
  const asset = cliAsset(version);
  const sums = listed ? `${sumsHash ?? sha256(cli)}  ${asset}\n${H("e")}  varlatch-release.json\n` : `${H("e")}  varlatch-release.json\n`;
  const files = { SHA256SUMS: Buffer.from(sums), "SHA256SUMS.sigstore.json": Buffer.from("{}"), [asset]: cli };
  const clients = structuredClone(clientsJson);
  clients.cli = { [version]: { commit: "f".repeat(40), sha256: sha256(cli) } };
  const download = async (url) => {
    const name = decodeURIComponent(url.split("/").pop());
    assert.ok(url.startsWith(`https://github.com/varlatch/varlatch/releases/download/v${version}/`), url);
    if (!(name in files)) throw new Error(`no ${name}`);
    return files[name];
  };
  return { version, clients, download, cli };
}

async function resolveWith(release, overrides = {}) {
  const workDir = mkdtempSync(join(tmpdir(), "conformance-clients-test-"));
  const calls = [];
  try {
    const verifyBlob = (args) => {
      calls.push(args);
      return { status: 0, output: "Verified OK" };
    };
    return {
      cli: await resolveCli(release.version, {
        repoRoot: "/nonexistent",
        workDir,
        log: () => {},
        deps: { clients: release.clients, download: release.download, verifyBlob, ...overrides },
      }),
      calls,
    };
  } finally {
    rmSync(workDir, { recursive: true, force: true });
  }
}

test("a verified CLI: cosign checked SHA256SUMS for the release's own identity, and the hash and version match", async () => {
  const release = fakeRelease();
  const { cli, calls } = await resolveWith(release);
  assert.equal(cli.version, "9.9.9");
  assert.equal(cli.sha256, sha256(release.cli));
  assert.equal(cli.commit, "f".repeat(40));
  assert.equal(cli.verified.identity, "https://github.com/varlatch/varlatch/.github/workflows/release.yml@refs/tags/v9.9.9");
  assert.equal(cli.verified.versionOutput, "varlatch 9.9.9 (migration 1)");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].identity, cli.verified.identity);
  assert.equal(calls[0].issuer, "https://token.actions.githubusercontent.com");
  assert.match(calls[0].sums, /SHA256SUMS$/);
  assert.match(calls[0].bundle, /SHA256SUMS\.sigstore\.json$/);
});

test("each failed check stops the CLI before any suite: signature, entry, hash, pin, version", async () => {
  await assert.rejects(resolveWith(fakeRelease(), { verifyBlob: () => ({ status: 1, output: "none of the expected identities matched" }) }), /cosign could not verify SHA256SUMS of v9\.9\.9 .*none of the expected identities/);
  await assert.rejects(resolveWith(fakeRelease({ listed: false })), /SHA256SUMS has no entry for varlatch-cli-9\.9\.9\.cjs/);
  await assert.rejects(resolveWith(fakeRelease({ sumsHash: H("0") })), /but SHA256SUMS lists/);
  const repinned = fakeRelease();
  repinned.clients.cli["9.9.9"].sha256 = H("1");
  await assert.rejects(resolveWith(repinned), /but clients\.json pins/);
  await assert.rejects(resolveWith(fakeRelease({ printed: "varlatch 9.9.8 (migration 1)" })), /--version reports 9\.9\.8, not the requested 9\.9\.9/);
  // A release file that cannot be downloaded stops it too.
  const gone = fakeRelease();
  await assert.rejects(resolveWith(gone, { download: async () => Promise.reject(new Error("downloading answered 404")) }), /answered 404/);
});

test("a version clients.json does not pin is a usage error, never a download", async () => {
  const release = fakeRelease();
  for (const spec of ["0.20.0", "latest", "constructor"]) {
    await assert.rejects(
      resolveCli(spec, { repoRoot: "/nonexistent", workDir: tmpdir(), log: () => {}, deps: { clients: release.clients, download: async () => assert.fail("downloaded"), verifyBlob: () => assert.fail("verified") } }),
      (err) => err.usage === true && /not a pinned CLI; clients\.json pins 9\.9\.9/.test(err.message),
      spec,
    );
  }
});
