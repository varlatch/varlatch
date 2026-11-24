// SPDX-License-Identifier: Apache-2.0
// The nightly image scan (image-scan.yml) reads what each line's releases
// attach: from the first night after a Go release is the latest, too.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { releaseImages } from "../../ci-scan-images.mjs";

const repo = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const digest = (c) => `sha256:${c.repeat(64)}`;
const image = (version, c = "a") => `ghcr.io/varlatch/varlatchd:${version}@${digest(c)}\n`;
const manifest = JSON.stringify({ version: "0.23.0", images: Object.fromEntries(["varlatchd", "varlatch-web", "convex-deploy"].map((n, i) => [n, { digest: `ghcr.io/varlatch/${n}@${digest(String(i))}` }])) });

test("a Go release's image is the one varlatchd-image.txt records", () => {
  const want = (tag) => [{ image: "varlatchd", tag, pinned: `ghcr.io/varlatch/varlatchd@${digest("a")}` }];
  assert.deepEqual(releaseImages("v0.50.0", { "varlatchd-image.txt": image("0.50.0") }), want("v0.50.0"));
  assert.deepEqual(releaseImages("v0.50.0-rc.3", { "varlatchd-image.txt": image("0.50.0-rc.3") }), want("v0.50.0-rc.3"));
  // Byte for byte as release.yml writes it: one line, then nothing.
  const release = readFileSync(join(repo, ".github/workflows/release.yml"), "utf8");
  assert.match(release, /printf '%s\\n' "\$REF" > varlatchd-image\.txt/);
  for (const bad of [image("0.50.1"), image("0.50.0").trim(), image("0.50.0") + "x\n", "ghcr.io/varlatch/varlatchd:0.50.0\n", image("0.50.0").replace("ghcr.io", "example.com"), image("0.50.0").replace("varlatchd:", "other:"), ""]) {
    assert.throws(() => releaseImages("v0.50.0", { "varlatchd-image.txt": bad }), undefined, JSON.stringify(bad));
  }
});

test("a TypeScript release's images are the two varlatch-release.json pins", () => {
  assert.deepEqual(releaseImages("v0.23.0", { "varlatch-release.json": manifest }), [
    { image: "varlatchd", tag: "v0.23.0", pinned: `ghcr.io/varlatch/varlatchd@${digest("0")}` },
    { image: "varlatch-web", tag: "v0.23.0", pinned: `ghcr.io/varlatch/varlatch-web@${digest("1")}` },
  ]);
  assert.throws(() => releaseImages("v0.23.0", { "varlatch-release.json": "{}" }), /pins varlatchd as undefined/);
});

test("a release with neither file, or both, is an error", () => {
  assert.throws(() => releaseImages("v0.50.0", {}), /neither/);
  assert.throws(() => releaseImages("v0.50.0", { "varlatchd-image.txt": image("0.50.0"), "varlatch-release.json": manifest }), /both/);
  assert.throws(() => releaseImages("latest", { "varlatch-release.json": manifest }), /not a release's tag/);
});

test("the night after v0.50.0: its image, and the last TypeScript release's two while that is supported", () => {
  const dir = mkdtempSync(join(tmpdir(), "image-scan-"));
  try {
    for (const [tag, file, text] of [["v0.50.0", "varlatchd-image.txt", image("0.50.0")], ["v0.23.0", "varlatch-release.json", manifest]]) {
      mkdirSync(join(dir, tag));
      writeFileSync(join(dir, tag, file), text);
    }
    const found = JSON.parse(execFileSync(process.execPath, [join(repo, "scripts/ci-scan-images.mjs"), dir], { encoding: "utf8" }));
    assert.deepEqual(found.map(({ image, tag }) => `${image} ${tag}`), ["varlatchd v0.23.0", "varlatch-web v0.23.0", "varlatchd v0.50.0"]);
    rmSync(join(dir, "v0.50.0", "varlatchd-image.txt"));
    assert.throws(() => execFileSync(process.execPath, [join(repo, "scripts/ci-scan-images.mjs"), dir], { stdio: "pipe" }), /neither/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  const workflow = readFileSync(join(repo, ".github/workflows/image-scan.yml"), "utf8");
  const last = /^const LastTypeScriptRelease = "([^"]+)"$/m.exec(readFileSync(join(repo, "go/lib/release/manifest.go"), "utf8"))[1];
  assert.match(workflow, new RegExp(`^  TYPESCRIPT_RELEASE: v${last.replaceAll(".", "\\.")} #`, "m"), "image-scan.yml scans the last TypeScript release");
  assert.match(workflow, /--pattern varlatchd-image\.txt --pattern varlatch-release\.json/);
  assert.match(workflow, /node scripts\/ci-scan-images\.mjs /);
  assert.match(workflow, /include: \$\{\{ fromJSON\(needs\.images\.outputs\.images\) \}\}/);
});
