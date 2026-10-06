// SPDX-License-Identifier: Apache-2.0
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { checkLinks } from "../scripts/check-links.mjs";

let dist;
function page(path, html) {
  mkdirSync(join(dist, path), { recursive: true });
  writeFileSync(join(dist, path, "index.html"), `<html><body>${html}</body></html>`);
}

afterEach(() => rmSync(dist, { recursive: true, force: true }));

describe("checkLinks", () => {
  it("accepts links to pages, anchors, and files that exist", () => {
    dist = mkdtempSync(join(tmpdir(), "docs-links-"));
    page("a", '<h2 id="limits">Limits</h2>');
    writeFileSync(join(dist, "og.png"), "");
    page("b", '<a href="/a/#limits">x</a> <a href="../a/">x</a> <a href="/og.png">x</a> <a href="https://example.com/#gone">x</a> <p id="self"></p><a href="#self">x</a>');
    expect(checkLinks(dist)).toEqual([]);
  });

  it("reports a missing page and a missing anchor", () => {
    dist = mkdtempSync(join(tmpdir(), "docs-links-"));
    page("a", '<h2 id="limits">Limits</h2>');
    page("b", '<a href="/a/#limit">x</a> <a href="/c/">x</a> <a href="#nowhere">x</a>');
    expect(checkLinks(dist)).toEqual([
      "/b/index.html: /a/#limit has no #limit on its page",
      "/b/index.html: /c/ has no page",
      "/b/index.html: #nowhere has no #nowhere on its page",
    ]);
  });
});
