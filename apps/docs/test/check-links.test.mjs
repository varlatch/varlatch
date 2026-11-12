// SPDX-License-Identifier: Apache-2.0
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { checkLinks, checkMoved } from "../scripts/check-links.mjs";
import { movedAnchorsScript } from "../src/moved-anchors.mjs";

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

  it("accepts a link to a section that moved", () => {
    dist = mkdtempSync(join(tmpdir(), "docs-links-"));
    page("old", "");
    page("b", '<a href="/old/#gone">x</a> <a href="/old/#other">x</a>');
    expect(checkLinks(dist, { "/old/": { gone: "/b/" } })).toEqual(["/b/index.html: /old/#other has no #other on its page"]);
  });

  it("accepts moved sections whose new place exists and whose old ID is gone", () => {
    dist = mkdtempSync(join(tmpdir(), "docs-links-"));
    page("old", '<h2 id="kept">Kept</h2>');
    page("new", '<h2 id="moved">Moved</h2>');
    expect(checkMoved(dist, { "/old/": { moved: "/new/#moved", whole: "/new/" } })).toEqual([]);
  });

  it("reports a moved section with no new place, or whose old ID still exists", () => {
    dist = mkdtempSync(join(tmpdir(), "docs-links-"));
    page("old", '<h2 id="still">Still here</h2>');
    page("new", "");
    expect(checkMoved(dist, { "/old/": { still: "/new/", gone: "/new/#gone", page: "/nope/" }, "/missing/": {} })).toEqual([
      "moved from /old/#still: the page still has that ID",
      "moved from /old/#gone: /new/#gone has no #gone on its page",
      "moved from /old/#page: /nope/ has no page",
      "moved from /missing/: the page no longer exists, so its script never runs",
    ]);
  });
});

describe("movedAnchorsScript", () => {
  function run(pathname, hash) {
    const location = { pathname, hash, replace: target => { location.to = target; } };
    new Function("location", movedAnchorsScript({ "/old/": { "a-b": "/new/#c" } }))(location);
    return location.to;
  }

  it("sends a moved fragment on, and leaves everything else alone", () => {
    expect(run("/old/", "#a-b")).toBe("/new/#c");
    expect(run("/old/", "#other")).toBeUndefined();
    expect(run("/old/", "")).toBeUndefined();
    expect(run("/new/", "#a-b")).toBeUndefined();
  });
});
