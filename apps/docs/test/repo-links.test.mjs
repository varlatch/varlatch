// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { rewrite } from "../src/repo-links.mjs";
import { pages } from "../src/sources.mjs";

const routes = new Map(pages().map(page => [page.source, page.route]));

describe("rewrite", () => {
  it("points a link to another page at its route, keeping the anchor", () => {
    expect(rewrite("operations/backup.md#install-the-operator-cli", "docs/getting-started.md", routes)).toBe(
      "/operations/backup/#install-the-operator-cli",
    );
    expect(rewrite("../THREAT-MODEL.md", "docs/reference/mcp.md", routes)).toBe("/threat-model/");
    expect(rewrite("../../CONTEXT.md", "docs/reference/mcp.md", routes)).toBe("/concepts/");
    expect(rewrite("../../docs/getting-started.md", "infra/compose/README.md", routes)).toBe("/getting-started/");
  });

  it("points a link to a file that is not a page at GitHub", () => {
    expect(rewrite("../SECURITY.md", "docs/getting-started.md", routes)).toBe(
      "https://github.com/varlatch/varlatch/blob/main/SECURITY.md",
    );
    expect(rewrite("../infra/compose/", "docs/getting-started.md", routes)).toBe(
      "https://github.com/varlatch/varlatch/tree/main/infra/compose",
    );
  });

  it("points a GitHub link to a page at the page", () => {
    expect(
      rewrite("https://github.com/varlatch/varlatch/blob/v0.14.1/docs/operations/backup.md#restore", "infra/compose/README.md", routes),
    ).toBe("/operations/backup/#restore");
    expect(rewrite("https://github.com/varlatch/varlatch/blob/main/SECURITY.md", "infra/compose/README.md", routes)).toBeUndefined();
  });

  it("leaves other sites, anchors, and site paths alone", () => {
    for (const url of ["https://example.com/a.md", "mailto:security@varlatch.com", "#limits", "/changelog/"]) {
      expect(rewrite(url, "docs/getting-started.md", routes)).toBeUndefined();
    }
  });

  it("fails on a link to a file that does not exist, or outside the repository", () => {
    expect(() => rewrite("operations/nope.md", "docs/getting-started.md", routes)).toThrow(/docs\/operations\/nope\.md, which does not exist/);
    expect(() => rewrite("../../outside.md", "docs/getting-started.md", routes)).toThrow(/outside the repository/);
  });
});

describe("pages", () => {
  it("gives every page its own route", () => {
    const list = pages();
    expect(new Set(list.map(page => page.route)).size).toBe(list.length);
    expect(list.map(page => page.source)).toContain("docs/getting-started.md");
  });
});
