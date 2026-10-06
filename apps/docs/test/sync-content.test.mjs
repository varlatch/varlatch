// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { dropComments, toPage } from "../scripts/sync-content.mjs";

describe("toPage", () => {
  it("makes the title line the page title, without code marks", () => {
    const page = toPage({ source: "docs/reference/mcp.md" }, "# The MCP server: `varlatch mcp`\n\nBody.\n");
    expect(page).toBe(
      '---\ntitle: "The MCP server: varlatch mcp"\neditUrl: "https://github.com/varlatch/varlatch/edit/main/docs/reference/mcp.md"\n---\n\nBody.\n',
    );
  });

  it("uses the listed title when there is one", () => {
    expect(toPage({ source: "CONTEXT.md", title: "Concepts" }, "# Varlatch\n\nBody.\n")).toContain('title: "Concepts"');
  });

  it("refuses a file that does not start with a title", () => {
    expect(() => toPage({ source: "docs/x.md" }, "Body.\n")).toThrow(/docs\/x\.md: the first line must be/);
  });
});

describe("dropComments", () => {
  it("drops a comment that starts a line, over one line or several", () => {
    expect(dropComments("A.\n\n<!-- TODO(owner): one -->\n\nB.\n\n<!-- TODO(owner): two\nlines -->\n\nC.\n")).toBe(
      "A.\n\nB.\n\nC.\n",
    );
  });

  it("keeps comments inside text and code blocks", () => {
    const body = "Between `<!-- varlatch:begin -->` and the end.\n\n```html\n<!-- kept -->\n```\n";
    expect(dropComments(body)).toBe(body);
  });
});
