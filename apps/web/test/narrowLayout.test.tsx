// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { create } from "react-test-renderer";
import { act } from "react";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { table } from "../src/components/ui";
import { SentenceText } from "../src/features/audit/parts";

vi.hoisted(() => vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true));

/**
 * The Audit page at a phone's width (390 px): what is in a table scrolls in
 * it, and a long word of an event breaks. Nothing here lays a page out; the
 * classes are what keeps it, measured in a browser when they were chosen.
 */

describe("a table that scrolls sideways", () => {
  it("holds what is absolutely placed in it, so a sr-only header cannot widen the page", () => {
    expect(table.wrap.split(" ")).toEqual(expect.arrayContaining(["relative", "overflow-x-auto"]));
  });

  it("is the shared one wherever a table has a sr-only header", () => {
    const files = (dir: string): string[] =>
      readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? files(join(dir, e.name)) : e.name.endsWith(".tsx") ? [join(dir, e.name)] : []));
    const src = join(__dirname, "../src");
    for (const file of files(src)) {
      const text = readFileSync(file, "utf8");
      if (!/<th[^>]*>\s*<span className="sr-only">/.test(text)) continue;
      expect(text, file).toContain("table.wrap");
    }
    // The webhooks table of the Audit page is one.
    expect(readFileSync(join(src, "features/audit/WebhooksSection.tsx"), "utf8")).toMatch(/table\.wrap[\s\S]*<span className="sr-only">Actions<\/span>/);
  });
});

describe("an event's sentence", () => {
  it("breaks a long word, and keeps a place on one line only where there is room", async () => {
    let root!: ReturnType<typeof create>;
    await act(async () => {
      root = create(<SentenceText className="min-w-0" segments={["read ", { kind: "mono", text: "audit_export.stream_started" }, " in ", { kind: "place", text: "api / development" }]} />);
    });
    const spans = root.root.findAllByType("span");
    expect(spans[0]!.props.className).toContain("[overflow-wrap:anywhere]");
    expect(spans[0]!.props.className).toContain("min-w-0");
    const place = spans.find((s) => s.children.includes("api / development"))!;
    expect(place.props.className.split(" ")).toContain("@3xl:whitespace-nowrap");
    expect(place.props.className.split(" ")).not.toContain("whitespace-nowrap");
  });
});
