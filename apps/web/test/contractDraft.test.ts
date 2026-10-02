// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import {
  changeCount,
  diffItems,
  draftItems,
  requiredFromKey,
  requiredLabel,
  rowProblem,
  rowState,
  rowsFrom,
  type ContractItem,
} from "../src/features/projects/contractDraft";

const items: ContractItem[] = [
  { name: "API_KEY", required: { kind: "selector", selector: { kind: "tier", tier: "production" } }, sensitive: true, type: "string" },
  { name: "LOG_LEVEL", required: { kind: "always" }, sensitive: false, type: "enum", enumValues: ["debug", "info"], defaultValue: "info" },
  { name: "PORT", required: { kind: "always" }, sensitive: false, type: "number", defaultValue: "3000", example: "8080" },
];

describe("draft rows", () => {
  it("starts unchanged and tracks edits, additions and removals", () => {
    const rows = rowsFrom(items);
    expect(rows.map(rowState)).toEqual(["unchanged", "unchanged", "unchanged"]);
    rows[2] = { ...rows[2]!, item: { ...rows[2]!.item, defaultValue: "8080" } };
    rows[0] = { ...rows[0]!, removed: true };
    rows.push({ key: "new:1", item: { name: "WORKERS", required: { kind: "never" }, sensitive: false, type: "integer" }, origin: null, removed: false });
    expect(rows.map(rowState)).toEqual(["removed", "unchanged", "edited", "new"]);
    expect(changeCount(rows)).toBe(3);
  });

  it("treats an edit that is undone as unchanged", () => {
    const rows = rowsFrom(items);
    const edited = { ...rows[2]!, item: { ...rows[2]!.item, description: "  " } };
    expect(rowState(edited)).toBe("unchanged");
  });

  it("pushes cleaned, sorted items and keeps fields the editor does not show", () => {
    const rows = rowsFrom(items);
    rows.push({ key: "new:1", item: { name: "A_FLAG", required: { kind: "never" }, sensitive: false, type: "boolean", defaultValue: "", description: "" }, origin: null, removed: false });
    const out = draftItems(rows);
    // Code-point order, like the server: "API_KEY" < "A_FLAG".
    expect(out.map((i) => i.name)).toEqual(["API_KEY", "A_FLAG", "LOG_LEVEL", "PORT"]);
    expect(out[1]).toEqual({ name: "A_FLAG", required: { kind: "never" }, sensitive: false, type: "boolean" });
    expect(out[3]!.example).toBe("8080");
  });
});

describe("diffItems", () => {
  it("lists security-relevant changes first", () => {
    const after: ContractItem[] = [
      { ...items[0]!, sensitive: false },
      { ...items[1]!, description: "Log level" },
      { ...items[2]!, required: { kind: "never" } },
      { name: "NEW_ITEM", required: { kind: "always" }, sensitive: true, type: "string" },
    ];
    const diff = diffItems(items, after);
    expect(diff.map((c) => `${c.kind}:${c.name}`)).toEqual([
      "added:NEW_ITEM",
      "secret:API_KEY",
      "required:PORT",
      "description:LOG_LEVEL",
    ]);
    expect(diff.filter((c) => c.securityRelevant)).toHaveLength(3);
    expect(diff[2]).toMatchObject({ from: "always", to: "optional" });
  });

  it("reports removals and type changes", () => {
    const diff = diffItems(items, [{ ...items[1]! }, { ...items[2]!, type: "integer" }]);
    expect(diff.map((c) => `${c.kind}:${c.name}`)).toEqual(["removed:API_KEY", "type:PORT"]);
  });
});

describe("requiredness", () => {
  it("round-trips tier-scoped requiredness", () => {
    const r = requiredFromKey("tier:staging", { kind: "always" });
    expect(requiredLabel(r)).toBe("staging only");
    expect(requiredFromKey("environments", items[0]!.required)).toBe(items[0]!.required);
  });
});

describe("rowProblem", () => {
  const names = new Map([["PORT", 1], ["DUP", 2]]);
  it("validates names", () => {
    expect(rowProblem({ ...items[2]!, name: "port" }, names)).toMatch(/capitals/);
    expect(rowProblem({ ...items[2]!, name: "DUP" }, names)).toMatch(/Another item/);
  });
  it("validates enum values and typed defaults", () => {
    expect(rowProblem({ ...items[1]!, enumValues: [] }, names)).toMatch(/allowed values/);
    expect(rowProblem({ ...items[1]!, defaultValue: "trace" }, names)).toMatch(/one of the allowed/);
    expect(rowProblem({ ...items[2]!, type: "integer", defaultValue: "3.5" }, names)).toMatch(/whole number/);
    expect(rowProblem(items[2]!, names)).toBeNull();
  });
});
