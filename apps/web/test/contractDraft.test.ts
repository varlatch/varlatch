// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import {
  changeCount,
  diffItems,
  draftItems,
  graceHours,
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

describe("rotation fields (ADR-0053)", () => {
  const names = new Map(items.map((i) => [i.name, 1]));
  const key = items[0]!;

  it("are pushed as typed, and dropped when empty", () => {
    const hint = "Issue a new key at the provider, then revoke the old one.";
    const rows = rowsFrom(items);
    rows[0]!.item = { ...key, rotationHint: hint, rotationGraceSeconds: 86400 };
    rows[1]!.item = { ...items[1]!, rotationHint: "", rotationGraceSeconds: undefined };
    const pushed = draftItems(rows);
    expect(pushed.find((i) => i.name === "API_KEY")).toMatchObject({ rotationHint: hint, rotationGraceSeconds: 86400 });
    expect(pushed.find((i) => i.name === "LOG_LEVEL")).not.toHaveProperty("rotationHint");
    expect(pushed.find((i) => i.name === "LOG_LEVEL")).not.toHaveProperty("rotationGraceSeconds");
  });

  it("show in the diff as a rotation change, never security-relevant", () => {
    const changes = diffItems(items, [{ ...key, rotationHint: "Rotate at the provider." }, items[1]!, items[2]!]);
    expect(changes).toEqual([{ name: "API_KEY", kind: "rotation", from: undefined, to: "Rotate at the provider.", securityRelevant: false }]);
    const grace = diffItems([{ ...key, rotationGraceSeconds: 3600 }], [{ ...key, rotationGraceSeconds: 7200 }]);
    expect(grace).toEqual([{ name: "API_KEY", kind: "rotation", from: "grace 1 h", to: "grace 2 h", securityRelevant: false }]);
  });

  it("refuse what the server would refuse", () => {
    expect(rowProblem({ ...key, rotationHint: "one\ttwo" }, names)).toMatch(/one line/);
    expect(rowProblem({ ...key, rotationHint: "one\u2028two" }, names)).toMatch(/one line/);
    expect(rowProblem({ ...key, rotationHint: "🔑".repeat(1025) }, names)).toMatch(/at most 1024/);
    expect(rowProblem({ ...key, rotationGraceSeconds: 0 }, names)).toMatch(/between 1 second and 30 days/);
    expect(rowProblem({ ...key, rotationGraceSeconds: Number.NaN }, names)).toMatch(/between 1 second and 30 days/);
    expect(rowProblem({ ...key, rotationGraceSeconds: 2_592_001 }, names)).toMatch(/between 1 second and 30 days/);
    expect(rowProblem({ ...key, rotationHint: "Fine.", rotationGraceSeconds: 1800 }, names)).toBeNull();
  });

  it("show grace in hours, exact to the second", () => {
    expect(graceHours(86400)).toBe("24");
    expect(graceHours(1800)).toBe("0.5");
    expect(Math.round(Number(graceHours(61)) * 3600)).toBe(61);
  });
});
