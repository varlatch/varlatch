// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import {
  contractItems,
  environmentHealth,
  itemCount,
  missingRequired,
  requiredHere,
  type ContractItemMeta,
} from "../src/features/projects/health";

const production = { id: "env_prod", tier: "production" as const };
const development = { id: "env_dev", tier: "development" as const };

const items: ContractItemMeta[] = [
  { name: "DATABASE_URL", required: { kind: "always" } },
  { name: "PORT", required: { kind: "always" }, defaultValue: "3000" },
  { name: "API_KEY", required: { kind: "selector", selector: { kind: "tier", tier: "production" } } },
  { name: "PREVIEW_TOKEN", required: { kind: "selector", selector: { kind: "environments", environmentIds: ["env_dev"] } } },
  { name: "PUBLIC_URL", required: { kind: "never" } },
];

describe("requiredHere", () => {
  it("follows always, never, tier and environment selectors", () => {
    expect(items.map((i) => requiredHere(i, production))).toEqual([true, true, true, false, false]);
    expect(items.map((i) => requiredHere(i, development))).toEqual([true, true, false, true, false]);
  });
});

describe("missingRequired", () => {
  it("counts required items with neither a value nor a default", () => {
    expect(missingRequired(items, production, new Set(["DATABASE_URL"]))).toEqual(["API_KEY"]);
    expect(missingRequired(items, production, new Set())).toEqual(["API_KEY", "DATABASE_URL"]);
    expect(missingRequired(items, development, new Set(["DATABASE_URL", "PREVIEW_TOKEN"]))).toEqual([]);
  });
});

describe("environmentHealth", () => {
  const present = new Set(["DATABASE_URL", "API_KEY"]);
  it("is ok when every required item is covered", () => {
    expect(environmentHealth({ contract: items, presence: present, env: production })).toEqual({ state: "ok" });
  });
  it("names the missing items", () => {
    expect(environmentHealth({ contract: items, presence: new Set(), env: production })).toEqual({
      state: "missing",
      items: ["API_KEY", "DATABASE_URL"],
    });
  });
  it("says nothing when the contract or the metadata cannot be read", () => {
    expect(environmentHealth({ contract: "unreadable", presence: present, env: production }).state).toBe("unknown");
    expect(environmentHealth({ contract: items, presence: "unreadable", env: production }).state).toBe("unknown");
    expect(environmentHealth({ contract: "unreadable", presence: "loading", env: production }).state).toBe("unknown");
  });
  it("waits while loading and reports a project without a contract", () => {
    expect(environmentHealth({ contract: "loading", presence: present, env: production }).state).toBe("loading");
    expect(environmentHealth({ contract: items, presence: "loading", env: production }).state).toBe("loading");
    expect(environmentHealth({ contract: "none", presence: present, env: production }).state).toBe("no-contract");
  });
});

describe("itemCount and contractItems", () => {
  it("counts distinct names across the contract and every environment", () => {
    expect(itemCount(items, [new Set(["DATABASE_URL", "EXTRA"]), new Set(["EXTRA", "OTHER"])])).toBe(7);
    expect(itemCount([], [])).toBe(0);
  });
  it("tolerates a revision without a body", () => {
    expect(contractItems(undefined)).toEqual([]);
    expect(contractItems({})).toEqual([]);
    expect(contractItems({ items }).length).toBe(5);
  });
});
