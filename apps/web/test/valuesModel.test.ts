// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import type { Environment, SyncTarget } from "@varlatch/protocol";
import {
  buildChanges,
  cellStateOf,
  dotenvLine,
  draftKind,
  editorKind,
  generateSecret,
  isSensitive,
  parseDotenv,
  requiredHere,
  type ContractItemMeta,
  type Draft,
  type ServerItem,
} from "../src/features/values/model";
import { syncTargetItemStatus, targetCoversItem } from "../src/features/sync/syncStatus";

const env = (over: Partial<Environment> = {}): Environment => ({
  id: "env_prod",
  projectId: "prj",
  name: "production",
  kind: "shared",
  tier: "production",
  createdAt: "2026-01-01T00:00:00Z",
  ...over,
});
const item = (over: Partial<ContractItemMeta> = {}): ContractItemMeta => ({
  name: "PORT",
  sensitive: false,
  type: "number",
  required: { kind: "always" },
  ...over,
});
const server = (over: Partial<ServerItem> = {}): ServerItem => ({
  name: "PORT",
  sensitive: false,
  source: "self",
  versionId: "ver_1",
  value: "8080",
  ...over,
});

describe("cell states", () => {
  it("set wins over the contract", () => {
    expect(cellStateOf(server(), item(), env())).toBe("set");
  });
  it("a required item with a default is covered, without one it is missing", () => {
    expect(cellStateOf(undefined, item({ defaultValue: "3000" }), env())).toBe("covered_by_default");
    expect(cellStateOf(undefined, item(), env())).toBe("missing_required");
  });
  it("tier selectors apply to their tier only; derived environments use their root", () => {
    const prodOnly = item({ required: { kind: "selector", selector: { kind: "tier", tier: "production" } } });
    expect(cellStateOf(undefined, prodOnly, env({ tier: "development" }))).toBe("unset_optional");
    const byRoot = item({ required: { kind: "selector", selector: { kind: "environments", environmentIds: ["env_root"] } } });
    expect(requiredHere(byRoot, env({ id: "env_child", parentEnvironmentId: "env_root" }))).toBe(true);
  });
});

describe("sensitivity", () => {
  it("items outside the contract are secrets", () => {
    expect(isSensitive(undefined, undefined)).toBe(true);
    expect(isSensitive(undefined, item())).toBe(false);
    expect(isSensitive(server({ sensitive: true }), item())).toBe(true);
  });
  it("secrets get a blind editor, enums and booleans a choice", () => {
    expect(editorKind(true, item({ type: "enum", enumValues: ["a"] }))).toEqual({ kind: "secret" });
    expect(editorKind(false, item({ type: "enum", enumValues: ["debug", "info"] }))).toEqual({
      kind: "options",
      options: ["debug", "info"],
    });
    expect(editorKind(false, item({ type: "boolean" }))).toEqual({ kind: "options", options: ["true", "false"] });
    expect(editorKind(false, item())).toEqual({ kind: "text" });
  });
});

describe("change sets", () => {
  it("guards own values with the reviewed version, never inherited ones", () => {
    const drafts = new Map<string, Draft>([
      ["PORT", { op: "set", value: "9090" }],
      ["LOG_LEVEL", { op: "set", value: "warn" }],
      ["OLD", { op: "delete" }],
      ["NEW", { op: "set", value: "x" }],
    ]);
    const reviewed = new Map<string, ServerItem>([
      ["PORT", server({ versionId: "ver_port" })],
      ["LOG_LEVEL", server({ name: "LOG_LEVEL", source: "parent", versionId: "ver_parent" })],
      ["OLD", server({ name: "OLD", versionId: "ver_old" })],
    ]);
    expect(buildChanges(drafts, reviewed)).toEqual([
      { op: "set", item: "PORT", value: "9090", expectedVersionId: "ver_port" },
      { op: "set", item: "LOG_LEVEL", value: "warn" },
      { op: "delete", item: "OLD", expectedVersionId: "ver_old" },
      { op: "set", item: "NEW", value: "x" },
    ]);
  });
  it("names draft kinds", () => {
    expect(draftKind({ op: "set", value: "1" }, server())).toBe("edited");
    expect(draftKind({ op: "set", value: "1" }, server({ source: "parent" }))).toBe("new");
    expect(draftKind({ op: "set", value: "1" }, undefined)).toBe("new");
    expect(draftKind({ op: "delete" }, server())).toBe("deleted");
  });
});

describe(".env", () => {
  it("parses the boring subset and strips one level of quotes", () => {
    expect(parseDotenv('# c\nA=1\n\nexport B="two words"\nC=\'x\'')).toEqual([
      { name: "A", value: "1" },
      { name: "B", value: "two words" },
      { name: "C", value: "x" },
    ]);
  });
  it("refuses ambiguous input as a whole", () => {
    expect(parseDotenv("A=1\nnot a line")).toBeNull();
    expect(parseDotenv("lower=1")).toBeNull();
  });
  it("quotes only when needed and round-trips", () => {
    expect(dotenvLine("PORT", "8080")).toBe("PORT=8080");
    expect(dotenvLine("URL", "https://x.example/a?b=c")).toBe("URL=https://x.example/a?b=c");
    for (const value of ['say "hi"\nback\\slash', "a\\nb", "two words"]) {
      expect(parseDotenv(dotenvLine("MSG", value))).toEqual([{ name: "MSG", value }]);
    }
  });
});

describe("generated secrets", () => {
  it("are 32 random bytes in base64url", () => {
    const a = generateSecret();
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(generateSecret()).not.toBe(a);
  });
});

describe("sync coverage", () => {
  const target = (mapping: SyncTarget["mapping"], over: Partial<SyncTarget> = {}): SyncTarget => ({
    id: "snt",
    organizationId: "org",
    projectId: "prj",
    environmentId: "env",
    connectionId: "pcn",
    destination: { repo: "api" },
    mapping,
    removeOrphans: false,
    redeploy: false,
    state: "active",
    disabledReason: null,
    failureCount: 0,
    needsSync: false,
    lastAttemptAt: null,
    lastResult: null,
    createdAt: "2026-01-01T00:00:00Z",
    version: 1,
    updatedAt: null,
    ...over,
  });
  it("wildcards cover everything but their exclusions", () => {
    const t = target({ kind: "wildcard", exclude: ["SECRET_*", "PORT"] } as SyncTarget["mapping"]);
    expect(targetCoversItem(t, "DATABASE_URL")).toBe(true);
    expect(targetCoversItem(t, "PORT")).toBe(false);
    expect(targetCoversItem(t, "SECRET_KEY")).toBe(false);
  });
  it("explicit mappings cover their items and status follows renames", () => {
    const t = target({ kind: "explicit", items: [{ name: "PORT", rename: "APP_PORT" }] } as SyncTarget["mapping"]);
    expect(targetCoversItem(t, "PORT")).toBe(true);
    expect(targetCoversItem(t, "OTHER")).toBe(false);
    expect(syncTargetItemStatus(t, [{ name: "app_port", state: "written" }], "PORT")).toBe("synced");
    expect(syncTargetItemStatus(t, [{ name: "APP_PORT", state: "failed-write" }], "PORT")).toBe("failed");
    expect(syncTargetItemStatus({ ...t, needsSync: true }, [{ name: "APP_PORT", state: "written" }], "PORT")).toBe("pending");
  });
});
