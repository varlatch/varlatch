// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import type { Environment, Project, Requirement } from "@varlatch/protocol";
import {
  consequences,
  coverage,
  draftBody,
  draftErrors,
  draftFrom,
  entryError,
  matchParts,
  requirementSentence,
  sameDraft,
  targetParts,
  type RequirementDraft,
} from "../src/features/access/requirements";
import type { Names } from "../src/features/access/model";

const project: Project = { id: "prj_api", slug: "api", name: "API" } as Project;
const env = (id: string, name: string, parentEnvironmentId: string | null = null): Environment =>
  ({ id, projectId: project.id, name, kind: "standard", tier: "production", parentEnvironmentId, createdAt: "2026-10-01T00:00:00Z" }) as Environment;
const environments = [
  env("env_prod", "production"),
  env("env_preview", "preview-42", "env_prod"),
  { ...env("env_stage", "staging"), tier: "staging" } as Environment,
  { ...env("env_other", "other"), tier: "production" } as Environment,
];
const names: Names = {
  project: (id) => (id === project.id ? project : undefined),
  environment: (id) => environments.find((e) => e.id === id),
  team: () => undefined,
};

// The shape production uses: one Environment, devices pinned by node ID.
const pinned: Requirement = {
  id: "req_pinned",
  kind: "tailnet",
  target: { kind: "environments", environmentIds: ["env_prod"] },
  selector: { tailnet: "example.ts.net", nodes: ["nAbc123CNTRL", "nDef456CNTRL"] },
  version: 1,
  updatedAt: null,
};
const tagged: Requirement = {
  id: "req_tagged",
  kind: "tailnet",
  target: { kind: "tier", tier: "production" },
  selector: { tailnet: "example.ts.net", tags: ["tag:prod"] },
  version: 3,
  updatedAt: null,
};

const users: Requirement = {
  id: "req_users",
  kind: "tailnet",
  target: { kind: "environments", environmentIds: ["env_prod", "env_gone"] },
  selector: { tailnet: "example.ts.net", nodes: ["nAbc123CNTRL"], tags: ["tag:prod"], users: ["alice@example.com"] },
  version: 7,
  updatedAt: null,
};
const edit = (d: RequirementDraft, f: (d: RequirementDraft) => void): RequirementDraft => {
  const next = structuredClone(d);
  f(next);
  return next;
};
const texts = (c: { text: string }[]) => c.map((x) => x.text);

describe("requirement drafts", () => {
  it("round-trips every target and selector field, for every shape", () => {
    for (const req of [pinned, tagged, users]) {
      const body = draftBody(draftFrom(req));
      expect(body.target).toEqual(req.target);
      expect(body.selector).toEqual(req.selector);
    }
  });

  it("keeps every other field when one changes", () => {
    const changed = draftBody(edit(draftFrom(users), (d) => d.selector.tags.push("tag:ci")));
    expect(changed).toEqual({
      target: { kind: "environments", environmentIds: ["env_prod", "env_gone"] },
      selector: { tailnet: "example.ts.net", nodes: ["nAbc123CNTRL"], tags: ["tag:prod", "tag:ci"], users: ["alice@example.com"] },
    });
    // Production's shape: one environment, one tag.
    const prod: Requirement = { ...pinned, selector: { tailnet: "example.ts.net", tags: ["tag:runner"] } };
    expect(draftBody(edit(draftFrom(prod), (d) => (d.selector.tailnet = "other.ts.net")))).toEqual({
      target: { kind: "environments", environmentIds: ["env_prod"] },
      selector: { tailnet: "other.ts.net", tags: ["tag:runner"] },
    });
  });

  it("sees an unchanged draft as unchanged, and a change of case or spaces in the tailnet as a change", () => {
    expect(sameDraft(draftFrom(users), draftFrom(users))).toBe(true);
    expect(sameDraft(draftFrom(users), edit(draftFrom(users), (d) => d.selector.users.pop()))).toBe(false);
    // The evaluator compares the tailnet exactly: nothing here may normalize it.
    expect(sameDraft(draftFrom(users), edit(draftFrom(users), (d) => (d.selector.tailnet = "EXAMPLE.TS.NET")))).toBe(false);
    expect(sameDraft(draftFrom(users), edit(draftFrom(users), (d) => (d.selector.tailnet = " example.ts.net ")))).toBe(false);
    expect(draftBody(edit(draftFrom(users), (d) => (d.selector.tailnet = "Example.ts.net"))).selector.tailnet).toBe("Example.ts.net");
  });

  it("keeps a stored tailnet as it is, but refuses spaces in a new or changed one", () => {
    const spaced: Requirement = { ...tagged, selector: { tailnet: " example.ts.net", tags: ["tag:prod"] } };
    const stored = draftFrom(spaced);
    expect(draftErrors(edit(stored, (d) => d.selector.tags.push("tag:ci")), stored)).toEqual([]);
    expect(draftErrors(edit(stored, (d) => (d.selector.tailnet = "other.ts.net ")), stored)).toEqual([
      "Remove the spaces around the tailnet name: Tailscale compares it exactly",
    ]);
    expect(draftErrors(edit(stored, (d) => (d.selector.tailnet = " example.ts.net")))).toContain(
      "Remove the spaces around the tailnet name: Tailscale compares it exactly",
    );
    // The Before preview shows the stored value exactly, spaces included.
    expect(requirementSentence(draftBody(stored), names)).toContain('devices on " example.ts.net"');
  });

  it("refuses what the API or Tailscale would not accept", () => {
    expect(draftErrors(draftFrom(users))).toEqual([]);
    expect(draftErrors(edit(draftFrom(users), (d) => (d.selector = { tailnet: "", nodes: [], tags: [], users: [] })))).toEqual([
      "Enter the tailnet, such as example.ts.net",
      "Name at least one device, tag or user",
    ]);
    expect(draftErrors(edit(draftFrom(users), (d) => (d.target = { kind: "environments", environmentIds: [] })))).toContain("Choose at least one environment");
    expect(entryError("tags", "tag:123")).toMatch(/letter/);
    expect(entryError("tags", "tag:ok-1")).toBeNull();
    expect(entryError("nodes", "n bad")).toMatch(/node ID/);
    expect(entryError("users", "alice")).toMatch(/login name/);
  });
});

describe("what a change does", () => {
  const prodTier: RequirementDraft = { target: { kind: "tier", tier: "production" }, selector: { tailnet: "example.ts.net", nodes: [], tags: ["tag:prod"], users: [] } };

  it("follows the evaluator's coverage: a tier, and a listed root with what derives from it", () => {
    expect([...coverage({ kind: "tier", tier: "production" }, environments).ids].sort()).toEqual(["env_other", "env_preview", "env_prod"]);
    expect([...coverage({ kind: "environments", environmentIds: ["env_prod"] }, environments).ids].sort()).toEqual(["env_preview", "env_prod"]);
    expect([...coverage({ kind: "environments", environmentIds: ["env_preview"] }, environments).ids]).toEqual(["env_preview"]);
    expect(coverage({ kind: "environments", environmentIds: ["env_gone"] }, environments).unseen).toEqual(["env_gone"]);
  });

  it("an added device, tag or user loosens, naming the scope; a removed one only tightens", () => {
    const added = consequences(prodTier, edit(prodTier, (d) => d.selector.tags.push("tag:ci")), environments, names);
    expect(texts(added.loosens)).toEqual(["Devices tagged tag:ci on example.ts.net can now read values in the production tier"]);
    expect(added.tightens).toEqual([]);
    const pinnedDraft = draftFrom(users);
    const removed = consequences(pinnedDraft, edit(pinnedDraft, (d) => (d.selector.nodes = [])), environments, names);
    expect(removed.loosens).toEqual([]);
    expect(texts(removed.tightens)).toEqual(["The device with node ID nAbc123CNTRL can no longer read values it covers"]);
  });

  it("review: a tailnet that differs only in case or spaces is a change that may loosen", () => {
    const upper = edit(prodTier, (d) => (d.selector.tailnet = "EXAMPLE.TS.NET"));
    const caseOnly = consequences(upper, prodTier, environments, names);
    expect(texts(caseOnly.loosens)).toEqual([
      "Devices on example.ts.net that match it can now read values in the production tier (Tailscale compares tailnet names exactly, so a change of case or spaces alone changes which devices pass)",
    ]);
    expect(texts(caseOnly.tightens)).toEqual(["Devices on EXAMPLE.TS.NET no longer pass it"]);
    const spaced = edit(prodTier, (d) => (d.selector.tailnet = "example.ts.net "));
    const spacesOnly = consequences(spaced, prodTier, environments, names);
    expect(spacesOnly.loosens).toHaveLength(1);
    expect(texts(spacesOnly.tightens)).toEqual(['Devices on "example.ts.net " no longer pass it']);
  });

  it("a different tailnet both loosens and tightens", () => {
    const c = consequences(prodTier, edit(prodTier, (d) => (d.selector.tailnet = "other.ts.net")), environments, names);
    expect(texts(c.loosens)).toEqual(["Devices on other.ts.net that match it can now read values in the production tier"]);
    expect(texts(c.tightens)).toEqual(["Devices on example.ts.net no longer pass it"]);
  });

  it("a tier changed to another tier loosens the old one, later environments included, and tightens the new one", () => {
    const c = consequences(prodTier, edit(prodTier, (d) => (d.target = { kind: "tier", tier: "staging" })), environments, names);
    expect(texts(c.loosens)).toEqual([
      "Values in api / production, api / preview-42, api / other no longer need this requirement",
      "The production tier is no longer covered as a whole: its environments that you cannot see, and those added later, will not need this requirement",
    ]);
    expect(texts(c.tightens)).toEqual([
      "Values in api / staging now need this requirement",
      "The whole staging tier is covered, environments added to it later included",
    ]);
  });

  it("a switch from a tier to environments loosens what is left out, even if every visible environment stays", () => {
    const toEnvs = consequences(prodTier, edit(prodTier, (d) => (d.target = { kind: "environments", environmentIds: ["env_prod", "env_other"] })), environments, names);
    expect(texts(toEnvs.loosens)).toEqual([
      "The production tier is no longer covered as a whole: its environments that you cannot see, and those added later, will not need this requirement",
    ]);
    const toTier = consequences(
      edit(prodTier, (d) => (d.target = { kind: "environments", environmentIds: ["env_stage"] })),
      prodTier,
      environments,
      names,
    );
    expect(texts(toTier.loosens)).toEqual(["Values in api / staging no longer need this requirement"]);
    expect(texts(toTier.tightens)).toContain("The whole production tier is covered, environments added to it later included");
  });

  it("follows inheritance: a root covers what derives from it, a derived environment only itself", () => {
    const root = edit(prodTier, (d) => (d.target = { kind: "environments", environmentIds: ["env_prod"] }));
    const derived = edit(prodTier, (d) => (d.target = { kind: "environments", environmentIds: ["env_preview"] }));
    expect(texts(consequences(root, derived, environments, names).loosens)).toEqual(["Values in api / production no longer need this requirement"]);
    const widen = consequences(derived, root, environments, names);
    expect(widen.loosens).toEqual([]);
    expect(texts(widen.tightens)).toEqual(["Values in api / production now need this requirement"]);
  });

  it("counts environments the viewer cannot see as possible loosening when they stop being covered", () => {
    const before = draftFrom(users);
    const keep = consequences(before, edit(before, (d) => d.selector.tags.push("tag:x")), environments, names);
    expect(texts(keep.loosens).some((t) => t.includes("cannot see"))).toBe(false);
    const drop = consequences(before, edit(before, (d) => (d.target = { kind: "environments", environmentIds: ["env_prod"] })), environments, names);
    expect(texts(drop.loosens)).toEqual(["It stops covering an environment you cannot see (env_gone), and whatever derives from it"]);
  });
});

describe("requirement display", () => {
  it("names targeted environments, notes derived ones, and falls back to the ID", () => {
    const req: Requirement = { ...pinned, target: { kind: "environments", environmentIds: ["env_prod", "env_preview", "env_gone"] } };
    expect(targetParts(req.target, names)).toEqual([
      { kind: "environment", id: "env_prod", project: "api", name: "production", tier: "production", includesDerived: true },
      { kind: "environment", id: "env_preview", project: "api", name: "preview-42", tier: "production", includesDerived: false },
      { kind: "environment", id: "env_gone", includesDerived: false },
    ]);
  });

  it("lists every alternative a device can match", () => {
    expect(matchParts({ tailnet: "example.ts.net", nodes: ["nAbc"], tags: ["tag:prod"], users: ["alice@example.com"] })).toEqual([
      { kind: "device", value: "nAbc" },
      { kind: "tag", value: "tag:prod" },
      { kind: "user", value: "alice@example.com" },
    ]);
    expect(requirementSentence(pinned, names)).toBe(
      "Values in api / production (and environments derived from it) can only be read from devices on example.ts.net that match any of: device nAbc123CNTRL, device nDef456CNTRL",
    );
  });
});
