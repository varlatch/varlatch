// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import type { Environment, Project, Requirement } from "@varlatch/protocol";
import {
  formEditBlocker,
  matchParts,
  parseTags,
  requirementSentence,
  requirementUpdate,
  targetParts,
} from "../src/features/access/requirements";
import type { Names } from "../src/features/access/model";

const project: Project = { id: "prj_api", slug: "api", name: "API" } as Project;
const env = (id: string, name: string, parentEnvironmentId: string | null = null): Environment =>
  ({ id, projectId: project.id, name, kind: "standard", tier: "production", parentEnvironmentId, createdAt: "2026-10-01T00:00:00Z" }) as Environment;
const environments = [env("env_prod", "production"), env("env_preview", "preview-42", "env_prod")];
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

describe("requirement editing", () => {
  it("never turns an environment-scoped, device-pinned requirement into a tier/tag one", () => {
    expect(formEditBlocker(pinned)).toMatch(/specific environments and names devices/);
    // Empty tags keep Save disabled, so the accidental save is the one after
    // someone types a tag: that edit must be refused, not sent.
    expect(() => requirementUpdate(pinned, { tier: "production", tailnet: "example.ts.net", tags: ["tag:prod"] })).toThrow(
      /cannot edit/,
    );
  });

  it("blocks a tier requirement that names devices or users: an added tag would widen it", () => {
    for (const selector of [
      { tailnet: "example.ts.net", tags: ["tag:prod"], nodes: ["nAbc123CNTRL"] },
      { tailnet: "example.ts.net", users: ["alice@example.com"] },
    ]) {
      const req = { ...tagged, selector };
      expect(formEditBlocker(req)).toMatch(/names devices or users/);
      expect(() => requirementUpdate(req, { tier: "production", tailnet: "example.ts.net", tags: ["tag:ci"] })).toThrow();
    }
  });

  it("blocks an environment-scoped requirement even when it only uses tags", () => {
    const req = { ...pinned, selector: { tailnet: "example.ts.net", tags: ["tag:prod"] } };
    expect(formEditBlocker(req)).toMatch(/applies to specific environments,/);
  });

  it("edits a tier/tag requirement in place, versioned", () => {
    expect(formEditBlocker(tagged)).toBeNull();
    expect(requirementUpdate(tagged, { tier: "production", tailnet: " example.ts.net ", tags: parseTags("tag:prod, tag:ci,") })).toEqual({
      expectedVersion: 3,
      target: { kind: "tier", tier: "production" },
      selector: { tailnet: "example.ts.net", tags: ["tag:prod", "tag:ci"] },
    });
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
