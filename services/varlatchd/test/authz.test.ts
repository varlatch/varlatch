// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import {
  evaluate,
  type EvaluateInput,
  type GrantRecord,
  type ResourceContext,
  type TailnetRequirementRecord,
} from "../src/authz/evaluate.js";

const org = "org_1";
const project = "prj_1";
const devEnv: ResourceContext["environment"] = {
  id: "env_dev",
  rootId: "env_dev",
  tier: "development",
};
const stagingEnv = { id: "env_stg", rootId: "env_stg", tier: "staging" as const };
const prodEnv = { id: "env_prod", rootId: "env_prod", tier: "production" as const };
const prodChild = { id: "env_pr1", rootId: "env_prod", tier: "production" as const };

function input(partial: Partial<EvaluateInput> & Pick<EvaluateInput, "action" | "resource">): EvaluateInput {
  return {
    orgRole: null,
    grants: [],
    requirements: [],
    tailnetContext: null,
    ...partial,
  };
}

describe("default deny", () => {
  it("denies with no role and no grants", () => {
    const r = evaluate(
      input({ action: "secret.reveal", resource: { organizationId: org, projectId: project, environment: devEnv } }),
    );
    expect(r.allowed).toBe(false);
    expect(r.denial).toBe("no-grant");
  });
});

describe("secret.use (ADR-0004/0022)", () => {
  const useGrant: GrantRecord = {
    id: "grt_use",
    subjectIdentityId: "idn_agent",
    scope: { kind: "project", projectId: project },
    actions: ["secret.use"],
  };

  it("is never in the member bundle on any tier", () => {
    for (const environment of [devEnv, stagingEnv, prodEnv]) {
      const r = evaluate(
        input({
          action: "secret.use",
          resource: { organizationId: org, projectId: project, environment },
          orgRole: "member",
        }),
      );
      expect(r.allowed).toBe(false);
    }
  });

  it("arrives only via an explicit Grant, including on production", () => {
    const r = evaluate(
      input({
        action: "secret.use",
        resource: { organizationId: org, projectId: project, environment: prodEnv },
        grants: [useGrant],
      }),
    );
    expect(r.allowed).toBe(true);
    expect(r.provenance.grantIds).toEqual(["grt_use"]);
  });

  it("does not imply secret.reveal", () => {
    const r = evaluate(
      input({
        action: "secret.reveal",
        resource: { organizationId: org, projectId: project, environment: devEnv },
        grants: [useGrant],
      }),
    );
    expect(r.allowed).toBe(false);
    expect(r.denial).toBe("no-grant");
  });

  it("is tailnet-constrained: a targeting Requirement restricts it", () => {
    const req: TailnetRequirementRecord = {
      id: "req_1",
      target: { kind: "tier", tier: "production" },
      selector: { tailnet: "example.ts.net", tags: ["tag:prod"] },
    };
    const denied = evaluate(
      input({
        action: "secret.use",
        resource: { organizationId: org, projectId: project, environment: prodEnv },
        grants: [useGrant],
        requirements: [req],
      }),
    );
    expect(denied.allowed).toBe(false);
    expect(denied.denial).toBe("requirement-failed");
    const allowed = evaluate(
      input({
        action: "secret.use",
        resource: { organizationId: org, projectId: project, environment: prodEnv },
        grants: [useGrant],
        requirements: [req],
        tailnetContext: { tailnet: "example.ts.net", nodeId: "n1", tags: ["tag:prod"] },
      }),
    );
    expect(allowed.allowed).toBe(true);
  });
});

describe("member bundle (ADR-0015 §5)", () => {
  const asMember = (action: EvaluateInput["action"], environment: ResourceContext["environment"]) =>
    evaluate(
      input({
        action,
        resource: { organizationId: org, projectId: project, environment },
        orgRole: "member",
      }),
    );

  it("development: read, reveal, write", () => {
    expect(asMember("config.value.write", devEnv).allowed).toBe(true);
    expect(asMember("secret.reveal", devEnv).allowed).toBe(true);
  });

  it("staging: reveal but no mutation", () => {
    expect(asMember("secret.reveal", stagingEnv).allowed).toBe(true);
    expect(asMember("config.value.write", stagingEnv).allowed).toBe(false);
  });

  it("production: metadata only — reveal/read/write all denied", () => {
    expect(asMember("environment.read", prodEnv).allowed).toBe(true);
    expect(asMember("config.metadata.read", prodEnv).allowed).toBe(true);
    expect(asMember("config.value.read", prodEnv).allowed).toBe(false);
    expect(asMember("secret.reveal", prodEnv).allowed).toBe(false);
    expect(asMember("config.value.write", prodEnv).allowed).toBe(false);
  });

  it("member cannot activate contracts or manage identities", () => {
    expect(
      evaluate(
        input({
          action: "contract.activate",
          resource: { organizationId: org, projectId: project },
          orgRole: "member",
        }),
      ).allowed,
    ).toBe(false);
  });
});

describe("admin role", () => {
  it("allows org-scoped administration but not bypass of requirements", () => {
    const req: TailnetRequirementRecord = {
      id: "req_1",
      target: { kind: "tier", tier: "production" },
      selector: { tailnet: "example.ts.net", tags: ["tag:prod"] },
    };
    const denied = evaluate(
      input({
        action: "secret.reveal",
        resource: { organizationId: org, projectId: project, environment: prodEnv },
        orgRole: "admin",
        requirements: [req],
      }),
    );
    expect(denied.allowed).toBe(false);
    expect(denied.denial).toBe("requirement-failed");
    expect(denied.requirements[0]).toMatchObject({ satisfied: false, reason: "no-tailnet-context" });
  });
});

describe("explicit grants", () => {
  const ciGrant: GrantRecord = {
    id: "grt_ci",
    subjectIdentityId: "idn_ci",
    scope: {
      kind: "environments",
      projectId: project,
      selector: { kind: "tier", tier: "production" },
    },
    actions: ["config.value.read", "secret.reveal"],
  };

  it("machine identity with tier-scoped grant can reveal production", () => {
    const r = evaluate(
      input({
        action: "secret.reveal",
        resource: { organizationId: org, projectId: project, environment: prodEnv },
        grants: [ciGrant],
      }),
    );
    expect(r.allowed).toBe(true);
    expect(r.provenance.grantIds).toEqual(["grt_ci"]);
  });

  it("grant does not leak across projects", () => {
    const r = evaluate(
      input({
        action: "secret.reveal",
        resource: { organizationId: org, projectId: "prj_other", environment: prodEnv },
        grants: [ciGrant],
      }),
    );
    expect(r.allowed).toBe(false);
  });

  it("explicit-environment selector covers the root's derived children", () => {
    const grant: GrantRecord = {
      id: "grt_env",
      subjectIdentityId: "idn_x",
      scope: {
        kind: "environments",
        projectId: project,
        selector: { kind: "environments", environmentIds: ["env_prod"] },
      },
      actions: ["config.value.read"],
    };
    const r = evaluate(
      input({
        action: "config.value.read",
        resource: { organizationId: org, projectId: project, environment: prodChild },
        grants: [grant],
      }),
    );
    expect(r.allowed).toBe(true);
  });

  it("grants union: role denial plus applicable grant allows", () => {
    const r = evaluate(
      input({
        action: "secret.reveal",
        resource: { organizationId: org, projectId: project, environment: prodEnv },
        orgRole: "member",
        grants: [ciGrant],
      }),
    );
    expect(r.allowed).toBe(true);
  });
});

describe("tailnet requirements (ADR-0014)", () => {
  const req: TailnetRequirementRecord = {
    id: "req_prod",
    target: { kind: "tier", tier: "production" },
    selector: { tailnet: "example.ts.net", tags: ["tag:prod"], nodes: ["node-abc"] },
  };
  const grant: GrantRecord = {
    id: "grt_w",
    subjectIdentityId: "idn_w",
    scope: { kind: "environments", projectId: project, selector: { kind: "tier", tier: "production" } },
    actions: ["config.value.read", "secret.reveal"],
  };
  const base = {
    action: "secret.reveal" as const,
    resource: { organizationId: org, projectId: project, environment: prodEnv },
    grants: [grant],
    requirements: [req],
  };

  it("satisfied by matching tag from the pinned tailnet", () => {
    const r = evaluate(
      input({
        ...base,
        tailnetContext: { tailnet: "example.ts.net", nodeId: "n1", tags: ["tag:prod"] },
      }),
    );
    expect(r.allowed).toBe(true);
    expect(r.requirements[0]).toMatchObject({ satisfied: true, by: "tag:prod" });
  });

  it("rejects a foreign tailnet even with matching tags", () => {
    const r = evaluate(
      input({
        ...base,
        tailnetContext: { tailnet: "other.ts.net", nodeId: "n1", tags: ["tag:prod"] },
      }),
    );
    expect(r.allowed).toBe(false);
    expect(r.requirements[0]).toMatchObject({ satisfied: false, reason: "tailnet-mismatch" });
  });

  it("requirement never creates permission", () => {
    const r = evaluate(
      input({
        ...base,
        grants: [],
        tailnetContext: { tailnet: "example.ts.net", nodeId: "node-abc", tags: [] },
      }),
    );
    expect(r.allowed).toBe(false);
    expect(r.denial).toBe("no-grant");
  });

  it("does not constrain unrelated tiers or non-retrieval actions", () => {
    const dev = evaluate(
      input({
        action: "secret.reveal",
        resource: { organizationId: org, projectId: project, environment: devEnv },
        orgRole: "member",
        requirements: [req],
      }),
    );
    expect(dev.allowed).toBe(true);
    const meta = evaluate(
      input({
        action: "environment.read",
        resource: { organizationId: org, projectId: project, environment: prodEnv },
        orgRole: "member",
        requirements: [req],
      }),
    );
    expect(meta.allowed).toBe(true);
    expect(meta.requirements).toEqual([]);
  });
});
