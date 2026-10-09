// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import {
  authorizationSummary,
  describeEvent,
  emptyResolver,
  listedItems,
  segmentsText,
  type AuditEventLike,
  type NameResolver,
} from "../src/features/audit/describe";

const names: NameResolver = {
  ...emptyResolver,
  identity: (id) => ({ idn_admin: "Dev Admin", idn_agent: "claude-code-agent" })[id ?? ""],
  project: (id) => (id === "prj_api" ? "api" : undefined),
  environment: (id) => (id === "env_prod" ? { name: "production", projectId: "prj_api" } : undefined),
  target: (id) => (id === "snt_1" ? "GitHub Actions acme-org/api" : undefined),
  role: (id) => (id === "rol_use" ? "Use secrets" : undefined),
};

const event = (over: Partial<AuditEventLike>): AuditEventLike => ({
  eventId: "evt_1",
  eventType: "value.written",
  occurredAt: "2026-10-02T09:14:00Z",
  decision: "info",
  actorIdentityId: "idn_admin",
  ...over,
});

const sentence = (e: AuditEventLike, n = names) => segmentsText(describeEvent(e, n).segments);

describe("describeEvent", () => {
  it("names the place as project / environment", () => {
    expect(
      sentence(event({ resource: { projectId: "prj_api", environmentId: "env_prod", itemName: "PORT", previousVersionId: "ver_1" } })),
    ).toBe("changed PORT in api / production");
  });

  it("says set for a first value", () => {
    expect(sentence(event({ resource: { projectId: "prj_api", environmentId: "env_prod", itemName: "PORT", previousVersionId: null } }))).toBe(
      "set PORT in api / production",
    );
  });

  it("lists one or two disclosed names, counts more", () => {
    const base = { eventType: "secret.disclosed", decision: "allow", resource: { projectId: "prj_api", environmentId: "env_prod" } };
    expect(sentence(event({ ...base, metadata: { items: "STRIPE_SECRET@ver_a" } }))).toBe("revealed STRIPE_SECRET in api / production");
    expect(sentence(event({ ...base, metadata: { items: "A@v1,B@v2+v0,C@v3" } }))).toBe("revealed 3 secrets in api / production");
  });

  it("mentions withheld values on reads", () => {
    expect(
      sentence(
        event({
          eventType: "value.disclosed",
          resource: { projectId: "prj_api", environmentId: "env_prod" },
          metadata: { items: "A@1,B@2,C@3", withheld: 2 },
        }),
      ),
    ).toBe("read 3 values in api / production, 2 withheld");
  });

  it("describes a denial with its action", () => {
    const d = describeEvent(
      event({ eventType: "authorization.denied", decision: "deny", action: "secret.use", resource: { projectId: "prj_api", environmentId: "env_prod" } }),
      names,
    );
    expect(d.title).toBe("Access denied");
    expect(segmentsText(d.segments)).toBe("was denied secret.use on api / production");
  });

  it("resolves sync places through the environment", () => {
    expect(sentence(event({ eventType: "sync.target_paused", resource: { targetId: "snt_1", environmentId: "env_prod" } }))).toBe(
      "paused GitHub Actions acme-org/api for api / production",
    );
  });

  it("describes a GitHub App registered, and one refused because GitHub created it on another account", () => {
    expect(
      sentence(event({ eventType: "sync.github_app_registered", resource: { githubAppId: "gha_1" }, metadata: { via: "manifest", appId: 5254113, slug: "varlatch-acme", owner: "acme-gh", ownerType: "organization" } })),
    ).toBe("registered the GitHub App varlatch-acme on acme-gh");
    const refused = { eventType: "sync.github_app_registration_refused", decision: "deny" };
    expect(
      sentence(event({ ...refused, metadata: { reason: "owner-mismatch", slug: "varlatch-acme", owner: "jeremydeceuster", ownerType: "user", account: "acme-gh", accountType: "organization" } })),
    ).toBe("refused the GitHub App varlatch-acme: GitHub created it on jeremydeceuster, not on acme-gh");
    expect(sentence(event({ ...refused, metadata: { reason: "organization-has-app", slug: "varlatch-acme-2" } }))).toBe(
      "refused the GitHub App varlatch-acme-2: the organization already had one",
    );
  });

  it("grants read as role names, then readable actions", () => {
    expect(
      sentence(event({ eventType: "grant.created", resource: { subjectIdentityId: "idn_agent" }, metadata: { roleId: "rol_use" } })),
    ).toBe("granted Use secrets to claude-code-agent");
    expect(
      sentence(event({ eventType: "grant.created", resource: { subjectIdentityId: "idn_agent" }, metadata: { actions: "secret.use" } })),
    ).toBe("granted Use secrets to claude-code-agent");
    expect(
      sentence(event({ eventType: "grant.created", resource: { subjectIdentityId: "idn_x" }, metadata: { actions: "a,b,c" } })),
    ).toBe("granted 3 permissions to an identity");
  });

  it("never shows a raw ID when a name is unknown", () => {
    const s = sentence(
      event({ eventType: "identity.retired", resource: { identityId: "idn_unknown" } }),
      emptyResolver,
    );
    expect(s).toBe("retired an identity");
    expect(s).not.toContain("idn_");
  });

  it("falls back to the event type for unknown events", () => {
    const d = describeEvent(event({ eventType: "future.thing_happened", resource: { projectId: "prj_api" } }), names);
    expect(segmentsText(d.segments)).toBe("future.thing_happened in api");
    expect(d.title).toBe("Future thing happened");
  });

  it("parses listed items", () => {
    expect(listedItems({ items: "A@v1,B@v2+v1" })).toEqual(["A", "B"]);
    expect(listedItems({})).toEqual([]);
  });
});

describe("authorizationSummary", () => {
  it("explains a missing grant", () => {
    expect(
      authorizationSummary(event({ decision: "deny", action: "secret.use", authorization: { denial: "no-grant", requirements: [] } })),
    ).toBe("No grant covers secret.use here.");
  });

  it("explains a failed network requirement", () => {
    expect(
      authorizationSummary(
        event({
          decision: "deny",
          authorization: { denial: "requirement-failed", requirements: [{ satisfied: false, reason: "no-tailnet-context" }] },
        }),
      ),
    ).toContain("did not come from the tailnet");
  });

  it("counts the grants that allowed a request", () => {
    expect(authorizationSummary(event({ decision: "allow", authorization: { grantIds: ["g1", "g2"] } }))).toBe("Allowed by 2 grants.");
  });
});
