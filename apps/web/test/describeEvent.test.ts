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
import { placeLabel, withoutTLS } from "../src/features/access/places";

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

  it("calls a read made for an env file a read for export, never a download (ADR-0053)", () => {
    const secret = describeEvent(event({ eventType: "secret.disclosed", metadata: { mode: "requested", items: "API_KEY@v1", purpose: "export" } }), names);
    expect(secret.title).toBe("Secrets read for export");
    expect(segmentsText(secret.segments)).toMatch(/^read .* for export$/);
    const plain = describeEvent(event({ eventType: "value.disclosed", metadata: { items: "PORT@v1", withheld: 0, purpose: "export" } }), names);
    expect(plain.title).toBe("Values read for export");
    expect(segmentsText(plain.segments)).not.toMatch(/download/);
  });

  it("says what drift a repair found, by kind and name, never who changed it (ADR-0050)", () => {
    const d = describeEvent(
      event({
        eventType: "sync.drift_detected",
        resource: { targetId: "snt_1", environmentId: "env_prod" },
        metadata: { changed: "PORT", removed: "", recreated: "OLD_KEY", count: 2, items: "PORT", generation: 7 },
      }),
      names,
    );
    expect(d.title).toBe("Drift detected");
    expect(segmentsText(d.segments)).toBe(
      "found 2 names that differed from what Varlatch last wrote to GitHub Actions acme-org/api (changed: PORT; back after deletion: OLD_KEY)",
    );
  });

  it("resolves sync places through the environment", () => {
    expect(sentence(event({ eventType: "sync.target_paused", resource: { targetId: "snt_1", environmentId: "env_prod" } }))).toBe(
      "paused GitHub Actions acme-org/api for api / production",
    );
  });

  it("says when a credential replacement resumed an integration (#57)", () => {
    const resource = { targetId: "snt_1", environmentId: "env_prod" };
    expect(sentence(event({ eventType: "sync.target_resumed", resource }))).toBe("resumed GitHub Actions acme-org/api for api / production");
    expect(sentence(event({ eventType: "sync.target_resumed", resource, metadata: { cause: "credential_replaced", connectionId: "pcn_1" } }))).toBe(
      "resumed GitHub Actions acme-org/api for api / production after the credential was replaced",
    );
  });

  it("describes a GitHub App registered, and one refused because GitHub created it on another account", () => {
    expect(
      sentence(event({ eventType: "sync.github_app_registered", resource: { githubAppId: "gha_1" }, metadata: { via: "manifest", appId: 5254113, slug: "varlatch-acme", owner: "acme-gh", ownerType: "organization" } })),
    ).toBe("registered the GitHub App varlatch-acme on acme-gh");
    const abandoned = { eventType: "sync.github_app_registration_abandoned", decision: "info" };
    expect(sentence(event({ ...abandoned, metadata: { reason: "expired", slug: "varlatch-acme", appId: 5254113 } }))).toBe(
      "deleted the key of the pending GitHub App varlatch-acme: not attached within the hour",
    );
    expect(sentence(event({ ...abandoned, metadata: { reason: "machine-credential", slug: "varlatch-acme" } }))).toBe(
      "deleted the key of the pending GitHub App varlatch-acme: a machine credential cannot approve attaching it",
    );
    expect(sentence(event({ ...abandoned, metadata: { reason: "discarded", slug: "varlatch-acme" } }))).toBe(
      "deleted the key of the pending GitHub App varlatch-acme: discarded before it was attached",
    );
    const refused = { eventType: "sync.github_app_registration_refused", decision: "deny" };
    expect(
      sentence(event({ ...refused, metadata: { reason: "owner-mismatch", slug: "varlatch-acme", owner: "jeremydeceuster", ownerType: "user", account: "acme-gh", accountType: "organization" } })),
    ).toBe("refused the GitHub App varlatch-acme: GitHub created it on jeremydeceuster, not on acme-gh");
    expect(sentence(event({ ...refused, metadata: { reason: "organization-has-app", slug: "varlatch-acme-2" } }))).toBe(
      "refused the GitHub App varlatch-acme-2: the organization already had one",
    );
  });

  it("describes a key rotation and an App's removal by what they covered", () => {
    expect(
      sentence(event({ eventType: "sync.github_app_key_rotated", metadata: { appId: 5254113, slug: "varlatch-acme", version: 2, connections: "pcn_a,pcn_b", reauthorizedTargets: "snt_1,snt_2,snt_3" } })),
    ).toBe("rotated the key of the GitHub App varlatch-acme, re-authorizing 3 integrations");
    expect(sentence(event({ eventType: "sync.github_app_key_rotated", metadata: { slug: "varlatch-acme", reauthorizedTargets: null } }))).toBe(
      "rotated the key of the GitHub App varlatch-acme, re-authorizing 0 integrations",
    );
    expect(
      sentence(event({ eventType: "sync.github_app_removed", metadata: { appId: 5254113, slug: "varlatch-acme", revokedConnections: "pcn_a", disabledTargets: "snt_1" } })),
    ).toBe("removed the GitHub App varlatch-acme, revoking 1 connection");
  });

  it("says imported for an imported App, and how an installation listing went", () => {
    expect(
      sentence(event({ eventType: "sync.github_app_registered", metadata: { via: "import", appId: 5254113, slug: "varlatch-acme", owner: "acme-gh", ownerType: "organization" } })),
    ).toBe("imported the GitHub App varlatch-acme on acme-gh");
    const listed = { eventType: "sync.github_app_installations_listed" };
    expect(sentence(event({ ...listed, metadata: { status: "ok", count: 2, truncated: false } }))).toBe("listed where the GitHub App is installed: 2 installations");
    expect(sentence(event({ ...listed, metadata: { status: "credential-rejected", count: 0 } }))).toBe(
      "listed where the GitHub App is installed: credential rejected",
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

describe("values typed into pages and applications (ADR-0064)", () => {
  const used = (metadata: Record<string, unknown>, eventType = "capability.exercised") =>
    sentence(event({ eventType, resource: { agentIdentityId: "idn_agent", projectId: "prj_api", environmentId: "env_prod" }, metadata: { items: "API_KEY@ver_1", ...metadata } }));
  it("says where, as the broker said, and nothing more of a host", () => {
    expect(used({ destination: "api.example.com:443" })).toBe("used API_KEY for claude-code-agent in api / production");
    expect(used({ destination: "web:https://portal.example.com:443/login", destinationKind: "web" })).toBe("used API_KEY for claude-code-agent at https://portal.example.com/login in api / production");
    expect(used({ destination: "app:CRM Client@idn_abc2", destinationKind: "app" })).toBe("used API_KEY for claude-code-agent in CRM Client on its machine in api / production");
    expect(used({ reason: "destination-mismatch", destination: "web:unreadable", destinationKind: "web" }, "capability.denied")).toBe("was refused a capability use at web:unreadable in api / production");
  });
  it("warns of a page without TLS, its own or the one around it", () => {
    const http = "web:http://intra.example:80/login";
    expect(used({ destination: http, destinationKind: "web" })).toBe("used API_KEY for claude-code-agent at http://intra.example/login (http: not encrypted) in api / production");
    expect(used({ reason: "destination-mismatch", destination: http, destinationKind: "web" }, "capability.denied")).toContain("at http://intra.example/login (http: not encrypted)");
    expect(used({ destination: "web:https://a.example:443/f", topDestination: http, destinationKind: "web" })).toContain("https://a.example/f (http: not encrypted)");
    expect(["web:https://a.example:443/http://", "web:80", "http.example.com:80", "app:web:http://x@idn_abc2"].filter(withoutTLS)).toEqual([]);
  });
  it("labels a destination", () => {
    const name = (id: string) => (id === "idn_abc2" ? "desk-7" : id);
    expect(["api.example.com:443", "web:443", "web:https://portal.example.com:443/", "web:http://*.intra.example:8080/a", "web:https://[2001:db8::1]:443/x", "app:CRM: Client@idn_abc2"].map((d) => placeLabel(d, name))).toEqual([
      "api.example.com:443", "web:443", "https://portal.example.com", "http://*.intra.example:8080/a", "https://[2001:db8::1]/x", "CRM: Client on desk-7",
    ]);
  });
});

describe("capabilities for another broker and exercise-only sign-ins (ADR-0060)", () => {
  const issued = (over: Partial<AuditEventLike>) =>
    sentence(event({ eventType: "capability.issued", resource: { agentIdentityId: "idn_agent", projectId: "prj_api", environmentId: "env_prod", ...over.resource }, metadata: { items: "API_KEY", ...over.metadata } }));
  it("names the broker it is for and that it works once, only when they are said", () => {
    expect(issued({})).toBe("let claude-code-agent use API_KEY in api / production");
    expect(issued({ resource: { brokerIdentityId: "idn_admin" }, metadata: { singleUse: true } })).toBe("let claude-code-agent use API_KEY through Dev Admin once in api / production");
  });
  it("says what an exercise-only sign-in allows, and what its credential was denied", () => {
    const created = { eventType: "oidc_binding.created", resource: { identityId: "idn_agent" } };
    expect(sentence(event({ ...created, metadata: {} }))).toBe("let claude-code-agent sign in with OIDC");
    expect(sentence(event({ ...created, metadata: { exerciseOnly: true } }))).toBe("let claude-code-agent use capabilities, and nothing else, with OIDC");
    expect(sentence(event({ eventType: "authorization.denied", decision: "deny", metadata: { reason: "exercise_only_credential" } }))).toBe(
      "was denied a request its exercise-only credential may not make",
    );
  });
});

describe("security control events (ADR-0054)", () => {
  it("says which control changed, how, and whether it was weakened with an approval", () => {
    const changed = (metadata: Record<string, unknown>) =>
      event({ eventType: "security_control.changed", resource: { control: "credential-lifetime" }, metadata });
    expect(sentence(changed({ control: "credential-lifetime", fromMode: "off", toMode: "report", loosened: false, loosenedFields: "" }))).toBe(
      "changed security control credential-lifetime from off to report",
    );
    const weakened = changed({ control: "credential-lifetime", fromMode: "report", toMode: "off", loosened: true, loosenedFields: "mode", approvalId: "apr_1" });
    expect(sentence(weakened)).toBe("changed security control credential-lifetime from report to off, approved with a trusted passkey");
    expect(describeEvent(weakened, names).title).toBe("Security control weakened");
    expect(sentence(changed({ control: "credential-lifetime", fromMode: "report", toMode: "report", loosened: false }))).toBe(
      "changed security control credential-lifetime (lifetimes only)",
    );
  });

  it("describes the host operator's reset and the approvals it closed", () => {
    const reset = event({
      eventType: "security_control.reset",
      actorIdentityId: null,
      resource: { control: "admin-step-up" },
      metadata: { control: "admin-step-up", operator: true, fromMode: "report", toMode: "off", approvalsClosed: 2 },
    });
    expect(sentence(reset)).toBe("reset security control admin-step-up to off (the host operator's reset), closing 2 pending approvals");
    expect(describeEvent(reset, names).title).toBe("Security control reset");
  });

  it("summarizes an hour of what a control in report mode would have done", () => {
    const summary = event({
      eventType: "security_control.would_block",
      resource: { control: "admin-step-up" },
      metadata: { control: "admin-step-up", configVersion: 1, operation: "grant.create", reason: "no-approval", bucketHour: "2026-11-10T10:00:00.000Z", count: 3 },
    });
    expect(sentence(summary)).toBe("would have been stopped 3 times by admin-step-up doing grant.create (no-approval) in report mode");
    expect(describeEvent(summary, names).title).toBe("Security control report");
  });
});

describe("upgrades, from the host and asked for in the web app (ADR-0065)", () => {
  const upgrade = (eventType: string, metadata: Record<string, unknown>, actorIdentityId: string | null = "idn_admin") =>
    event({ eventType, actorIdentityId, metadata: { from: "0.51.0", to: "0.52.0", requestId: "upr_" + "a".repeat(26), ...metadata } });
  it("says where an upgrade came from: the web app, or the host", () => {
    const web = upgrade("installation.upgraded", { source: "web" }, null);
    expect(describeEvent(web, names).title).toBe("Varlatch upgraded");
    expect(sentence(web)).toBe("upgraded Varlatch from 0.51.0 to 0.52.0, as asked in the web app");
    expect(sentence(upgrade("installation.upgraded", { source: "host", requestId: null }, null))).toBe("upgraded Varlatch from 0.51.0 to 0.52.0 on the host");
  });
  it("describes a request, its cancel by an admin or its expiry, a cancel too late, a refusal and an undo", () => {
    expect(sentence(upgrade("installation.upgrade_requested", { approvalId: "apr_1" }))).toBe(
      "asked the host to upgrade Varlatch from 0.51.0 to 0.52.0, approved with a passkey",
    );
    const cancelled = upgrade("installation.upgrade_cancelled", { reason: "cancelled" });
    expect(describeEvent(cancelled, names).title).toBe("Upgrade request cancelled");
    expect(sentence(cancelled)).toBe("cancelled the request to upgrade to 0.52.0");
    const expired = upgrade("installation.upgrade_cancelled", { reason: "expired" }, null);
    expect(describeEvent(expired, names).title).toBe("Upgrade request expired");
    expect(sentence(expired)).toBe("the request to upgrade to 0.52.0 expired before the host took it");
    expect(sentence(upgrade("installation.upgrade_cancel_too_late", {}))).toBe("tried to cancel the upgrade to 0.52.0, which the host had taken");
    expect(sentence(upgrade("installation.upgrade_refused", { reason: "no-backup-destination" }, null))).toBe(
      "the host refused the upgrade to 0.52.0: no backup destination",
    );
    const undone = upgrade("installation.upgrade_undone", { reason: "admin status: a check failed", source: "web" }, null);
    expect(describeEvent(undone, names).title).toBe("Upgrade undone");
    expect(sentence(undone)).toBe("a health check of 0.52.0 failed, so the host went back to 0.51.0");
  });
});
