// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it, vi } from "vitest";
import type { OrgIdentity } from "@varlatch/sdk";
vi.hoisted(() => {
  vi.stubGlobal("location", { origin: "https://varlatch.example", hostname: "varlatch.example" });
});
vi.mock("better-auth/client", () => ({ createAuthClient: () => ({ signOut: async () => {}, signIn: { passkey: async () => ({}) } }) }));
vi.mock("@better-auth/passkey/client", () => ({ passkeyClient: () => ({}) }));
import { NO_FILTERS, serverFilters } from "../src/features/audit/AuditTimeline";
import { VARLATCH_ACTOR, actorOf, actorOptions, isVarlatchEvent, mergeCredentials } from "../src/features/audit/parts";
import type { AuditEventLike } from "../src/features/audit/describe";

/**
 * Who acted, and how: the audit timeline's actor names the identity and,
 * when the server says, the client or credential it acted through; the
 * actor filter groups identities by kind and offers Varlatch itself.
 */

const person = (over: Partial<OrgIdentity>): OrgIdentity => ({ id: "idn_x", name: "x", kind: "human", disabled: false, orgRole: null, ...over });
const identities = [
  person({ id: "idn_zoe", name: "Zoe", kind: "human" }),
  person({ id: "idn_ada", name: "Ada", kind: "human", disabled: true }),
  person({ id: "idn_bot", name: "claude-code-agent", kind: "agent" }),
  person({ id: "idn_gha", name: "github-actions", kind: "ci" }),
  person({ id: "idn_web", name: "web-runner", kind: "workload" }),
  person({ id: "idn_api", name: "api-runner", kind: "service" }),
  person({ id: "idn_brk", name: "broker", kind: "broker" }),
];
const byId = new Map(identities.map((i) => [i.id, i]));
const credentials = {
  crd_cli: { name: "laptop CLI", kind: "cli", client: "varlatch CLI 0.16.0 on Linux" },
  crd_svc: { name: null, kind: "service", client: null },
};

const event = (over: Partial<AuditEventLike>): AuditEventLike => ({
  eventId: "evt_1",
  eventType: "secret.disclosed",
  occurredAt: "2026-10-08T09:14:00Z",
  decision: "allow",
  actorIdentityId: "idn_zoe",
  ...over,
});

describe("actorOf: how the actor connected", () => {
  it("is the event's client when the server recorded one", () => {
    const actor = actorOf(event({ credentialId: "crd_cli", client: "varlatch CLI 0.16.0 on Linux, assisted" }), byId, credentials);
    expect(actor).toMatchObject({ name: "Zoe", kind: "human", via: "varlatch CLI 0.16.0 on Linux, assisted" });
    expect(actor.credential).toEqual({ id: "crd_cli", name: "laptop CLI", kind: "cli", client: "varlatch CLI 0.16.0 on Linux" });
  });

  it("is the credential's name from the sidecar otherwise, and nothing when neither is known", () => {
    expect(actorOf(event({ credentialId: "crd_cli" }), byId, credentials).via).toBe("laptop CLI");
    expect(actorOf(event({ credentialId: "crd_unknown" }), byId, credentials).via).toBeUndefined();
    expect(actorOf(event({ credentialId: "crd_svc" }), byId, credentials).via).toBeUndefined();
    expect(actorOf(event({}), byId).via).toBeUndefined();
  });

  it("never names a credential the event is about as the way the actor connected", () => {
    const revoked = actorOf(event({ eventType: "credential.revoked", credentialId: "crd_cli" }), byId, credentials);
    expect(revoked.via).toBeUndefined();
    expect(revoked.credential?.id).toBe("crd_cli");
    expect(actorOf(event({ eventType: "credential.revoked", credentialId: "crd_cli", client: "Firefox on Linux" }), byId, credentials).via).toBe(
      "Firefox on Linux",
    );
  });

  it("keeps Varlatch and unknown callers as they were", () => {
    expect(actorOf(event({ actorIdentityId: null, eventType: "sync.push_attempted" }), byId, credentials)).toEqual({
      name: "Varlatch",
      known: true,
      kind: "system",
    });
    expect(actorOf(event({ actorIdentityId: null, eventType: "authentication.failed" }), byId)).toMatchObject({ name: "Unknown", kind: "unknown" });
    expect(isVarlatchEvent(event({ actorIdentityId: null, eventType: "sync.push_attempted" }))).toBe(true);
    expect(isVarlatchEvent(event({ actorIdentityId: null, eventType: "authentication.failed" }))).toBe(false);
    expect(isVarlatchEvent(event({}))).toBe(false);
  });
});

describe("the actor filter", () => {
  it("offers anyone, Varlatch, then people, agents, CI, and machines, each by name, retired ones marked", () => {
    expect(actorOptions(identities)).toEqual([
      { value: "", label: "anyone" },
      { value: VARLATCH_ACTOR, label: "Varlatch" },
      { value: "idn_ada", label: "Ada (retired)", group: "People" },
      { value: "idn_zoe", label: "Zoe", group: "People" },
      { value: "idn_bot", label: "claude-code-agent", group: "Agents" },
      { value: "idn_gha", label: "github-actions", group: "CI" },
      { value: "idn_api", label: "api-runner", group: "Machines" },
      { value: "idn_brk", label: "broker", group: "Machines" },
      { value: "idn_web", label: "web-runner", group: "Machines" },
    ]);
  });

  it("asks the server for actor=varlatch, and for an identity by its ID", () => {
    expect(serverFilters({ ...NO_FILTERS, actor: VARLATCH_ACTOR }, {}, undefined)).toEqual({ actor: "varlatch" });
    expect(serverFilters({ ...NO_FILTERS, actor: "idn_zoe", decision: "deny" }, {}, undefined)).toEqual({ actorIdentityId: "idn_zoe", decision: "deny" });
  });
});

describe("the credentials sidecar across pages", () => {
  it("merges every loaded page's credentials, older servers' pages adding none", () => {
    expect(
      mergeCredentials([
        { credentials: { crd_cli: credentials.crd_cli } },
        {},
        { credentials: { crd_svc: credentials.crd_svc } },
      ]),
    ).toEqual(credentials);
    expect(mergeCredentials([])).toEqual({});
  });
});
