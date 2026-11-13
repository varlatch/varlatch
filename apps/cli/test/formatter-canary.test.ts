// SPDX-License-Identifier: Apache-2.0
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Approval, ExposureReport, IncidentFreezeState, MachineReach, MemberRemoval, MemberReview, OrganizationDeletion, WhoAmI } from "@varlatch/sdk";
import { checkTargetFlags } from "../src/agentRun.js";
import { approvalLines } from "../src/approvals.js";
import { deletionStateLines } from "../src/deletion.js";
import { formatDoctor, type DoctorReport } from "../src/doctor.js";
import { liftConfirmationLines } from "../src/freeze.js";
import { exposureLines, removalLines } from "../src/members.js";
import { reachLines } from "../src/reach.js";
import { REDACTED, UNRECOGNIZED_VERSION } from "../src/safeText.js";
import { CHECKLIST, CONTROL_EXPLANATIONS, securityStatusLines, type SecurityStatus } from "../src/securityStatus.js";
import { formatStatusHuman, type StatusDocument } from "../src/status.js";
import { UsageError, formatViolations } from "../src/strictRun.js";
import { formatSyncCheck, type SyncCheckResult } from "../src/syncCheck.js";
import { formatWhoamiHuman } from "../src/whoami.js";

/**
 * Canary tests for the human formatters that print server fields (issue
 * #119). Each fixture is built with `s(label)` around every string a server
 * provides. With `plain`, s returns the label: the output is pinned to what
 * the formatter printed before. With `hostile()`, s appends a forged line, an
 * ANSI escape and a bidirectional override: every label must come out with
 * them escaped, and no raw control character may reach the output.
 */

type S = (label: string) => string;

const FORGED = "\nError FORGED\u001b[31m‮";
const ESCAPED = "\\u000aError FORGED\\u001b[31m\\u202e";

const plain: S = (label) => label;

function hostile(): S & { labels: Set<string> } {
  const labels = new Set<string>();
  const s = (label: string) => {
    labels.add(label);
    return `${label}${FORGED}`;
  };
  return Object.assign(s, { labels });
}

/** Every label printed with its canary escaped; no control character but the line breaks between lines; no forged line. */
function expectEscaped(output: string | string[], s: ReturnType<typeof hostile>): void {
  const text = Array.isArray(output) ? output.join("\n") : output;
  expect(text).not.toMatch(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f‪-‮⁦-⁩]/);
  expect(text).not.toMatch(/^Error FORGED/m);
  for (const label of s.labels) expect(text, label).toContain(`${label}${ESCAPED}`);
}

const T = "2026-11-01T00:00:00.000Z";
const LATER = "2026-12-01T00:00:00.000Z";

// A credential held in the store: a server echoing it in free text gets it masked.
const STORED = "stored-credential-canary-91c4e7";
const dir = mkdtempSync(join(tmpdir(), "varlatch-formatter-canary-"));
const savedConfig = process.env.VARLATCH_CONFIG_DIR;

beforeAll(() => {
  writeFileSync(join(dir, "credentials.json"), JSON.stringify({ servers: { "https://other.example": { token: STORED } } }));
  process.env.VARLATCH_CONFIG_DIR = dir;
});

afterAll(() => {
  if (savedConfig === undefined) delete process.env.VARLATCH_CONFIG_DIR;
  else process.env.VARLATCH_CONFIG_DIR = savedConfig;
  rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------

function statusDoc(s: S): StatusDocument {
  return {
    version: 1,
    servers: [
      {
        server: "https://vl.example",
        name: s("laptop"),
        issuedAt: null,
        expiresAt: LATER,
        credentialId: null,
        expired: false,
        expiring: false,
        probe: { state: "valid", detail: s("probe-detail") },
      },
    ],
    repo: {
      server: "https://vl.example",
      organization: s("acme"),
      project: s("web"),
      environment: s("production"),
      environmentSource: "varlatch.toml",
      repoRoot: "/repo",
      tier: s("prod"),
      tierCachedAt: null,
      serverSource: "varlatch.toml",
    },
  } as unknown as StatusDocument;
}

describe("varlatch status (formatStatusHuman)", () => {
  it("prints ordinary input as before", () => {
    expect(formatStatusHuman(statusDoc(plain))).toBe(
      [
        `https://vl.example  (expires ${LATER}, laptop, probe: valid (probe-detail))`,
        "",
        "Repo          /repo",
        "Project       acme/web",
        "Environment   production (varlatch.toml, tier prod)",
      ].join("\n"),
    );
  });

  it("escapes every server field", () => {
    const s = hostile();
    expectEscaped(formatStatusHuman(statusDoc(s)), s);
  });
});

// ---------------------------------------------------------------------------

function whoami(s: S): WhoAmI {
  return {
    identity: { id: s("idn_1"), name: s("Ada"), kind: "human", email: s("ada@example.com") },
    organization: { id: s("org_1"), slug: s("acme"), name: s("Acme"), createdAt: T },
    credential: { id: s("crd_1"), name: s("laptop"), kind: s("cli"), expiresAt: LATER },
    listener: s("public"),
    tailnet: { recognized: true, tailnet: s("example.ts.net"), nodeId: s("n1"), nodeName: s("box"), tags: [s("tag:ci")] },
  } as unknown as WhoAmI;
}

describe("varlatch whoami (formatWhoamiHuman)", () => {
  it("prints ordinary input as before", () => {
    expect(formatWhoamiHuman("https://vl.example", whoami(plain))).toBe(
      [
        "Identity      Ada (human, idn_1)",
        "Email         ada@example.com",
        "Organization  acme (Acme, org_1)",
        `Credential    laptop (cli, crd_1), expires ${LATER}`,
        "Server        https://vl.example (public listener)",
        "Device        box (n1), tags tag:ci, on example.ts.net",
      ].join("\n"),
    );
  });

  it("escapes every server field", () => {
    const s = hostile();
    expectEscaped(formatWhoamiHuman("https://vl.example", whoami(s)), s);
  });
});

// ---------------------------------------------------------------------------

function memberReview(s: S): MemberReview {
  return {
    syncTargets: [{ id: s("tgt_1"), platform: s("github"), state: s("active"), environmentId: s("env_x"), changes: [s("created")] }],
    connections: [{ id: s("con_1"), name: s("gh"), platform: s("github-conn"), credentialKind: "token", revoked: false, changes: ["created"] }],
    webhooks: [{ id: s("whk_1"), host: s("hooks.example"), revoked: false }],
    oidcBindings: [{ id: s("oidc_1"), identityName: s("deployer"), issuer: s("https://issuer.example"), revoked: false }],
    credentials: [{ id: s("crd_2"), name: s("ci"), identityName: s("ci-bot"), state: s("live") }],
    personalEnvironments: [{ id: s("env_p"), name: s("ada-dev") }],
  } as unknown as MemberReview;
}

const REVIEW_LINES = [
  "  Integrations:",
  "    tgt_1  github, active, environment env_x  (created)",
  "  Connections:",
  "    con_1  gh (github-conn, token)  (created)",
  "  Webhooks (each signing secret was shown to its creator):",
  "    whk_1  hooks.example",
  "  OIDC bindings:",
  "    oidc_1  deployer from https://issuer.example",
  "  Machine credentials whose token they were shown:",
  "    crd_2  ci for ci-bot: live",
  "  Personal environments:",
  "    env_p  ada-dev",
];

function exposure(s: S, hint: string): ExposureReport {
  return {
    member: { name: s("Ada"), removedAt: T, role: null },
    coverage: { complete: true, from: null, to: null },
    received: [
      {
        itemName: s("API_KEY"),
        versionId: s("ver_1"),
        owningEnvironmentId: "env_1",
        servedAs: "current",
        notServedBecause: null,
        retiringUntil: null,
        confirmation: null,
        served: true,
        rotationHint: hint,
        receipts: [{ way: s("revealed"), environmentId: "env_1", firstAt: T, lastAt: T }],
      },
    ],
    authorityAtRemoval: {
      removedAt: T,
      environments: [{ environmentId: "env_1", conditionalOn: [s("req_1")], actions: [{ action: s("secret.reveal") }] }],
      requirements: [{ requirementId: s("req_2"), target: { kind: "tier", tier: s("prod") }, selector: { tailnet: s("example.ts.net"), tags: [s("tag:ci")] } }],
    },
    indirect: memberReview(s),
  } as unknown as ExposureReport;
}

describe("varlatch member exposure (exposureLines)", () => {
  const envName = (s: S) => (id: string | null) => (id === "env_1" ? s("production") : "an unknown environment");

  it("prints ordinary input as before", () => {
    expect(exposureLines(exposure(plain, "rotate it in the console"), envName(plain))).toEqual([
      `Exposure report for Ada (former member, removed ${T}).`,
      "",
      "Received (observed in the audit log; a delivery is not proof that a copy was kept):",
      "  API_KEY  ver_1  in production: still served (current)",
      `    revealed, ${T}`,
      "    to rotate: rotate it in the console",
      "",
      `Could reach when removed (${T}):`,
      "  production: secret.reveal (reading values conditional on Tailnet Requirement req_1)",
      "  Tailnet Requirements as defined at removal:",
      "    req_2: on the prod tier, a device in example.ts.net with tags tag:ci",
      "",
      "Not covered: what they could reach before removal and no longer could then, and values that reached a broker, an agent or a platform; those are listed below as indirect paths.",
      "",
      "Indirect paths (what they set up; not evidence that they held a value):",
      ...REVIEW_LINES,
    ]);
  });

  it("escapes every server field", () => {
    const s = hostile();
    expectEscaped(exposureLines(exposure(s, s("rotation-hint")), envName(s)), s);
  });

  it("masks a stored credential in a rotation hint", () => {
    const lines = exposureLines(exposure(plain, `paste ${STORED} into the console\nError FORGED`), envName(plain));
    expect(lines).toContain(`    to rotate: paste ${REDACTED} into the console\\u000aError FORGED`);
    expect(lines.join("\n")).not.toContain(STORED);
  });
});

describe("varlatch member remove (removalLines)", () => {
  const removal = (s: S) =>
    ({ left: false, grantsRevoked: 2, groupsLeft: 1, invitationsRevoked: 0, review: memberReview(s) }) as unknown as MemberRemoval;

  it("prints ordinary input as before", () => {
    expect(removalLines(removal(plain), "Ada", "acme")).toEqual([
      "Removed Ada from acme.",
      "Revoked 2 Grants, left 1 group or team, revoked 0 pending invitations.",
      "Their sign-in and credentials are unaffected; from their next request they reach nothing in this organization.",
      "",
      "To review (the removal changed none of it; it may keep working without them):",
      ...REVIEW_LINES,
    ]);
  });

  it("escapes every server field", () => {
    const s = hostile();
    expectEscaped(removalLines(removal(s), s("Ada"), s("acme")), s);
  });
});

// ---------------------------------------------------------------------------

function reach(s: S): MachineReach {
  return {
    identity: { id: s("idn_m"), name: s("deployer"), kind: s("service"), state: s("active"), disabledReason: null, liveCredentials: 1 },
    requirements: [{ id: "req_1", condition: s("tag:ci on example.ts.net") }],
    organizationActions: [{ action: s("audit.read"), conditions: [] }],
    projects: [
      {
        slug: s("web"),
        name: s("Web"),
        actions: [{ action: s("project.read"), conditions: [] }],
        environments: [{ name: s("production"), actions: [{ action: s("secret.use"), conditions: ["req_1", s("req_gone")] }] }],
      },
    ],
    notes: [s("A note from the server.")],
  } as unknown as MachineReach;
}

describe("varlatch identity reach (reachLines)", () => {
  it("prints ordinary input as before", () => {
    expect(reachLines(reach(plain))).toEqual([
      "Reach of deployer (idn_m, service, active, 1 live credential).",
      "",
      "Organization-wide: audit.read",
      "",
      "web (Web):",
      "  project: project.read",
      "  production: secret.use (tag:ci on example.ts.net and Requirement req_gone)",
      "",
      "Conditions are Tailnet Requirements: each must be met by the device a request comes from. They are listed, not checked against any device.",
      "",
      "A note from the server.",
    ]);
  });

  it("escapes every server field", () => {
    const s = hostile();
    expectEscaped(reachLines(reach(s)), s);
  });
});

// ---------------------------------------------------------------------------

const NOW = Date.parse("2026-11-13T12:00:00.000Z");

function securityStatus(s: S): SecurityStatus {
  return {
    organization: "acme",
    enforceAvailable: false,
    enforceable: [],
    controls: {
      availableModes: [s("off"), s("report")],
      window: { days: 30, since: T, generatedAt: T },
      items: [
        {
          control: s("admin-step-up"),
          mode: s("report"),
          version: 1,
          availableModes: ["off", "report"],
          config: null,
          changedAt: T,
          changedBy: null,
          explanation: CONTROL_EXPLANATIONS["admin-step-up"],
          counts: {
            total: 1,
            currentHour: 0,
            pending: 0,
            entries: [{ operation: s("security_control.change"), reason: s("loosening"), actor: { id: s("idn_2"), name: null, kind: s("service") }, count: 1 }],
          },
        },
      ],
    },
    approvalKeys: { items: [{ identity: { id: "idn_3", name: s("Carol") }, trusted: 1, unconfirmed: 0 }], summary: { withoutTrustedKey: 0 } },
    credentialReview: {
      idleDays: 90,
      summary: { reviewed: 1, listed: 0 },
      items: [],
      expiry: {
        warningDays: 14,
        summary: { soon: 1, expired: 0 },
        items: [{ id: s("crd_9"), name: s("deploy key"), identity: { name: s("deployer") }, state: "expiring", expiresAt: LATER }],
      },
    },
    requirements: null,
    checklist: CHECKLIST,
    unavailable: [],
    incidentFreeze: { id: "frz_1", frozenAt: T, frozenBy: { id: "idn_1", name: s("Ada") }, reason: s("incident 42") },
  } as unknown as SecurityStatus;
}

describe("varlatch security status (securityStatusLines)", () => {
  it("prints ordinary input as before", () => {
    const lines = securityStatusLines(securityStatus(plain), NOW);
    expect(lines.slice(0, 9)).toEqual([
      "Security for acme",
      `FROZEN for an incident since ${T} by Ada: incident 42`,
      "  Every read and write is refused except inspection, audit and recovery. Lift it: varlatch org unfreeze acme",
      "Every control is off by default. Turned on here: admin-step-up (report).",
      "",
      "Controls (counts of the last 30 days)",
      "  admin-step-up  report  1 counted",
      "      security_control.change  loosening  by idn_2 (service): 1",
      "  Modes: off, report. Enforce: coming in a later release.",
    ]);
    expect(lines).toContain("  Carol  1 trusted, 0 unconfirmed");
    expect(lines).toContain(`  crd_9  deploy key  for deployer: expires in 18 days (${LATER})`);
  });

  it("escapes every server field", () => {
    const s = hostile();
    expectEscaped(securityStatusLines(securityStatus(s), NOW), s);
  });

  it("masks a stored credential in a freeze reason", () => {
    const status = securityStatus(plain);
    status.incidentFreeze!.reason = `leaked ${STORED}`;
    expect(securityStatusLines(status, NOW)[1]).toBe(`FROZEN for an incident since ${T} by Ada: leaked ${REDACTED}`);
  });
});

// ---------------------------------------------------------------------------

function doctorReport(s: S, serverVersion: string): DoctorReport {
  return {
    dir: "/srv/varlatch",
    facts: { serverVersion, releaseVersion: "0.21.0", migrationVersion: 30, publicUrl: null, convexConfigured: false, installationId: null },
    checks: [
      { id: "plane", title: s("Secret Plane ready"), status: "fail", class: "mandatory", detail: s("detail from varlatchd"), remedy: s("restart it") },
      { id: "db", title: s("Database reachable"), status: "pass", class: "mandatory" },
    ],
  } as unknown as DoctorReport;
}

describe("varlatch doctor (formatDoctor)", () => {
  it("prints ordinary input as before", () => {
    expect(formatDoctor(doctorReport(plain, "0.21.0"))).toBe(
      [
        "Varlatch doctor — /srv/varlatch (server 0.21.0)",
        "",
        "✗ Secret Plane ready  [mandatory]",
        "    detail from varlatchd",
        "    → restart it",
        "✓ Database reachable",
        "",
        "1 mandatory failure(s), 0 advisory finding(s), 0 unknown. Read-only: nothing was changed.",
      ].join("\n"),
    );
  });

  it("escapes every server field, and shows a malformed version as a fixed phrase", () => {
    const s = hostile();
    const text = formatDoctor(doctorReport(s, `0.21.0${FORGED}`));
    expectEscaped(text, s);
    expect(text.split("\n")[0]).toBe(`Varlatch doctor — /srv/varlatch (server ${UNRECOGNIZED_VERSION})`);
  });
});

// ---------------------------------------------------------------------------
// The cheaper ones.

describe("varlatch run --strict (formatViolations)", () => {
  it("prints ordinary input as before and escapes server fields", () => {
    const violations = (s: S) => [{ name: s("API_KEY"), kind: "invalid" as const, reason: s("not a URL") }];
    expect(formatViolations(violations(plain))).toEqual([
      "varlatch: strict startup found 1 violation(s); the command was not started:",
      "  API_KEY: invalid: not a URL",
    ]);
    const s = hostile();
    expectEscaped(formatViolations(violations(s)), s);
  });
});

describe("varlatch sync check (formatSyncCheck)", () => {
  const result = (s: S) =>
    ({
      platform: "github",
      base: "acme/web",
      destination: {},
      environment: s("production"),
      keySet: "contract",
      keys: [{ name: s("API_KEY"), destination: s("API_KEY_ON_PLATFORM"), status: "match" }],
      usage: [{ code: "usage-unchecked", reason: s("compose file unreadable") }],
      notices: [],
      exitCode: 0,
    }) as unknown as SyncCheckResult;

  it("prints ordinary input as before and escapes server fields", () => {
    expect(formatSyncCheck(result(plain))).toEqual({
      stdout: ["github acme/web against production:", "  match  API_KEY -> API_KEY_ON_PLATFORM", "in sync: 1 match, 0 differ, 0 missing on the platform, 0 extra on the platform, 0 not compared"],
      stderr: ["varlatch: usage: usage not checked: compose file unreadable"],
    });
    const s = hostile();
    const out = formatSyncCheck(result(s));
    expectEscaped([...out.stdout, ...out.stderr], s);
  });
});

describe("varlatch org unfreeze (liftConfirmationLines)", () => {
  const state = (s: S) =>
    ({
      freeze: { id: "frz_1", frozenAt: T, frozenBy: { id: "idn_1", name: s("Ada") }, reason: s("incident 42") },
      resumingTargets: [{ id: s("tgt_1"), projectSlug: s("web"), environmentName: s("production"), platform: s("github"), destination: s("acme/web") }],
    }) as unknown as IncidentFreezeState;

  it("prints ordinary input as before, escapes server fields and masks the reason", () => {
    expect(liftConfirmationLines(state(plain), "acme")).toEqual([
      `acme is frozen since ${T} by Ada: incident 42`,
      "Lifting undoes nothing done during the freeze: revoked credentials and Grants stay revoked.",
      "Sync Targets that resume pushing (1):",
      "  web/production -> github acme/web [tgt_1]",
    ]);
    const s = hostile();
    expectEscaped(liftConfirmationLines(state(s), "acme"), s);
    const leaked = state(plain);
    leaked.freeze!.reason = `leaked ${STORED}`;
    expect(liftConfirmationLines(leaked, "acme")[0]).toBe(`acme is frozen since ${T} by Ada: leaked ${REDACTED}`);
  });
});

describe("varlatch org delete (deletionStateLines)", () => {
  const deletion = (s: S) =>
    ({ id: s("del_1"), scheduledAt: T, runAfter: LATER, requestedBy: s("Ada"), approvalRequired: true, approvedBy: s("Bob"), approvedAt: T }) as unknown as OrganizationDeletion;

  it("prints ordinary input as before and escapes server fields", () => {
    expect(deletionStateLines(deletion(plain), "acme", new Date(NOW))).toEqual([
      `Deletion del_1 of acme: scheduled ${T} by Ada.`,
      `It runs no earlier than ${LATER}.`,
      `Approved by Bob at ${T}.`,
      "acme is frozen until then: changes are refused, reads still work, so a last copy can be made.",
      "Any admin can cancel it until it runs: varlatch org delete acme --cancel del_1",
    ]);
    const s = hostile();
    expectEscaped(deletionStateLines(deletion(s), "acme", new Date(NOW)), s);
  });
});

describe("step-up approvals (approvalLines)", () => {
  const approval = (s: S, title: string) =>
    ({
      id: s("apr_1"),
      summary: { title, changes: [{ field: s("mode"), from: s("report"), to: s("off"), loosens: true }] },
      url: s("https://vl.example/approve/apr_1"),
      expiresAt: LATER,
    }) as unknown as Approval;

  it("prints ordinary input as before, escapes server fields and masks the title and values", () => {
    expect(approvalLines(approval(plain, "Turn admin-step-up off"))).toEqual([
      "This needs your approval with a trusted passkey: Turn admin-step-up off",
      "  mode: report -> off (loosens)",
      "Open this address in a browser where you are signed in to Varlatch as yourself, check what it says, and approve with a trusted passkey:",
      "  https://vl.example/approve/apr_1",
      `It expires at ${LATER}. Only you can approve it.`,
    ]);
    const s = hostile();
    expectEscaped(approvalLines(approval(s, s("title"))), s);
    expect(approvalLines(approval(plain, `Use ${STORED}`))[0]).toBe(`This needs your approval with a trusted passkey: Use ${REDACTED}`);
    const values = {
      id: "apr_1",
      summary: { title: "Change", changes: [{ field: "token", from: `old ${STORED}`, to: STORED, loosens: false }] },
      url: "https://vl.example/approve/apr_1",
      expiresAt: LATER,
    } as unknown as Approval;
    expect(approvalLines(values)[1]).toBe(`  token: old ${REDACTED} -> ${REDACTED}`);
  });
});

// ---------------------------------------------------------------------------

describe("run with --target (checkTargetFlags)", () => {
  it("escapes a stored name from the server in the error, and keeps the message's own lines", () => {
    const evil = `EVIL${FORGED}`;
    let caught: unknown;
    try {
      checkTargetFlags(["API_KEY", evil], { targets: { API_KEY: ["header:authorization"] }, omit: [] });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(UsageError);
    const message = (caught as Error).message;
    expect(message).not.toMatch(/[\u001b‮]/);
    expect(message).not.toMatch(/^Error FORGED/m);
    expect(message).toBe(
      `EVIL${ESCAPED} has no substitution target: add --target EVIL${ESCAPED}=header:authorization\n` +
        `          (or query:, json:, form:), or --omit EVIL${ESCAPED} to leave it out of this run`,
    );
  });
});
