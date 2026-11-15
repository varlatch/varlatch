#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import "../../redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * Security Controls over the API (ADR-0054; capabilities security.controls,
 * security.report, security.approval-keys), which no dashboard suite
 * exercises: in an Organization of its own, the controls as a new
 * Organization has them, a tightening change, a stale version, a loosening
 * change asking for a step-up approval (then cancelled), the self-lockout
 * refusal of passkey-verification at enforce, report mode counting the
 * suite's own accesses, and the admins' approval keys.
 *
 * The admin identity's CLI credential comes from admin-recover, so its
 * sign-in carries no passkey evidence: passkey-verification at report
 * counts its accesses (no-evidence), and enforcing it from that credential
 * is refused. The Organization is left with admin-step-up and
 * passkey-verification at report; nothing else uses it.
 *
 *   security.mjs <origin> <api token>   (run by scripts/conformance/run.mjs)
 */
import { randomBytes } from "node:crypto";
import { reporter } from "../suite-kit.mjs";

const [origin, token] = process.argv.slice(2);
if (!origin || !token) {
  console.error("Usage: security.mjs <origin> <api token>");
  process.exit(64);
}
const { check, error, finish } = reporter({ detailOnFailure: true });

async function api(method, path, { body, headers = {} } = {}) {
  const res = await fetch(new URL(path, origin), {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      "User-Agent": "varlatch-conformance-security",
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      ...headers,
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    // Not JSON: kept as text for the detail.
  }
  return { status: res.status, json, text, headers: res.headers };
}

const ok = (r, what) => {
  if (r.status >= 300) throw new Error(`${what}: ${r.status} ${r.text}`);
  return r.json;
};

const CONTROLS = ["requirement-protection", "admin-step-up", "passkey-verification", "credential-lifetime"];
const slug = `security-${randomBytes(4).toString("hex")}`;
const base = `/v1/organizations/${slug}/security`;

try {
  const me = ok(await api("GET", "/v1/me"), "whoami");
  ok(await api("POST", "/v1/organizations", { body: { name: "Security suite", slug } }), "creating the Organization");

  const listed = ok(await api("GET", `${base}/controls`), "listing the controls");
  check(
    "security.new-organization-all-off",
    "a new Organization's Security Controls are all off at version 0, never changed, each offering off, report and enforce",
    JSON.stringify(listed.items.map((c) => c.control)) === JSON.stringify(CONTROLS) &&
      listed.items.every((c) => c.mode === "off" && c.version === 0 && c.config === null && c.changedAt === null && c.changedBy === null &&
        JSON.stringify(c.availableModes) === JSON.stringify(["off", "report", "enforce"])) &&
      JSON.stringify(listed.availableModes) === JSON.stringify(["off", "report"]),
    JSON.stringify(listed),
  );

  const tightened = await api("PATCH", `${base}/controls/admin-step-up`, { body: { mode: "report", expectedVersion: 0 } });
  const after = ok(await api("GET", `${base}/controls`), "listing the controls again").items.find((c) => c.control === "admin-step-up");
  check(
    "security.tightening-changes-without-approval",
    "turning a control from off to report needs no approval: it changes at once, to version 1, recorded as the caller's change",
    tightened.status === 200 && tightened.json?.changed === true && tightened.json?.loosened === false &&
      after?.mode === "report" && after?.version === 1 && after?.changedBy?.id === me.identity.id,
    `${tightened.status} ${tightened.text} ${JSON.stringify(after)}`,
  );

  const stale = await api("PATCH", `${base}/controls/admin-step-up`, { body: { mode: "enforce", expectedVersion: 0 } });
  check(
    "security.stale-version-conflict",
    "a change at a version the control has left answers VERSION_CONFLICT with the current version, and changes nothing",
    stale.status === 409 && stale.json?.error?.code === "VERSION_CONFLICT" && stale.json?.error?.details?.currentVersion === 1,
    `${stale.status} ${stale.text}`,
  );

  const loosen = await api("PATCH", `${base}/controls/admin-step-up`, { body: { mode: "off", expectedVersion: 1 } });
  const approval = loosen.json?.error?.details?.approval;
  const unchanged = ok(await api("GET", `${base}/controls`), "listing the controls after the loosening").items.find((c) => c.control === "admin-step-up");
  check(
    "security.loosening-asks-for-approval",
    "turning a control off without an approval answers STEP_UP_REQUIRED with a pending approval for exactly that change, and changes nothing",
    loosen.status === 403 && loosen.json?.error?.code === "STEP_UP_REQUIRED" && /^apr_[a-z2-7]{26}$/.test(approval?.id ?? "") &&
      approval?.operation === "security_control.change" && approval?.state === "pending" && approval?.organization?.slug === slug &&
      typeof approval?.url === "string" && approval.url.endsWith(`/approve/${approval.id}`) &&
      unchanged?.mode === "report" && unchanged?.version === 1,
    `${loosen.status} ${loosen.text}`,
  );
  if (approval?.id) {
    const pending = await api("PATCH", `${base}/controls/admin-step-up`, { body: { mode: "off", expectedVersion: 1 }, headers: { "Varlatch-Approval": approval.id } });
    check(
      "security.pending-approval-refused",
      "the same change repeated with the approval before it is approved answers APPROVAL_INVALID (pending)",
      pending.status === 409 && pending.json?.error?.code === "APPROVAL_INVALID" && pending.json?.error?.details?.reason === "pending" &&
        pending.json?.error?.details?.approvalId === approval.id,
      `${pending.status} ${pending.text}`,
    );
    ok(await api("POST", `/v1/me/approvals/${approval.id}/cancel`), "cancelling the approval");
  } else {
    check("security.pending-approval-refused", "the same change repeated with the approval before it is approved answers APPROVAL_INVALID (pending)", false, "no approval to repeat with");
  }

  const lockout = await api("PATCH", `${base}/controls/passkey-verification`, { body: { mode: "enforce", expectedVersion: 0 } });
  check(
    "security.enforce-passkey-verification-self-lockout-refused",
    "enforcing passkey-verification from a sign-in it would refuse is refused (PASSKEY_VERIFICATION_REQUIRED, change refused) and changes nothing",
    lockout.status === 403 && lockout.json?.error?.code === "PASSKEY_VERIFICATION_REQUIRED" && lockout.json?.error?.details?.change === "refused" &&
      lockout.json?.error?.details?.reason === "no-evidence",
    `${lockout.status} ${lockout.text}`,
  );

  // passkey-verification at report: each successful access by this
  // credential counts, best effort, after its response.
  ok(await api("PATCH", `${base}/controls/passkey-verification`, { body: { mode: "report", expectedVersion: 0 } }), "passkey-verification to report");
  for (let i = 0; i < 3; i++) ok(await api("GET", `${base}/controls`), "an access to count");
  let counted = null;
  let report = null;
  for (let attempt = 0; attempt < 20 && !counted; attempt++) {
    report = await api("GET", `${base}/control-report?days=1`);
    const pv = report.json?.controls?.find((c) => c.control === "passkey-verification");
    const entry = pv?.entries?.find((e) => e.actor?.id === me.identity.id && e.reason === "no-evidence" && e.operation === "organization.read");
    if (pv && entry && entry.count >= 3 && pv.currentHour >= 3 && pv.pending >= 3) counted = { pv, entry };
    else await new Promise((r) => setTimeout(r, 250));
  }
  check(
    "security.report-counts-accesses",
    "passkey-verification at report counts each access it would have refused, in the current hour, not yet summarized, under the action and the person",
    counted !== null && report.status === 200 && report.headers.get("cache-control") === "no-store" && report.json?.days === 1 &&
      report.json?.summaryDelayMinutes === 10,
    `${report?.status} ${report?.text}`,
  );

  const badDays = await api("GET", `${base}/control-report?days=31`);
  check(
    "security.report-window-bounded",
    "a report window beyond 30 days is refused (VALIDATION_FAILED)",
    badDays.status === 422 && badDays.json?.error?.code === "VALIDATION_FAILED",
    `${badDays.status} ${badDays.text}`,
  );

  const keys = await api("GET", `${base}/approval-keys`);
  const mine = keys.json?.items?.find((i) => i.identity?.id === me.identity.id);
  check(
    "security.approval-keys-list-admins",
    "the approval keys list the Organization's admins with their passkeys' trust, names and dates, never a credential id or key",
    keys.status === 200 && keys.headers.get("cache-control") === "no-store" && keys.json?.summary?.admins >= 1 && mine !== undefined &&
      Array.isArray(mine.passkeys) && mine.passkeys.length === mine.trusted + mine.unconfirmed &&
      mine.passkeys.every((p) => Object.keys(p).sort().join(",") === "createdAt,name,trust,trustedAt,trustedVia"),
    `${keys.status} ${keys.text}`,
  );
} catch (err) {
  error(`security: ${err.message}`);
}
finish("security check(s)");
