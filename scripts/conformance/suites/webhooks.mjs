#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import "../../redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * Audit webhook delivery (ADR-0016, ADR-0029 section 8, ADR-0051 Decision
 * 9, ADR-0057), against a local receiver (the webhook-receiver capability:
 * an endpoint on the server's own loopback, which the target's outbound
 * allow list opens and nothing else private). No dashboard suite sees a
 * delivery; this one waits for them. The server delivers every 30 seconds.
 *
 * In an Organization of its own: webhooks to the receiver (every event, an
 * event-type filter, one whose endpoint fails its first request, one
 * revoked, one moved to another URL), then a Project, whose creation every
 * live webhook must receive, signed. Then a private destination, refused
 * at registration and recorded; and the audit events' redacted URLs. In a
 * second Organization (group deletion): a webhook receives nothing while
 * the Organization's deletion is scheduled, and what waited once the
 * deletion is cancelled.
 *
 *   webhooks.mjs <origin> <api token>   (run by scripts/conformance/run.mjs)
 */
import { createHmac, randomBytes } from "node:crypto";
import { reporter, targetOp } from "../suite-kit.mjs";

const [origin, token] = process.argv.slice(2);
if (!origin || !token) {
  console.error("Usage: webhooks.mjs <origin> <api token>");
  process.exit(64);
}
const kit = reporter({ detailOnFailure: true });
const { check, error, finish } = kit;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function api(method, path, { body } = {}) {
  const res = await fetch(new URL(path, origin), {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      "User-Agent": "varlatch-conformance-webhooks",
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
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
  return { status: res.status, json, text };
}

const ok = (r, what) => {
  if (r.status >= 300) throw new Error(`${what}: ${r.status} ${r.text}`);
  return r.json;
};

const receiver = () => JSON.parse(targetOp("webhook-receiver", ["url"])).url;
const received = () => JSON.parse(targetOp("webhook-receiver", ["requests"]));
const at = (path) => (r) => r.target.split("?")[0] === path;

/** Waits until `done(requests)` holds, for up to `ms`; answers the requests. */
async function waitFor(done, ms) {
  const deadline = Date.now() + ms;
  for (;;) {
    const got = received();
    if (done(got) || Date.now() > deadline) return got;
    await sleep(2000);
  }
}

/** Whether a delivery's signature verifies with the secret, made within five minutes. */
function verifies(r, secret) {
  const m = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(r.signature ?? "");
  if (!m) return false;
  const expected = createHmac("sha256", secret).update(`${m[1]}.${r.body}`, "utf8").digest("hex");
  return expected === m[2] && Math.abs(Date.now() / 1000 - Number(m[1])) < 300;
}

const events = (r) => JSON.parse(r.body).events;
const types = (r) => events(r).map((e) => e.eventType);
// A delivery's whole time: a pass every 30 seconds, and a retry the pass after.
const PASS_MS = 75_000;

const suffix = randomBytes(4).toString("hex");
const slug = `webhooks-${suffix}`;
const base = `/v1/organizations/${slug}`;

try {
  ok(await api("GET", "/v1/me"), "whoami");
  const org = ok(await api("POST", "/v1/organizations", { body: { name: "Webhooks suite", slug } }), "creating the Organization");
  const url = receiver();
  const hook = async (path, extra = {}) => ok(await api("POST", `${base}/webhooks`, { body: { url: `${url}${path}`, ...extra } }), `registering ${path}`);

  // Every event (a token in its query, which audit must not show), a
  // filter, an endpoint that fails once, one to revoke, one to move.
  const all = await hook(`/${suffix}/all?token=s3cr3t-${suffix}`);
  const filtered = await hook(`/${suffix}/filtered`, { eventTypes: ["project.created"] });
  const flaky = await hook(`/${suffix}/fail-1/retry`);
  const revoked = await hook(`/${suffix}/revoked`);
  const moved = await hook(`/${suffix}/before`);
  check(
    "webhooks.secret-shown-once",
    "registering a webhook answers its signing secret once; listing never shows it",
    /^vlt_whsec_[A-Za-z0-9_-]{43}$/.test(all.secret ?? "") &&
      ok(await api("GET", `${base}/webhooks`), "listing").items.every((w) => !("secret" in w)),
    `secret ${String(all.secret).length} characters`,
  );
  ok(await api("DELETE", `${base}/webhooks/${revoked.id}`), "revoking");
  const patched = ok(await api("PATCH", `${base}/webhooks/${moved.id}`, { body: { expectedVersion: 1, url: `${url}/${suffix}/after` } }), "moving");
  const project = ok(await api("POST", `${base}/projects`, { body: { name: "Hooked", slug: "hooked", contractAuthority: "managed" } }), "creating a Project");

  const got = await waitFor(
    (g) =>
      g.some((r) => at(`/${suffix}/all`)(r) && types(r).includes("project.created")) &&
      g.filter(at(`/${suffix}/fail-1/retry`)).length >= 2 &&
      g.some((r) => at(`/${suffix}/after`)(r) && types(r).includes("project.created")) && g.some(at(`/${suffix}/filtered`)),
    2 * PASS_MS,
  );
  const allGot = got.filter(at(`/${suffix}/all`));
  const allEvents = allGot.flatMap(events);
  check(
    "webhooks.delivery-signed",
    "a delivery is a signed JSON POST of the Organization's events after the registration, the Project's creation among them",
    allGot.length > 0 && allGot.every((r) => r.method === "POST" && r.contentType === "application/json" && verifies(r, all.secret)) &&
      allGot.every((r) => JSON.parse(r.body).webhookId === all.id && JSON.parse(r.body).organizationId === org.id) &&
      allEvents.some((e) => e.eventType === "project.created" && e.resource?.projectId === project.id) &&
      !allEvents.some((e) => e.eventType === "webhook.created" && e.resource?.webhookId === all.id) &&
      !allEvents.some((e) => e.eventType === "organization.created"),
    JSON.stringify(allGot.map((r) => ({ status: r.status, types: types(r) }))),
  );
  const filteredGot = got.filter(at(`/${suffix}/filtered`));
  check(
    "webhooks.event-type-filter",
    "a webhook with an event-type filter receives only those events",
    filteredGot.length > 0 && filteredGot.every((r) => verifies(r, filtered.secret) && types(r).every((t) => t === "project.created")),
    JSON.stringify(filteredGot.map(types)),
  );
  const retries = got.filter(at(`/${suffix}/fail-1/retry`));
  const listed = ok(await api("GET", `${base}/webhooks`), "listing").items;
  const flakyRow = listed.find((w) => w.id === flaky.id);
  // The retry starts at the same event: the cursor did not move. It may
  // carry more, when events came between the two passes.
  const ids = (r) => events(r).map((e) => e.id);
  check(
    "webhooks.retry-after-failure",
    "a batch the endpoint failed is sent again from the same event on the next pass; the webhook then shows the success",
    retries.length >= 2 && retries[0].status === 500 && retries[1].status === 200 &&
      ids(retries[0]).every((id, i) => ids(retries[1])[i] === id) &&
      verifies(retries[1], flaky.secret) && flakyRow?.failureCount === 0 && flakyRow?.lastStatus === "200",
    JSON.stringify({ statuses: retries.map((r) => r.status), row: flakyRow }),
  );
  // A pass may come between a registration and the next request: what
  // the old URL and the revoked webhook may have received is only what
  // came before the change.
  const later = (r) => events(r).some((e) => e.eventType === "project.created" || (e.eventType === "webhook.updated" && e.resource?.webhookId === moved.id));
  const after = got.filter(at(`/${suffix}/after`));
  const before = got.filter(at(`/${suffix}/before`));
  check(
    "webhooks.update-keeps-secret",
    "a webhook moved to another URL in place delivers there, signed with its first secret, and nothing after the move goes to the old URL",
    patched.version === 2 && after.length > 0 && after.every((r) => verifies(r, moved.secret)) &&
      after.some((r) => types(r).includes("project.created")) && !before.some(later),
    JSON.stringify({ version: patched.version, after: after.map(types), before: before.map(types) }),
  );
  const afterRevoke = got.filter(at(`/${suffix}/revoked`));
  check(
    "webhooks.revoked-receives-nothing",
    "a revoked webhook receives nothing after its revocation",
    !afterRevoke.some((r) => types(r).includes("project.created") || types(r).includes("webhook.revoked")),
    JSON.stringify(afterRevoke.map(types)),
  );

  // The audit events show webhook URLs redacted.
  const audit = async (type) => ok(await api("GET", `${base}/audit-events?eventType=${type}&limit=100`), `listing ${type}`).items;
  const created = (await audit("webhook.created")).find((e) => e.resource?.webhookId === all.id);
  const updated = (await audit("webhook.updated")).find((e) => e.resource?.webhookId === moved.id);
  const shown = JSON.stringify([created, updated]);
  check(
    "webhooks.url-redacted-in-audit",
    "webhook audit events show the URL with its path and query redacted, never a token in it",
    created?.metadata?.url === `${url}/[redacted]?[redacted]` && updated?.metadata?.oldUrl === `${url}/[redacted]` &&
      updated?.metadata?.newUrl === `${url}/[redacted]` && !shown.includes("s3cr3t") && !shown.includes(suffix),
    shown,
  );

  // A private destination is refused at registration, and the refusal recorded.
  const refused = await api("POST", `${base}/webhooks`, { body: { url: "https://10.255.0.1/private/hook?k=v" } });
  check(
    "webhooks.private-destination-refused",
    "registering a webhook to a private address is refused with the outbound policy's reason, never the address",
    refused.status === 422 && refused.json?.error?.code === "VALIDATION_FAILED" && refused.json?.error?.details?.outbound === "private_address" &&
      !refused.text.includes("10.255.0.1"),
    refused.text,
  );
  const record = (await audit("outbound.refused")).find((e) => e.metadata?.host === "10.255.0.1");
  check(
    "webhooks.refusal-recorded",
    "the refused registration is recorded as outbound.refused: purpose, phase, host, port and reason, no path or query",
    record?.decision === "deny" && record.metadata.purpose === "webhook" && record.metadata.phase === "configuration" &&
      record.metadata.port === 443 && record.metadata.reason === "private_address" && !JSON.stringify(record).includes("private/hook"),
    JSON.stringify(record ?? null),
  );

  // Group deletion: a webhook is suspended while its Organization's deletion is scheduled.
  if (kit.group("deletion")) {
    const dslug = `webhooks-del-${suffix}`;
    const dbase = `/v1/organizations/${dslug}`;
    ok(await api("POST", "/v1/organizations", { body: { name: "Webhooks deletion", slug: dslug } }), "creating the second Organization");
    const dhook = ok(await api("POST", `${dbase}/webhooks`, { body: { url: `${url}/${suffix}/deleting` } }), "registering in the second Organization");
    const first = ok(await api("POST", `${dbase}/projects`, { body: { name: "First", slug: "first", contractAuthority: "managed" } }), "creating a Project");
    const named = (id) => (g) => g.filter(at(`/${suffix}/deleting`)).some((r) => events(r).some((e) => e.resource?.projectId === id));
    const before = named(first.id)(await waitFor(named(first.id), PASS_MS));
    // A Project created just before the deletion is scheduled: a pass in
    // between (a few milliseconds of 30 seconds) would deliver it first,
    // and the check is then made again with another.
    let held = null;
    let deletion = null;
    for (let attempt = 0; attempt < 2 && !held; attempt++) {
      const p = ok(await api("POST", `${dbase}/projects`, { body: { name: `Held ${attempt}`, slug: `held-${attempt}`, contractAuthority: "managed" } }), "creating a Project");
      deletion = ok(await api("POST", `${dbase}/deletion`, { body: { afterDays: 1 } }), "scheduling the deletion");
      if (named(p.id)(received())) {
        ok(await api("POST", `${dbase}/deletion/${deletion.id}/cancel`, { body: {} }), "cancelling the deletion");
        continue;
      }
      held = p;
    }
    if (!held) throw new Error("a delivery pass came between the Project and the deletion twice");
    const during = await waitFor(named(held.id), PASS_MS);
    const suspended = !named(held.id)(during);
    ok(await api("POST", `${dbase}/deletion/${deletion.id}/cancel`, { body: {} }), "cancelling the deletion");
    const resumed = await waitFor(named(held.id), PASS_MS);
    const deliveries = resumed.filter(at(`/${suffix}/deleting`));
    check(
      "webhooks.suspended-while-deleting",
      "nothing is delivered while the Organization's deletion is scheduled; once it is cancelled, what waited is delivered, without the deletion's own events",
      before && suspended && named(held.id)(resumed) && deliveries.every((r) => verifies(r, dhook.secret)) &&
        !deliveries.flatMap(types).some((t) => t.startsWith("organization.deletion")),
      JSON.stringify({ before, suspended, types: deliveries.map(types) }),
    );
  }
} catch (err) {
  error(err instanceof Error ? err.stack ?? err.message : String(err));
}
finish("webhook checks");
