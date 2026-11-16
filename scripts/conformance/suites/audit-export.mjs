#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import "../../redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * The audit export to object storage (ADR-0056; capability
 * audit.storage-export), against a local S3 server with Object Lock (the
 * object-store capability: MinIO, pinned by digest, which the target's
 * outbound allow list opens and nothing else private). Its configuration
 * (ADR-0059 step 4.11a): the probe, creation, the retention tightened
 * without an approval, the changes that always ask for one, and a private
 * destination refused. The suite's own Organizations; it cancels the
 * approvals it asks for.
 *
 *   audit-export.mjs <origin> <api token>   (run by scripts/conformance/run.mjs)
 */
import { randomBytes } from "node:crypto";
import { listedKeys, s3Request } from "../lib/s3.mjs";
import { reporter, targetOp } from "../suite-kit.mjs";

const [origin, token] = process.argv.slice(2);
if (!origin || !token) {
  console.error("Usage: audit-export.mjs <origin> <api token>");
  process.exit(64);
}
const { check, error, finish } = reporter({ detailOnFailure: true });

async function api(method, path, { body, headers = {} } = {}) {
  const res = await fetch(new URL(path, origin), {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      "User-Agent": "varlatch-conformance-audit-export",
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
  return { status: res.status, json, text };
}

const ok = (r, what) => {
  if (r.status >= 300) throw new Error(`${what}: ${r.status} ${r.text}`);
  return r.json;
};

/** Asked for an approval: STEP_UP_REQUIRED with the approval to cancel. */
async function askedForApproval(r) {
  const id = r.json?.error?.details?.approval?.id;
  if (r.status === 403 && r.json?.error?.code === "STEP_UP_REQUIRED" && typeof id === "string") {
    ok(await api("POST", `/v1/me/approvals/${encodeURIComponent(id)}/cancel`), "cancelling the approval");
    return true;
  }
  return false;
}

const suffix = randomBytes(4).toString("hex");
const slug = `audit-export-${suffix}`;
const base = `/v1/organizations/${slug}/audit-export`;

try {
  ok(await api("GET", "/v1/me"), "whoami");
  const org = ok(await api("POST", "/v1/organizations", { body: { name: "Audit export suite", slug } }), "creating the Organization");
  const store = JSON.parse(targetOp("object-store", ["start"]));
  const s3 = { endpoint: store.hostEndpoint, region: store.region, accessKeyId: store.accessKeyId, secretAccessKey: store.secretAccessKey };
  const bucket = `audit-${suffix}`;
  const made = await s3Request(s3, "PUT", `/${bucket}`, { headers: { "x-amz-bucket-object-lock-enabled": "true" } });
  if (made.status !== 200) throw new Error(`creating the bucket: ${made.status} ${made.text.slice(0, 300)}`);
  const destination = { endpoint: store.endpoint, region: store.region, bucket, prefix: "varlatch", pathStyle: true };
  const credential = { accessKeyId: store.accessKeyId, secretAccessKey: store.secretAccessKey };

  const probed = ok(await api("POST", `${base}/check`, { body: { destination, credential, retention: { mode: "compliance", days: 1 } } }), "checking");
  check(
    "audit-export.check-probes",
    "checking a destination writes conditionally, reads the object and its retention back, and saves nothing",
    probed.ok === true && probed.conditionalCreation === true && probed.objectLock === "verified" && probed.keyCanRead === true &&
      probed.retentionReadable === true && ok(await api("GET", base), "reading").export === null,
    JSON.stringify(probed),
  );

  const created = await api("POST", base, { body: { destination, credential, retention: { mode: "governance", days: 1 } } });
  const view = created.json;
  check(
    "audit-export.create",
    "creating the export probes it and answers it active from the beginning of the log, Object Lock verified, never the key",
    created.status === 201 && view?.state === "active" && view.cursor === "0" && view.version === 1 && view.lockVerified === true &&
      view.objectLock === "verified" && view.destination.prefix === "varlatch/" && !created.text.includes(store.secretAccessKey),
    created.text,
  );
  const listed = await s3Request(s3, "GET", `/${bucket}`, { query: { "list-type": "2", prefix: `varlatch/varlatch-audit/${org.id}/probe/` } });
  const probes = listedKeys(listed.text);
  check(
    "audit-export.probe-objects-stay",
    "the probe's test objects stay in the bucket under the Organization's probe prefix",
    listed.status === 200 && probes.length >= 2 && probes.every((k) => /\/probe\/[0-9a-f]{32}\.json$/.test(k)),
    JSON.stringify(probes),
  );
  const again = await api("POST", base, { body: { destination, credential } });
  check(
    "audit-export.one-per-organization",
    "a second export is refused while one is live",
    again.status === 422 && again.json?.error?.details?.reason === "export-exists",
    again.text,
  );

  const tightened = await api("PATCH", base, { body: { expectedVersion: 1, retention: { mode: "compliance", days: 2 } } });
  check(
    "audit-export.tighten-without-approval",
    "a longer or stronger retention changes at once, without an approval",
    tightened.status === 200 && tightened.json?.changed === true && tightened.json?.loosened === false && tightened.json?.export?.version === 2 &&
      tightened.json?.export?.retention?.mode === "compliance",
    tightened.text,
  );

  const loosen = await api("PATCH", base, { body: { expectedVersion: 2, retention: null } });
  const moved = await api("PATCH", base, { body: { expectedVersion: 2, destination: { prefix: "elsewhere" } } });
  const rekeyed = await api("PUT", `${base}/credential`, { body: { expectedVersion: 2, credential } });
  const removed = await api("DELETE", `${base}?expectedVersion=2`);
  const asked = [await askedForApproval(loosen), await askedForApproval(moved), await askedForApproval(rekeyed), await askedForApproval(removed)];
  const after = ok(await api("GET", base), "reading again").export;
  check(
    "audit-export.loosening-needs-approval",
    "removing the retention, another destination, a new key and removal each ask for the requester's approval, and change nothing meanwhile",
    asked.every(Boolean) && after?.version === 2 && after?.destination?.prefix === "varlatch/" && after?.state === "active",
    JSON.stringify({ statuses: [loosen.status, moved.status, rekeyed.status, removed.status], after: after?.version }),
  );

  const other = `audit-export-refused-${suffix}`;
  ok(await api("POST", "/v1/organizations", { body: { name: "Audit export refused", slug: other } }), "creating the second Organization");
  const refused = await api("POST", `/v1/organizations/${other}/audit-export`, {
    body: { destination: { ...destination, endpoint: "https://10.255.0.1" }, credential },
  });
  check(
    "audit-export.private-endpoint-refused",
    "an endpoint at a private address is refused with the outbound policy's reason, before the key goes anywhere",
    refused.status === 422 && refused.json?.error?.details?.outbound === "private_address" && !refused.text.includes("10.255.0.1"),
    refused.text,
  );
} catch (err) {
  error(err instanceof Error ? err.stack ?? err.message : String(err));
}
finish("audit export checks");
