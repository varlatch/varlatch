// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHmac } from "node:crypto";
import { decrypt, type Envelope } from "../crypto/aead.js";
import type { Querier } from "../db/migrate.js";
import type { Digest } from "./bundle.js";
import { digestInput } from "./canonical.js";
import { ExportRefused } from "./refused.js";

/**
 * Decision 7's keyed digests (ADR-0059 step 7, go-step7): every item of
 * every encryption class decrypted, and HMAC-SHA256 under the migration's
 * run key over the canonical JSON of {class, ids, plaintext}
 * (canonical.ts digestInput). Only the digests leave: never a plaintext,
 * never the run key, which the caller reads from a pipe and clears.
 *
 * An item's class is its envelope's purpose and its ids are the rest of
 * its envelope's associated data (the AAD context both servers already
 * share), so varlatchd derives the same ids for the same item:
 *
 *   kek-canary               installationId              (Root KEK)
 *   org-kek                  organizationId              (Root KEK)
 *   dek                      organizationId, secretId, versionId (Organization KEK)
 *   value                    organizationId, secretId, versionId (the DEK)
 *   webhook-secret           organizationId, webhookId   (Organization KEK)
 *   platform-credential      organizationId, connectionId (Organization KEK)
 *   github-app-key           organizationId, githubAppId (Organization KEK;
 *                            an app's key, and a registration's pending key under its id)
 *   audit-export-credential  organizationId, exportId    (Organization KEK; active)
 *   audit-export-drain       organizationId, exportId    (Root KEK; draining)
 *   jwt-signing-key          keyId                       (Root KEK)
 *
 * Items are read within the export's snapshot; the bundle writer sorts
 * them (by class, then by ids as written, BUNDLE.md section 3). An item
 * under an Organization KEK that was destroyed (its Organization deleted)
 * is opened on neither side (CHECKS.md): no key opens it, and its bytes are
 * the rows check's. An erased value version is no item; an audit export
 * that has ended holds no credential.
 *
 * An item the schema says is there but that does not open (its envelope
 * null where its row says it holds one, or not opening under its key)
 * refuses the export, named by its table, column and ids, never a value.
 */

const envelopeOf = (v: unknown): Envelope => (typeof v === "string" ? (JSON.parse(v) as Envelope) : (v as Envelope));

/** The digests of every item, class by class, streamed. */
export async function* digests(client: Querier, rootKek: Buffer, runKey: Buffer): AsyncIterable<Digest> {
  if (runKey.length !== 32) throw new Error("export: the run key is not 256 bits");
  const item = (cls: string, ids: Record<string, string>, key: Buffer, envelope: unknown, where: string): Digest & { plaintext: Buffer } => {
    let plaintext: Buffer;
    try {
      if (envelope === null || envelope === undefined) throw new Error("no envelope");
      plaintext = decrypt(key, envelopeOf(envelope), { purpose: cls, ...ids });
    } catch {
      // The failure's own message is not shown: only where the item is.
      const named = Object.entries(ids).map(([k, v]) => `${k} ${v}`).join(", ");
      throw new ExportRefused(`the ${cls} item in ${where} (${named}) does not open: its row holds no envelope, or one its key does not open; nothing was exported`);
    }
    const hmac = createHmac("sha256", runKey).update(digestInput(cls, ids, plaintext)).digest("hex");
    return { class: cls, ids, hmac, plaintext };
  };
  const emit = (d: Digest & { plaintext: Buffer }): Digest => {
    d.plaintext.fill(0);
    return { class: d.class, ids: d.ids, hmac: d.hmac };
  };
  const rows = async (sql: string) => (await client.query(sql)).rows as Record<string, unknown>[];

  for (const r of await rows(`SELECT id, kek_canary FROM installation ORDER BY id COLLATE "C"`)) {
    yield emit(item("kek-canary", { installationId: String(r.id) }, rootKek, r.kek_canary, "installation.kek_canary"));
  }
  // The Organization KEKs, held only while their Organization's items are digested.
  const orgs = await rows(`SELECT id, wrapped_org_kek FROM organizations WHERE wrapped_org_kek IS NOT NULL ORDER BY id COLLATE "C"`);
  const orgKeks = new Map<string, Buffer>();
  try {
    for (const o of orgs) {
      const d = item("org-kek", { organizationId: String(o.id) }, rootKek, o.wrapped_org_kek, "organizations.wrapped_org_kek");
      orgKeks.set(String(o.id), Buffer.from(d.plaintext));
      yield emit(d);
    }
    // Null for an Organization whose KEK was destroyed: its items are skipped.
    const keyOf = (orgId: unknown): Buffer | null => orgKeks.get(String(orgId)) ?? null;
    for (const v of await rows(
      `SELECT vv.id, vv.value_id, vv.payload, vv.wrapped_dek, p.organization_id
         FROM value_versions vv JOIN env_values ev ON ev.id = vv.value_id
         JOIN environments e ON e.id = ev.environment_id JOIN projects p ON p.id = e.project_id
        WHERE vv.erased_at IS NULL
        ORDER BY p.organization_id COLLATE "C", vv.value_id COLLATE "C", vv.id COLLATE "C"`,
    )) {
      const orgKek = keyOf(v.organization_id);
      if (!orgKek) continue;
      const ids = { organizationId: String(v.organization_id), secretId: String(v.value_id), versionId: String(v.id) };
      const dek = item("dek", ids, orgKek, v.wrapped_dek, "value_versions.wrapped_dek");
      let value: Digest & { plaintext: Buffer };
      try {
        value = item("value", ids, dek.plaintext, v.payload, "value_versions.payload");
      } catch (err) {
        dek.plaintext.fill(0);
        throw err;
      }
      yield emit(dek);
      yield emit(value);
    }
    const perOrg = async (cls: string, idName: string, where: string, sql: string, keyFor: (r: Record<string, unknown>) => Buffer | null = (r) => keyOf(r.organization_id)) => {
      const out: Digest[] = [];
      for (const r of await rows(sql)) {
        const key = keyFor(r);
        if (!key) continue;
        out.push(emit(item(cls, { organizationId: String(r.organization_id), [idName]: String(r.id) }, key, r.envelope, where)));
      }
      return out;
    };
    yield* await perOrg("webhook-secret", "webhookId", "webhooks.secret_envelope",
      `SELECT id, organization_id, secret_envelope AS envelope FROM webhooks WHERE secret_envelope IS NOT NULL ORDER BY organization_id COLLATE "C", id COLLATE "C"`);
    yield* await perOrg("platform-credential", "connectionId", "platform_connections.credential_envelope",
      `SELECT id, organization_id, credential_envelope AS envelope FROM platform_connections WHERE credential_envelope IS NOT NULL ORDER BY organization_id COLLATE "C", id COLLATE "C"`);
    yield* await perOrg("github-app-key", "githubAppId", "github_apps.key_envelope",
      `SELECT id, organization_id, key_envelope AS envelope FROM github_apps WHERE key_envelope IS NOT NULL ORDER BY organization_id COLLATE "C", id COLLATE "C"`);
    yield* await perOrg("github-app-key", "githubAppId", "github_app_registrations.pending_key_envelope",
      `SELECT id, organization_id, pending_key_envelope AS envelope FROM github_app_registrations WHERE pending_key_envelope IS NOT NULL ORDER BY organization_id COLLATE "C", id COLLATE "C"`);
    yield* await perOrg("audit-export-credential", "exportId", "audit_exports.credential_envelope",
      `SELECT id, organization_id, credential_envelope AS envelope FROM audit_exports WHERE credential_envelope IS NOT NULL AND state <> 'draining' ORDER BY organization_id COLLATE "C", id COLLATE "C"`);
    yield* await perOrg("audit-export-drain", "exportId", "audit_exports.credential_envelope",
      `SELECT id, organization_id, credential_envelope AS envelope FROM audit_exports WHERE credential_envelope IS NOT NULL AND state = 'draining' ORDER BY organization_id COLLATE "C", id COLLATE "C"`,
      () => rootKek);
  } finally {
    for (const k of orgKeks.values()) k.fill(0);
  }
  for (const r of await rows(`SELECT id, private_key_wrapped FROM signing_keys ORDER BY id COLLATE "C"`)) {
    yield emit(item("jwt-signing-key", { keyId: String(r.id) }, rootKek, r.private_key_wrapped, "signing_keys.private_key_wrapped"));
  }
}
