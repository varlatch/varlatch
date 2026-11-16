// SPDX-License-Identifier: Apache-2.0
/**
 * A minimal S3 client for the audit-export suite: AWS Signature Version 4
 * over fetch, path style, for the few requests the suite makes of the
 * local object store (create a bucket with Object Lock, list objects, read
 * an object and its retention). Standard library only.
 */
import { createHash, createHmac } from "node:crypto";

const sha256 = (data) => createHash("sha256").update(data).digest("hex");
const hmac = (key, data) => createHmac("sha256", key).update(data).digest();

/** RFC 3986 encoding, as SigV4 wants it ("/" kept in a path). */
function encode(s, keepSlash = false) {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`).replace(keepSlash ? /%2F/g : /$^/, "/");
}

/**
 * One signed request. `path` is "/bucket" or "/bucket/key"; `query` an
 * object of parameters; `headers` extra headers (signed too).
 */
export async function s3Request({ endpoint, region, accessKeyId, secretAccessKey }, method, path, { query = {}, headers = {}, body = "" } = {}) {
  const url = new URL(endpoint);
  const now = new Date();
  const amzDate = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const day = amzDate.slice(0, 8);
  const payloadHash = sha256(body);
  const canonicalQuery = Object.keys(query).sort().map((k) => `${encode(k)}=${encode(String(query[k]))}`).join("&");
  const all = { ...Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), String(v)])), host: url.host, "x-amz-date": amzDate, "x-amz-content-sha256": payloadHash };
  const names = Object.keys(all).sort();
  const canonicalHeaders = names.map((n) => `${n}:${all[n].trim()}\n`).join("");
  const signed = names.join(";");
  const canonicalPath = encode(path, true);
  const canonical = [method, canonicalPath, canonicalQuery, canonicalHeaders, signed, payloadHash].join("\n");
  const scope = `${day}/${region}/s3/aws4_request`;
  const toSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256(canonical)].join("\n");
  const key = hmac(hmac(hmac(hmac(`AWS4${secretAccessKey}`, day), region), "s3"), "aws4_request");
  const signature = createHmac("sha256", key).update(toSign).digest("hex");
  const authorization = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signed}, Signature=${signature}`;
  const res = await fetch(`${url.origin}${canonicalPath}${canonicalQuery ? `?${canonicalQuery}` : ""}`, {
    method,
    headers: { ...all, authorization },
    ...(body ? { body } : {}),
    signal: AbortSignal.timeout(30_000),
  });
  return { status: res.status, text: await res.text(), headers: res.headers };
}

/** The keys a ListObjectsV2 answer names. */
export function listedKeys(xml) {
  return [...xml.matchAll(/<Key>([^<]*)<\/Key>/g)].map((m) => m[1].replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">"));
}
