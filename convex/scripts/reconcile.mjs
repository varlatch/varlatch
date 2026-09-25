#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Application Plane reconciliation — the convex-deploy one-shot (ADR-0035
 * D3/D4; ADR-0019 §6: the only place Convex deployment authority is used).
 *
 * Desired state: this image's function bundle (its stamped fingerprint) and
 * the trust configuration Convex needs to verify varlatchd's tokens
 * (VARLATCH_ISSUER, VARLATCH_JWKS_URL). Observed state: what the backend
 * actually serves (the public `meta:release` query) and trusts (its
 * environment) — never a recorded version number. The job changes only what
 * diverges; on an unchanged installation it changes nothing.
 *
 * Deployment authority: CONVEX_SELF_HOSTED_ADMIN_KEY when the installation
 * still provides one (existing installations; ADR-0035 D13 removes it only
 * after derivation is proven). Otherwise the key is derived here from the
 * instance secret with the pinned backend's own key tool — inside this
 * ephemeral container, handed to the Convex CLI through its environment,
 * never persisted, printed, or placed on another command line.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const APP = join(dirname(fileURLToPath(import.meta.url)), "..");
const TRUST_VARS = ["VARLATCH_ISSUER", "VARLATCH_JWKS_URL"];

/** Pure decision: what must change for observed to match desired. */
export function plan(observed, desired) {
  const setEnv = TRUST_VARS
    .filter((name) => desired.env[name] !== undefined && observed.env[name] !== desired.env[name])
    .map((name) => [name, desired.env[name]]);
  const reasons = [];
  if (observed.fingerprint !== desired.fingerprint) {
    reasons.push(observed.fingerprint
      ? `functions ${short(observed.fingerprint)} differ from this release's ${short(desired.fingerprint)}`
      : `functions do not report this release's fingerprint ${short(desired.fingerprint)}`);
  }
  // auth.config.ts reads the trust variables when functions are pushed, so a
  // changed trust configuration only takes effect with a deploy.
  if (setEnv.length) reasons.push(`trust configuration differs: ${setEnv.map(([n]) => n).join(", ")}`);
  return { setEnv, deploy: reasons.length > 0, reasons };
}

export function parseEnvList(text) {
  const env = {};
  for (const line of text.split("\n")) {
    const m = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (m) env[m[1]] = m[2];
  }
  return env;
}

const short = (fp) => (fp && fp.length > 12 ? `${fp.slice(0, 12)}…` : String(fp));

function stampedFingerprint() {
  const text = readFileSync(join(APP, "convex/releaseStamp.ts"), "utf8");
  const value = text.match(/FUNCTIONS_FINGERPRINT: string = "([^"]*)"/)?.[1];
  if (!value || value === "unstamped") throw new Error("This image's function bundle is not stamped (build it with scripts/fingerprint.mjs --stamp)");
  return value;
}

async function observeFingerprint(url) {
  try {
    const res = await fetch(`${url}/api/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: "meta:release", args: {}, format: "json" }),
      signal: AbortSignal.timeout(15_000),
    });
    const body = await res.json().catch(() => null);
    return body?.status === "success" ? (body.value?.fingerprint ?? null) : null;
  } catch {
    return null;
  }
}

/** A set variable wins; an empty or missing file (the unconfigured default) falls through. */
export function readSecret(env) {
  if (env.CONVEX_INSTANCE_SECRET?.trim()) return env.CONVEX_INSTANCE_SECRET.trim();
  if (!env.CONVEX_INSTANCE_SECRET_FILE) return "";
  try { return readFileSync(env.CONVEX_INSTANCE_SECRET_FILE, "utf8").trim(); } catch { return ""; }
}

function adminKey(env) {
  if (env.CONVEX_SELF_HOSTED_ADMIN_KEY) return { key: env.CONVEX_SELF_HOSTED_ADMIN_KEY, source: "provided" };
  const secret = readSecret(env);
  if (!secret) throw new Error("No deployment authority: set CONVEX_INSTANCE_SECRET (or CONVEX_INSTANCE_SECRET_FILE), or CONVEX_ADMIN_KEY for existing installations");
  const name = env.INSTANCE_NAME || "convex-self-hosted";
  const out = execFileSync("convex-generate-key", [name, secret], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  const key = out.trim().split("\n").pop();
  if (!key || !key.startsWith(`${name}|`)) throw new Error("The key tool returned no admin key");
  return { key, source: "derived" };
}

function convex(args, { url, key }) {
  try {
    return execFileSync(join(APP, "node_modules/.bin/convex"), args, {
      cwd: APP,
      encoding: "utf8",
      env: { ...process.env, CONVEX_SELF_HOSTED_URL: url, CONVEX_SELF_HOSTED_ADMIN_KEY: key },
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch (err) {
    const detail = `${err.stdout ?? ""}${err.stderr ?? ""}`.split(key).join("<admin key>");
    throw new Error(`convex ${args[0]} ${args[1] ?? ""} failed:\n${detail.trim()}`);
  }
}

async function main() {
  const env = process.env;
  const url = env.CONVEX_SELF_HOSTED_URL || "http://convex-backend:3210";
  const desired = {
    fingerprint: stampedFingerprint(),
    env: Object.fromEntries(TRUST_VARS.filter((n) => env[n]).map((n) => [n, env[n]])),
  };
  const auth = adminKey(env);
  const ctx = { url, key: auth.key };
  const observed = { fingerprint: await observeFingerprint(url), env: parseEnvList(convex(["env", "list"], ctx)) };
  const decision = plan(observed, desired);
  console.log(`reconcile: deployment authority ${auth.source}; desired functions ${short(desired.fingerprint)}`);
  if (!decision.deploy) {
    console.log("reconcile: functions and trust configuration current — nothing to change");
    return;
  }
  for (const reason of decision.reasons) console.log(`reconcile: ${reason}`);
  for (const [name, value] of decision.setEnv) {
    convex(["env", "set", name, value], ctx);
    console.log(`reconcile: set ${name}`);
  }
  convex(["deploy", "-y"], ctx);
  const after = await observeFingerprint(url);
  if (after !== desired.fingerprint) {
    throw new Error(`deploy finished but the backend reports ${short(after)}, not ${short(desired.fingerprint)}`);
  }
  console.log(`reconcile: deployed functions ${short(desired.fingerprint)}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(`reconcile failed: ${err.message}`);
    process.exit(1);
  });
}
