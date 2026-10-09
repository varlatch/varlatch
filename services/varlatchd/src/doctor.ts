// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from "node:fs";
import { activeGate, backupStatus, EMBEDDED_RELEASE } from "@varlatch/backup";
import type { Querier } from "./db/migrate.js";
import { schemaIsCurrent } from "./db/migrate.js";
import { getInstallation, verifyLoadedKek } from "./domain/bootstrap.js";
import type { AppCtx } from "./domain/ctx.js";
import { SERVER_VERSION } from "./http/app.js";
import { evaluateMirror, readMirrorStatus, type MirrorStatus } from "./mirror/status.js";
import { custodyStatus } from "./domain/custody.js";
import { readListenerReport, type ListenerReason, type TailnetListenerReport } from "./tailnet/observe.js";

/**
 * Read-only Installation Health checks that need the Secret Plane's own view
 * (ADR-0035 Decision 8). Run by `varlatchd admin doctor` inside the varlatchd
 * container on behalf of the host `varlatch doctor`; SELECTs and file reads
 * only — no writes, no locks, no audit events.
 *
 * Verified facts and unverifiable claims are never merged (Decision 9), and
 * every check says whether it passed, failed, or could not be determined.
 */

export type CheckStatus = "pass" | "fail" | "unknown";
export type CheckClass = "mandatory" | "advisory";

export interface Check {
  id: string;
  title: string;
  status: CheckStatus;
  class: CheckClass;
  detail?: string;
  remedy?: string;
}

export interface ServerFacts {
  serverVersion: string;
  releaseVersion: string;
  migrationVersion: number;
  publicUrl: string | null;
  convexConfigured: boolean;
  installationId: string | null;
  /** The tailnet browser endpoint as configured (ADR-0046); null when off. */
  tailnetBrowserEndpoint?: string | null;
}

export interface ServerDoctorReport {
  facts: ServerFacts;
  checks: Check[];
}

export interface ServerDoctorInput {
  /** Null when the Root KEK could not be loaded at all. */
  ctx: AppCtx | null;
  db: Querier;
  stateDir: string;
  publicUrl: string | undefined;
  convexUrl: string | undefined;
  /** How long to wait for Mirrors to reach the watermark. */
  waitMs?: number;
  readStatus?: (dir: string) => MirrorStatus | null;
  sleep?: (ms: number) => Promise<void>;
  /** The fingerprint this release's Application Plane functions carry. */
  expectedFunctions?: () => string | null;
  /** What Convex's `meta:release` reports; null when it cannot say. */
  observeFunctions?: (convexUrl: string) => Promise<string | null>;
  /** The tailnet listeners as configured; null without Tailscale. */
  tailnet?: { browserEndpoint: string | null } | null;
  readListeners?: (dir: string) => TailnetListenerReport | null;
  now?: () => number;
}

export const FUNCTIONS_FINGERPRINT_FILE = "/opt/varlatch/convex-functions.fingerprint";

function expectedFunctionsFromImage(): string | null {
  try {
    return readFileSync(process.env.VARLATCH_CONVEX_FINGERPRINT_FILE ?? FUNCTIONS_FINGERPRINT_FILE, "utf8").trim() || null;
  } catch {
    return null;
  }
}

async function observeFunctionsViaQuery(convexUrl: string): Promise<string | null> {
  try {
    const res = await fetch(`${convexUrl}/api/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: "meta:release", args: {}, format: "json" }),
      signal: AbortSignal.timeout(10_000),
    });
    const body = (await res.json().catch(() => null)) as { status?: string; value?: { fingerprint?: string } } | null;
    return body?.status === "success" ? (body.value?.fingerprint ?? null) : null;
  } catch {
    return null;
  }
}

export const CUSTODY_MAX_AGE_DAYS = 180;

/**
 * ADR-0035 D9: an attestation is a dated claim, never a check. It is shown
 * as such, ages into an advisory finding, and a replaced Root KEK voids it.
 */
export async function checkCustody(db: Querier, now = Date.now()): Promise<Check> {
  const base = { id: "custody.attestations", title: "Off-host recovery key copies (operator attestation)", class: "advisory" as const };
  const remedy = "Store the Root KEK and backup key off this host, then record it: `varlatch setup` (escrow step) or `varlatchd admin custody attest`";
  let status: Awaited<ReturnType<typeof custodyStatus>>;
  try {
    status = await custodyStatus(db);
  } catch {
    return { ...base, status: "unknown", detail: "attestations could not be read" };
  }
  const problems: string[] = [];
  const claims: string[] = [];
  for (const key of ["root-kek", "backup-key"] as const) {
    const a = status.attestations[key];
    if (!a) {
      problems.push(key === "root-kek" ? `no attestation for Root KEK version ${status.rootKekVersion}` : "no attestation for the backup key");
      continue;
    }
    const days = Math.floor((now - Date.parse(a.at)) / 86_400_000);
    if (days > CUSTODY_MAX_AGE_DAYS) problems.push(`${key} attested ${days} days ago (${a.method}) — re-confirm`);
    else claims.push(`${key} attested ${a.at.slice(0, 10)} (${a.method})`);
  }
  const caveat = "the installation cannot verify that copies exist";
  return problems.length
    ? { ...base, status: "fail", detail: [...problems, ...claims].join("; ") + ` — ${caveat}`, remedy }
    : { ...base, status: "pass", detail: `${claims.join("; ")} — ${caveat}` };
}

/** ADR-0035 D4: observed, not recorded — what the backend actually serves. */
export async function checkFunctions(input: ServerDoctorInput, maintenance: boolean): Promise<Check> {
  const base = { id: "application-plane.functions", title: "Application Plane functions match the release", class: "mandatory" as const };
  if (!input.convexUrl) return { ...base, status: "unknown", detail: "no Application Plane configured" };
  if (maintenance) return { ...base, status: "unknown", detail: "the Application Plane is paused while installation maintenance is active" };
  const expected = (input.expectedFunctions ?? expectedFunctionsFromImage)();
  if (!expected) return { ...base, status: "unknown", detail: "this varlatchd image carries no function fingerprint (development build)" };
  const observed = await (input.observeFunctions ?? observeFunctionsViaQuery)(input.convexUrl);
  if (observed === expected) return { ...base, status: "pass", detail: `serving ${expected.slice(0, 12)}…` };
  return {
    ...base,
    status: "fail",
    detail: observed
      ? `Convex serves functions ${observed.slice(0, 12)}…, this release expects ${expected.slice(0, 12)}…`
      : "Convex does not report a function fingerprint (not deployed, a release before this check, or unreachable)",
    remedy: "Reconcile the Application Plane: docker compose run --rm convex-deploy",
  };
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

export function checkPublicUrl(publicUrl: string | undefined): Check {
  const base = { id: "config.public-url", title: "Public URL", class: "mandatory" as const };
  const remedy =
    "Set VARLATCH_PUBLIC_URL to the exact origin users open in the browser, e.g. https://vault.example.com";
  if (!publicUrl) {
    return { ...base, status: "fail", detail: "VARLATCH_PUBLIC_URL is not set; passkeys and tokens fall back to localhost", remedy };
  }
  let url: URL;
  try {
    url = new URL(publicUrl);
  } catch {
    return { ...base, status: "fail", detail: `not a valid URL: ${publicUrl}`, remedy };
  }
  if (url.pathname !== "/" || url.search || url.hash) {
    return { ...base, status: "fail", detail: `must be an origin without path or query: ${publicUrl}`, remedy };
  }
  if (url.protocol !== "https:" && !LOOPBACK.has(url.hostname)) {
    return {
      ...base,
      status: "fail",
      detail: `${url.origin} is not HTTPS; browsers only allow passkeys on HTTPS or localhost`,
      remedy: "Serve the dashboard over HTTPS and set VARLATCH_PUBLIC_URL to the https:// origin",
    };
  }
  return { ...base, status: "pass", detail: `${url.origin} (passkey RP ID ${url.hostname})` };
}

export function checkBackups(dir: string, now = Date.now()): Check {
  const base = { id: "backups.status", title: "Backups", class: "advisory" as const };
  let status: ReturnType<typeof backupStatus>;
  try {
    status = backupStatus(dir, now);
  } catch {
    return { ...base, status: "unknown", detail: "backup status records are unreadable" };
  }
  if (status.warnings.length === 0) {
    const newest = status.archives[0]!;
    return { ...base, status: "pass", detail: `newest archive ${newest.archiveId} created ${newest.createdAt}, verified` };
  }
  return {
    ...base,
    status: "fail",
    detail: status.warnings.join("; "),
    remedy: "See `varlatch admin backup status` and docs/operations/backup.md",
  };
}

async function latestEventOrder(db: Querier): Promise<string> {
  const res = await db.query("SELECT coalesce(max(event_order),0)::text AS position FROM audit_events");
  return (res.rows[0] as { position: string }).position;
}

export async function checkMirror(input: ServerDoctorInput, maintenance: boolean): Promise<Check> {
  const base = { id: "mirror.catch-up", title: "Dashboard read models (Mirrors)", class: "mandatory" as const };
  if (!input.convexUrl) {
    return {
      ...base,
      status: "fail",
      detail: "VARLATCH_CONVEX_URL is not set; varlatchd publishes no Mirrors",
      remedy: "Set VARLATCH_CONVEX_URL (canonical Compose: http://convex-backend:3210)",
    };
  }
  if (maintenance) {
    return { ...base, status: "unknown", detail: "publication is paused while installation maintenance is active" };
  }
  const read = input.readStatus ?? readMirrorStatus;
  const sleep = input.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
  const watermark = await latestEventOrder(input.db);
  const deadline = Date.now() + (input.waitMs ?? 15_000);
  let verdict = evaluateMirror(read(input.stateDir), watermark);
  while (verdict.state === "behind" && Date.now() < deadline) {
    await sleep(500);
    verdict = evaluateMirror(read(input.stateDir), watermark);
  }
  switch (verdict.state) {
    case "caught-up":
      return { ...base, status: "pass", detail: `published through audit position ${watermark}` };
    case "behind":
      return {
        ...base,
        status: "fail",
        detail: `published through ${verdict.cursorOrder ?? "nothing"}, expected at least ${watermark}`,
        remedy: "Check varlatchd logs for `mirror sync failed`",
      };
    case "rejected":
      return {
        ...base,
        status: "fail",
        detail: `Convex rejects varlatchd's mirror token: ${verdict.message}`,
        remedy:
          "Convex's trust configuration (VARLATCH_ISSUER / VARLATCH_JWKS_URL) does not match this installation; redeploy the Application Plane functions with the current public URL",
      };
    case "failing":
      return { ...base, status: "fail", detail: verdict.message, remedy: "Check that convex-backend is running and reachable from varlatchd" };
    case "unknown":
      return { ...base, status: "unknown", detail: `${verdict.reason} (daemon older than this check, or just started)` };
  }
}

/** A listener report older than this says nothing about now: the daemon is not running, or stuck. */
const LISTENERS_STALE_MS = 10 * 60_000;

const REASON_TEXT: Record<ListenerReason, string> = {
  NOT_CHECKED: "not checked yet",
  NOT_LISTENING: "a tailnet listener did not bind its port",
  NO_CERTIFICATE: "no valid certificate is loaded",
  LOCALAPI_UNAVAILABLE: "tailscaled's LocalAPI does not answer",
  NOT_RUNNING: "the node is not connected to the tailnet",
  OTHER_TAILNET: "the node is on another tailnet than the pinned one",
  NAME_CHANGED: "the node's name is no longer the browser endpoint's host",
};

/**
 * The tailnet listeners as varlatchd last observed them (ADR-0046, Listener
 * metadata), and what no check here can know: whether a browser reaches the
 * endpoint. Advisory: Tailscale never decides whether the installation is
 * ready (ADR-0019).
 */
export function checkTailnet(input: ServerDoctorInput): Check[] {
  if (!input.tailnet) return [];
  const listener = { id: "tailnet.listener", title: "Tailnet listener", class: "advisory" as const };
  let report: TailnetListenerReport | null;
  try {
    report = (input.readListeners ?? readListenerReport)(input.stateDir);
  } catch {
    report = null;
  }
  const checkedAt = report?.observed.checkedAt ? Date.parse(report.observed.checkedAt) : NaN;
  const now = (input.now ?? Date.now)();
  if (!report || !Number.isFinite(checkedAt) || now - checkedAt > LISTENERS_STALE_MS) {
    const why = !report ? "varlatchd has not reported its tailnet listeners" : "varlatchd's last report is older than 10 minutes";
    const unknown = (c: typeof listener) => ({ ...c, status: "unknown" as const, detail: `${why} (just started, not running, or older than this check)` });
    return [
      unknown(listener),
      ...(input.tailnet.browserEndpoint ? [unknown({ id: "tailnet.browser-endpoint", title: "Tailnet browser endpoint", class: "advisory" })] : []),
    ];
  }
  const { listener: bound, localApi, node } = report.observed.checks;
  const failing = [bound, localApi, node].filter((c) => c.status === "fail");
  const checks: Check[] = [
    failing.length
      ? {
          ...listener,
          status: "fail",
          detail: failing.map((c) => REASON_TEXT[c.reason ?? "NOT_CHECKED"]).join("; "),
          remedy: "Inspect: docker compose logs tailscale varlatchd",
        }
      : [bound, localApi, node].every((c) => c.status === "pass")
        ? { ...listener, status: "pass", detail: `port ${report.configured.listenerPort}, tailnet ${report.configured.tailnet}, checked ${report.observed.checkedAt}` }
        : { ...listener, status: "unknown", detail: "not every part could be checked yet" },
  ];
  if (input.tailnet.browserEndpoint) {
    const tls = report.observed.checks.browserTls;
    const base = { id: "tailnet.browser-endpoint", title: "Tailnet browser endpoint", class: "advisory" as const };
    checks.push(
      tls?.status === "pass"
        ? { ...base, status: "pass", detail: `${input.tailnet.browserEndpoint}, certificate valid until ${tls.certificateNotAfter}` }
        : tls?.status === "fail"
          ? {
              ...base,
              status: "fail",
              detail: `${input.tailnet.browserEndpoint}: ${REASON_TEXT[tls.reason ?? "NO_CERTIFICATE"]}`,
              remedy:
                "The sidecar must let varlatchd's user fetch certificates (TS_PERMIT_CERT_UID) and the tailnet must have HTTPS certificates enabled: run `varlatch setup --tailnet-endpoint` again",
            }
          : { ...base, status: "unknown", detail: "not checked yet" },
      {
        id: "tailnet.browser-reachability",
        title: "Tailnet browser endpoint reachable from browsers",
        class: "advisory",
        status: "unknown",
        detail:
          "only a browser on an approved device can tell: use Connect to tailnet in the dashboard. Its device needs an access rule allowing the endpoint's port",
      },
    );
  }
  return checks;
}

export async function serverDoctor(input: ServerDoctorInput): Promise<ServerDoctorReport> {
  const checks: Check[] = [];
  let gate: ReturnType<typeof activeGate> = null;
  let gateUnreadable = false;
  try {
    gate = activeGate(input.stateDir);
  } catch {
    gateUnreadable = true;
  }

  const installation = await getInstallation(input.db).catch(() => null);
  const schema = await schemaIsCurrent(input.db).catch(() => false);
  const kek = input.ctx ? await verifyLoadedKek(input.ctx).catch(() => false) : false;
  const problems = [
    ...(gateUnreadable ? ["maintenance state unreadable (isolation stays active)"] : []),
    ...(gate ? [`installation ${gate.kind} in progress (${gate.phase}); requests are paused by design`] : []),
    ...(installation ? [] : ["installation not initialized"]),
    ...(schema ? [] : ["database migrations are not current for this binary"]),
    ...(kek ? [] : [input.ctx ? "loaded Root KEK does not match the installation canary" : "Root KEK could not be loaded"]),
  ];
  checks.push({
    id: "secret-plane.ready",
    title: "Secret Plane ready",
    class: "mandatory",
    status: problems.length ? "fail" : "pass",
    ...(problems.length
      ? { detail: problems.join("; ") }
      : { detail: `schema current, Root KEK verified against canary, installation ${installation!.id}` }),
  });

  checks.push(checkPublicUrl(input.publicUrl));
  checks.push(await checkMirror(input, gate !== null || gateUnreadable));
  checks.push(await checkFunctions(input, gate !== null || gateUnreadable));
  checks.push(checkBackups(input.stateDir));
  checks.push(await checkCustody(input.db));
  checks.push(...checkTailnet(input));

  return {
    facts: {
      serverVersion: SERVER_VERSION,
      releaseVersion: EMBEDDED_RELEASE.version,
      migrationVersion: EMBEDDED_RELEASE.migrationVersion,
      publicUrl: input.publicUrl ?? null,
      convexConfigured: Boolean(input.convexUrl),
      installationId: installation?.id ?? null,
      tailnetBrowserEndpoint: input.tailnet?.browserEndpoint ?? null,
    },
    checks,
  };
}
