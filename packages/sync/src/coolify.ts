// SPDX-License-Identifier: Apache-2.0
import {
  MAX_DESTINATIONS,
  foreign,
  isRecord,
  jsonBody,
  listingFailed,
  shortText,
  unexpected,
  unreachable,
  type AccessCheck,
  type AccessCheckWhere,
  type DestinationListing,
  type DestinationOption,
} from "./access.js";
import {
  AdapterError,
  DEFAULT_TIMEOUT_MS,
  type AdapterRequest,
  type NameOutcome,
  type PlatformAdapter,
  type SyncItem,
  type UsageReport,
} from "./types.js";
import { classifyComposeUsage, coolifyOwnsName } from "./coolifyCompose.js";

/**
 * Coolify adapter. Base identity is the instance origin — the admin's choice
 * of host is the trust decision (ADR-0031 §8); the adapter additionally
 * requires https, follows no redirects, and pins the configured host.
 * Coolify tokens are inherently instance-wide, so the Connection is the
 * truthful scoping unit. Env values can be read back, so the repair pass may
 * verify-and-fix instead of force-writing.
 *
 * Destination record: exactly one of `applicationUuid` (an application) or
 * `serviceUuid` (a service: a Compose stack whose variables every container
 * shares, ADR-0031 amendment 2026-10-21) is the identity (the exclusivity
 * key: the bare uuid for an application, `service:<uuid>` for a service).
 * The remaining fields are per-target options the engine passes through
 * untouched, for applications only:
 * - `buildTime` ("true" | "false"): whether keys Varlatch manages are
 *   available at build time. Values baked into a build (VITE_*, NEXT_PUBLIC_*)
 *   are invisible to it otherwise. Absent = Coolify's own default for new
 *   keys, and existing keys keep whatever the operator set.
 * - `deployAction` ("deploy" | "restart"): what the redeploy trigger does.
 *   "deploy" (default) queues a forced rebuild, the only action that
 *   re-bakes build-time values; "restart" only recreates the container
 *   with the current runtime env — faster, and enough for runtime-only apps.
 * A service always restarts (Coolify's `/start` refuses a running one), and
 * its variables have no build-time flag.
 *
 * Coolify API compatibility — verified against the upstream source:
 * - GET /applications/{uuid}/envs returns production AND preview rows in one
 *   list (every version); only production rows are ours.
 * - Env flags were renamed in September 2025: `is_build_time` (default
 *   false on create; PATCH resets it to false when omitted) became
 *   `is_buildtime` + `is_runtime` (default true on create; PATCH leaves them
 *   alone when omitted). PATCH also resets `is_literal` to false when
 *   omitted on every version, and unknown fields are rejected with 422. The
 *   adapter mirrors an existing row's flags back on PATCH and infers the
 *   flag style from the rows it listed (falling back on 422 for an empty app).
 * - A service's variable PATCH keeps every flag it is not sent (beta.420
 *   fills only what it gets; 4.4 sets only what is present), so a service
 *   write sends the key and value alone.
 * - A credential without `read:sensitive` lists variables without their
 *   `value` (4.4 omits the key); so does a "shown once" variable. That is
 *   an unreadable value, not an empty one.
 * - The start/restart actions accept POST on every version and, since
 *   v4.3, POST only (GET answers 405). A service restart is queued: it
 *   rewrites the service's `.env`, stops the whole stack and recreates it.
 */

const TOKEN_REJECTED: AccessCheck = {
  status: "credential-rejected",
  where: "connection",
  httpStatus: 401,
  message: "Coolify rejected the token: it is mistyped, or was deleted.",
};

/** What /api/v1/version answers: the bare version, e.g. 4.0.0-beta.420. */
const VERSION_TEXT = /^"?v?\d+\.\d+[\w.+-]*"?$/;

const UUID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9-]{2,63}$/;
const NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

interface CoolifyEnv {
  uuid: string;
  key: string;
  value: string | null;
  is_preview?: boolean | null;
  is_literal?: boolean | null;
  is_multiline?: boolean | null;
  is_shown_once?: boolean | null;
  /** Legacy flag (before September 2025). */
  is_build_time?: boolean | null;
  /** Current flags. */
  is_buildtime?: boolean | null;
  is_runtime?: boolean | null;
}

/** Which env-flag vocabulary the instance speaks. */
type FlagStyle = "current" | "legacy";

function flagStyleOf(row: CoolifyEnv): FlagStyle | undefined {
  if ("is_buildtime" in row || "is_runtime" in row) return "current";
  if ("is_build_time" in row) return "legacy";
  return undefined;
}

function buildTimeOption(destination: Record<string, string>): boolean | undefined {
  if (destination.buildTime === "true") return true;
  if (destination.buildTime === "false") return false;
  return undefined;
}

/**
 * Flags for a new key: literal (multiline too where the vocabulary has it),
 * so the value reaches the container as stored; the build-time option when
 * set, otherwise Coolify's default.
 */
function createFlags(style: FlagStyle, buildTime: boolean | undefined): Record<string, boolean> {
  if (style === "current") {
    return { is_literal: true, is_multiline: true, ...(buildTime === undefined ? {} : { is_buildtime: buildTime, is_runtime: true }) };
  }
  return { is_literal: true, ...(buildTime === undefined ? {} : { is_build_time: buildTime }) };
}

/**
 * Flags for an existing key: mirror what the row already has so a
 * value-only update never silently strips a flag, then apply the
 * build-time option on top. Only fields the instance's PATCH accepts are
 * sent (legacy rejects is_multiline/is_shown_once with 422).
 */
function updateFlags(row: CoolifyEnv, buildTime: boolean | undefined): Record<string, boolean> {
  const style = flagStyleOf(row);
  if (style === "current") {
    return {
      // Literal and multiline: Coolify then quotes the value instead of
      // expanding it (ADR-0031 amendment 2026-10-21, value fidelity).
      is_literal: true,
      is_multiline: true,
      is_shown_once: Boolean(row.is_shown_once),
      is_buildtime: buildTime ?? Boolean(row.is_buildtime),
      // A runtime-only request must stay reachable at runtime; otherwise
      // keep the operator's choice (a build-only var stays build-only).
      is_runtime: buildTime === false ? true : (row.is_runtime ?? true),
    };
  }
  if (style === "legacy") {
    return {
      is_literal: true,
      is_build_time: buildTime ?? Boolean(row.is_build_time),
    };
  }
  // Unknown vocabulary: only the flag every version names.
  return { is_literal: true };
}

async function request(
  req: AdapterRequest,
  method: string,
  path: string,
  body?: unknown,
): Promise<Response> {
  const url = new URL(`${req.baseIdentity}/api/v1${path}`);
  // Host pinning: the base identity is an https origin; nothing (including a
  // redirect, which we refuse to follow) may move a request off it.
  const fetchImpl = req.fetchImpl ?? fetch;
  try {
    return await fetchImpl(url.toString(), {
      method,
      headers: {
        Authorization: `Bearer ${req.credential}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      redirect: "error",
      signal: AbortSignal.timeout(req.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    });
  } catch (err) {
    throw new AdapterError(err instanceof Error ? err.name : "fetch failed", true, { cause: err });
  }
}

/**
 * Coolify answers 403 for several unrelated reasons; its message picks the
 * advice. The message is matched, never repeated.
 */
async function forbidden(res: Response, where: AccessCheckWhere): Promise<AccessCheck> {
  let message = "";
  try {
    const body = (await res.json()) as { message?: unknown };
    if (typeof body.message === "string") message = body.message;
  } catch {
    // Not JSON: fall through to the general advice.
  }
  const advice = /API is disabled/i.test(message)
    ? "The API is off on this Coolify instance. Turn on API access in its settings."
    : /not allowed to access the API/i.test(message)
      ? "Coolify accepts API calls only from listed IP addresses, and this server's is not among them."
      : /exceed your current role/i.test(message)
        ? "The token belongs to a team member, and Coolify limits members to read-only tokens. Create it as a team admin or owner."
        : "Coolify refused the token. It needs the read and write permissions, plus deploy to redeploy.";
  return { status: "permission-missing", where, httpStatus: 403, message: advice };
}


/** Which resource a canonical destination names, and where its API lives. */
interface Resource {
  kind: "application" | "service";
  uuid: string;
  /** `/applications/{uuid}` or `/services/{uuid}`. */
  path: string;
}

function resourceOf(destination: Record<string, string>): Resource {
  if (destination.serviceUuid) {
    return { kind: "service", uuid: destination.serviceUuid, path: `/services/${destination.serviceUuid}` };
  }
  const uuid = destination.applicationUuid as string;
  return { kind: "application", uuid, path: `/applications/${uuid}` };
}

/** Production env rows only: the application endpoint merges preview-deployment rows in. */
async function listEnvs(req: AdapterRequest): Promise<CoolifyEnv[]> {
  const res = await request(req, "GET", `${resourceOf(req.destination).path}/envs`);
  if (!res.ok) {
    throw new AdapterError(
      `Coolify env list failed (${res.status})`,
      res.status !== 401 && res.status !== 403 && res.status !== 404,
    );
  }
  const parsed = (await res.json()) as unknown;
  return Array.isArray(parsed)
    ? (parsed as CoolifyEnv[]).filter((e) => e && typeof e === "object" && !e.is_preview)
    : [];
}

/** What PHP's trim() removes, which Coolify applies to every value it stores and reads. */
const PHP_TRIMMED = /^[ \t\n\r\0\x0B]|[ \t\n\r\0\x0B]$/;
/** Coolify's shared-variable types, replaced inside `{{type.NAME}}` (and `vault` for a linked secret manager). */
const SHARED_TYPES = new Set(["team", "project", "environment", "server", "vault"]);

/**
 * Why a value would not reach the destination's containers exactly as
 * given, or null when it does. Varlatch writes every value literal and
 * multiline, so Coolify puts it in single quotes, unescaped, in the `.env`
 * Docker Compose reads; what that cannot carry is refused rather than
 * delivered changed (ADR-0031 amendment 2026-10-21, value fidelity).
 */
function undeliverableValue(value: string, copiedIntoCompose: boolean): string | null {
  if (PHP_TRIMMED.test(value)) {
    return "Coolify removes leading and trailing whitespace from values, so it would store a different value";
  }
  if (value.includes("'")) {
    return "Coolify writes values in single quotes without escaping, so a value with a single quote breaks the .env it deploys";
  }
  if (/(?:^|[^\\])(?:\\\\)*\\$/.test(value)) {
    return "Coolify writes values in single quotes, so a value ending in a backslash breaks the .env it deploys";
  }
  for (const [, inner] of value.matchAll(/\{\{(.*?)\}\}/g)) {
    const type = /^([^.]*)\./.exec((inner ?? "").trim())?.[1];
    if (type !== undefined && SHARED_TYPES.has(type)) {
      return "Coolify replaces {{" + type + ".…}} with one of its shared variables, so it would deliver a different value";
    }
  }
  if ((value.startsWith("{") || value.startsWith("[")) && isJson(value) && /[$\n]| #/.test(value)) {
    return "Coolify writes JSON values unquoted, where Docker Compose changes $, \" #\" and line breaks";
  }
  if (copiedIntoCompose && value.includes("$")) {
    return "The service's compose file copies this value where Docker Compose expands $, so it would arrive changed";
  }
  return null;
}

function isJson(value: string): boolean {
  try {
    JSON.parse(value);
    return true;
  } catch {
    return false;
  }
}

/** Coolify's labels for a service's containers (its applications and databases), bounded. */
function containerNames(service: Record<string, unknown>): string[] {
  const names: string[] = [];
  for (const list of [service.applications, service.databases]) {
    if (!Array.isArray(list)) continue;
    for (const item of list) {
      const name = isRecord(item) ? shortText(item.name, 64) : undefined;
      if (name) names.push(name);
    }
  }
  return [...new Set(names)].sort().slice(0, 20);
}

const SERVICE_ENV_FORBIDDEN =
  "Coolify lets only team admins and owners manage a service's variables. Create the token as one.";

export const coolifyAdapter: PlatformAdapter = {
  platform: "coolify",
  credentialScopeUnit: "instance",
  supportsReadBack: true,
  supportsRedeploy: true,

  canonicalizeBaseIdentity(raw: string): string {
    let url: URL;
    try {
      url = new URL(raw.trim());
    } catch {
      throw new AdapterError("Invalid Coolify instance URL", false);
    }
    if (url.protocol !== "https:") {
      throw new AdapterError("Coolify instance URL must be https", false);
    }
    if (url.username || url.password) {
      throw new AdapterError("Coolify instance URL must not contain userinfo credentials", false);
    }
    if (url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) {
      throw new AdapterError("Coolify instance URL must be a bare origin (https://host[:port])", false);
    }
    return url.origin.toLowerCase();
  },

  canonicalizeDestination(raw: Record<string, unknown>) {
    const given = (v: unknown) => v !== undefined && v !== null && v !== "";
    const service = typeof raw.serviceUuid === "string" ? raw.serviceUuid.trim() : "";
    if (given(raw.serviceUuid)) {
      if (given(raw.applicationUuid)) {
        throw new AdapterError("A Coolify destination is an application or a service, not both", false);
      }
      if (!UUID_PATTERN.test(service)) {
        throw new AdapterError("Invalid Coolify service UUID", false);
      }
      // A service's variables have no build-time flag, and its only
      // redeploy is a restart of the whole stack.
      if (given(raw.buildTime)) {
        throw new AdapterError("A Coolify service takes no buildTime option: its variables have no build-time flag", false);
      }
      if (given(raw.deployAction)) {
        throw new AdapterError("A Coolify service takes no deployAction option: it always restarts", false);
      }
      // The prefix keeps a service's claim apart from any application's
      // bare uuid (the pattern admits no colon).
      return { destination: { serviceUuid: service }, key: `service:${service}` };
    }

    const uuid = typeof raw.applicationUuid === "string" ? raw.applicationUuid.trim() : "";
    if (!UUID_PATTERN.test(uuid)) {
      throw new AdapterError("Invalid Coolify application UUID", false);
    }
    const destination: Record<string, string> = { applicationUuid: uuid };

    const buildTime = raw.buildTime;
    if (buildTime === true || buildTime === "true") destination.buildTime = "true";
    else if (buildTime === false || buildTime === "false") destination.buildTime = "false";
    else if (buildTime !== undefined && buildTime !== null && buildTime !== "") {
      throw new AdapterError('Coolify buildTime must be "true" or "false"', false);
    }

    const deployAction = raw.deployAction;
    if (deployAction === "restart") destination.deployAction = "restart";
    else if (deployAction === "deploy") destination.deployAction = "deploy";
    else if (deployAction !== undefined && deployAction !== null && deployAction !== "") {
      throw new AdapterError('Coolify deployAction must be "deploy" or "restart"', false);
    }

    // Options never enter the identity: the same application is the same
    // destination whatever its flags (ADR-0031 §1).
    return { destination, key: uuid };
  },

  validateName(name: string, destination?: Record<string, string>): string | null {
    if (!NAME_PATTERN.test(name)) {
      return "Coolify env keys allow only letters, digits, and _, not starting with a digit";
    }
    if (destination?.serviceUuid && coolifyOwnsName(name)) {
      return "Coolify sets this name itself on a service (SERVICE_FQDN_*, SERVICE_URL_*, SERVICE_NAME_*, COOLIFY_*)";
    }
    return null;
  },

  canonicalizeName(name: string): string {
    return name;
  },

  async writeValues(req: AdapterRequest, items: SyncItem[]): Promise<NameOutcome[]> {
    const resource = resourceOf(req.destination);
    const path = `${resource.path}/envs`;
    const rows = await listEnvs(req);
    const existing = new Map(rows.map((e) => [e.key, e]));
    const buildTime = buildTimeOption(req.destination);
    // The instance's flag vocabulary, learned from any row it returned; an
    // empty application reveals nothing, so the first create guesses the
    // current vocabulary and falls back once on a validation rejection.
    let style: FlagStyle | undefined;
    for (const row of rows) {
      style = flagStyleOf(row);
      if (style) break;
    }
    const outcomes: NameOutcome[] = [];
    for (const item of items) {
      if (req.shouldAbort && (await req.shouldAbort())) break;
      const problem = undeliverableValue(item.value, Boolean(req.usage?.names.get(item.name)?.copiedIntoCompose));
      if (problem) {
        // Nothing is sent: a value Coolify would change is not delivered.
        outcomes.push({ name: item.name, ok: false, error: problem });
        continue;
      }
      const row = existing.get(item.name);
      let res: Response;
      if (resource.kind === "service") {
        // Literal and multiline, as for an application; a service PATCH
        // keeps every flag it is not sent.
        res = await request(req, row ? "PATCH" : "POST", path, {
          key: item.name,
          value: item.value,
          is_literal: true,
          is_multiline: true,
        });
      } else if (row) {
        res = await request(req, "PATCH", path, {
          key: item.name,
          value: item.value,
          is_preview: false,
          ...updateFlags(row, buildTime),
        });
      } else {
        const create = (s: FlagStyle) =>
          request(req, "POST", path, {
            key: item.name,
            value: item.value,
            is_preview: false,
            ...createFlags(s, buildTime),
          });
        res = await create(style ?? "current");
        if (res.status === 422 && style === undefined) {
          // Nothing was written (validation rejected the unknown field):
          // retry once in the legacy vocabulary and remember it.
          style = "legacy";
          res = await create(style);
        } else if (res.ok && style === undefined) {
          style = "current";
        }
      }
      outcomes.push(
        res.ok ? { name: item.name, ok: true } : { name: item.name, ok: false, error: `HTTP ${res.status}` },
      );
    }
    return outcomes;
  },

  async deleteNames(req: AdapterRequest, names: string[]): Promise<NameOutcome[]> {
    const resource = resourceOf(req.destination);
    const byKey = new Map((await listEnvs(req)).map((e) => [e.key, e.uuid]));
    const outcomes: NameOutcome[] = [];
    for (const name of names) {
      if (req.shouldAbort && (await req.shouldAbort())) break;
      const uuid = byKey.get(name);
      if (!uuid) {
        // Already absent: converged.
        outcomes.push({ name, ok: true });
        continue;
      }
      const res = await request(req, "DELETE", `${resource.path}/envs/${uuid}`);
      outcomes.push(
        res.ok || res.status === 404
          ? { name, ok: true }
          : { name, ok: false, error: `HTTP ${res.status}` },
      );
    }
    return outcomes;
  },

  async readValues(req: AdapterRequest): Promise<Map<string, string | null>> {
    // A row without `value` is one Coolify withholds (no read:sensitive, or
    // shown once): unreadable. A stored empty or null value is "".
    return new Map((await listEnvs(req)).map((e) => [e.key, "value" in e ? (e.value ?? "") : null]));
  },

  /**
   * An application deploys (forced rebuild, so build-time values are
   * re-baked and no cached layer can serve a stale one) unless the target
   * opted for a restart; a service restarts, which rewrites its `.env` and
   * recreates every container. Both are queued by Coolify: success means
   * requested. Throws on a non-2xx so the caller can surface "pushed but
   * not redeployed" instead of reporting a phantom success.
   */
  async triggerRedeploy(req: AdapterRequest): Promise<void> {
    if (req.shouldAbort && (await req.shouldAbort())) return;
    const resource = resourceOf(req.destination);
    const restart = resource.kind === "service" || req.destination.deployAction === "restart";
    const res = await request(req, "POST", restart ? `${resource.path}/restart` : `${resource.path}/start?force=true`);
    if (!res.ok) {
      throw new AdapterError(`Coolify ${restart ? "restart" : "deploy"} failed (${res.status})`);
    }
  },

  /**
   * The instance first (/version needs the read permission, so a token, the
   * API switch and the IP allowlist are all exercised), then, for a
   * destination, the application or service itself. Coolify tokens are
   * team-scoped: another team's resource is a 404 like a mistyped UUID. A
   * service is also asked for its variables, the request every push
   * starts with: Coolify lets only team admins and owners manage them.
   */
  async checkAccess(req: AdapterRequest): Promise<AccessCheck> {
    const host = new URL(req.baseIdentity).host;
    let where: AccessCheckWhere = "connection";
    try {
      const version = await request(req, "GET", "/version");
      if (version.status === 401) return TOKEN_REJECTED;
      if (version.status === 403) return await forbidden(version, where);
      if (version.status === 404) {
        return { status: "not-found", where, httpStatus: 404, message: `No Coolify API answered at ${host}. Check the instance URL.` };
      }
      // A sign-in page in front of the instance answers 200 as well.
      if (!version.ok || !VERSION_TEXT.test((await version.text()).trim())) {
        return foreign("Coolify", "instance", host, version.status);
      }
      if (!req.destination.applicationUuid && !req.destination.serviceUuid) {
        return { status: "ok", where, message: "Coolify accepted the token." };
      }

      where = "destination";
      const resource = resourceOf(req.destination);
      const res = await request(req, "GET", resource.path);
      if (res.ok) {
        const found = await jsonBody(res);
        if (!isRecord(found) || found.uuid !== resource.uuid) {
          return {
            status: "failed",
            where,
            httpStatus: res.status,
            message: `${host} did not answer with ${resource.kind} ${resource.uuid}. Check the instance URL and the UUID.`,
          };
        }
        if (resource.kind === "application") {
          return {
            status: "ok",
            where,
            message: `The token can read application ${resource.uuid}. The first push shows whether it may also write its variables.`,
          };
        }
        return await checkServiceVariables(req, resource, found, host);
      }
      if (res.status === 401) return TOKEN_REJECTED;
      if (res.status === 403) return await forbidden(res, where);
      if (res.status === 404) {
        return {
          status: "not-found",
          where,
          httpStatus: 404,
          message: `The token's team has no ${resource.kind} ${resource.uuid} on ${host}. Copy the UUID from the ${resource.kind}'s URL in Coolify.`,
        };
      }
      return unexpected("Coolify", res.status, where);
    } catch (err) {
      return unreachable(host, err, where);
    }
  },

  /**
   * The applications and services of the token's team, by name, an
   * application with its first address. Coolify answers with whole
   * records; only the uuid, name and address leave the adapter, whatever
   * else a broad token can read. Services follow the applications: when
   * only they cannot be listed, the applications still are.
   */
  async listDestinations(req: AdapterRequest): Promise<DestinationListing> {
    const host = new URL(req.baseIdentity).host;
    const where = "connection";
    try {
      const res = await request(req, "GET", "/applications");
      if (res.status === 401) return listingFailed(TOKEN_REJECTED);
      if (res.status === 403) return listingFailed(await forbidden(res, where));
      if (res.status === 404) {
        return listingFailed({ status: "not-found", where, httpStatus: 404, message: `No Coolify API answered at ${host}. Check the instance URL.` });
      }
      const apps = res.ok ? await jsonBody(res) : undefined;
      if (!Array.isArray(apps)) return listingFailed(foreign("Coolify", "instance", host, res.status));
      const items: DestinationOption[] = [];
      for (const app of apps) {
        if (!isRecord(app) || typeof app.uuid !== "string" || !UUID_PATTERN.test(app.uuid)) continue;
        const address = shortText(typeof app.fqdn === "string" ? app.fqdn.split(",")[0]?.replace(/^https?:\/\//, "") : undefined);
        items.push({
          destination: { applicationUuid: app.uuid },
          label: shortText(app.name) ?? app.uuid,
          ...(address ? { detail: address } : {}),
        });
      }
      const appCount = items.length;

      let servicesNote = "";
      const svcRes = await request(req, "GET", "/services");
      const services = svcRes.ok ? await jsonBody(svcRes) : undefined;
      if (Array.isArray(services)) {
        for (const svc of services) {
          if (!isRecord(svc) || typeof svc.uuid !== "string" || !UUID_PATTERN.test(svc.uuid)) continue;
          // The list route returns no containers, so a service has no address here.
          items.push({ destination: { serviceUuid: svc.uuid }, label: shortText(svc.name) ?? svc.uuid, detail: "service" });
        }
      } else {
        servicesNote = ` Its services could not be listed (HTTP ${svcRes.status}).`;
      }
      const serviceCount = items.length - appCount;
      items.sort((a, b) => a.label.localeCompare(b.label));
      return {
        check: {
          status: "ok",
          where,
          message: `The token's team has ${appCount} applications${Array.isArray(services) ? ` and ${serviceCount} services` : ""} on ${host}.${servicesNote}`,
        },
        items: items.slice(0, MAX_DESTINATIONS),
        truncated: items.length > MAX_DESTINATIONS,
      };
    } catch (err) {
      return listingFailed(unreachable(host, err, where));
    }
  },

  /**
   * A service's compose files, read where the token may (Coolify's
   * read:sensitive), classified inside this adapter: only names,
   * container names and verdicts leave it. An application has no compose
   * notion here (null). Never throws.
   */
  async inspectUsage(req: AdapterRequest, names: string[]): Promise<UsageReport | null> {
    const resource = resourceOf(req.destination);
    if (resource.kind !== "service") return null;
    const unchecked = (reason: string): UsageReport => ({ checked: false, reason, names: new Map(names.map((n) => [n, {}])) });
    let body: unknown;
    try {
      const res = await request(req, "GET", resource.path);
      if (!res.ok) return unchecked(`Coolify did not return the service (HTTP ${res.status})`);
      body = await jsonBody(res);
    } catch {
      return unchecked("Coolify could not be reached");
    }
    if (!isRecord(body) || body.uuid !== resource.uuid) return unchecked("Coolify did not answer with the service");
    if (!("docker_compose_raw" in body)) {
      return unchecked("Coolify did not return the service's compose file to this token (reading it takes its read:sensitive permission)");
    }
    const version = Number(body.compose_parsing_version);
    return classifyComposeUsage(
      typeof body.docker_compose_raw === "string" ? body.docker_compose_raw : null,
      typeof body.docker_compose === "string" ? body.docker_compose : null,
      Number.isFinite(version) ? version : null,
      names,
    );
  },
};

/**
 * A service's variables, the push's first request: whether the token may
 * manage them, and whether it can read their values. Values are discarded.
 */
async function checkServiceVariables(
  req: AdapterRequest,
  resource: Resource,
  service: Record<string, unknown>,
  host: string,
): Promise<AccessCheck> {
  const where = "destination";
  const res = await request(req, "GET", `${resource.path}/envs`);
  if (res.status === 401) return TOKEN_REJECTED;
  if (res.status === 403) {
    const advice = await forbidden(res, where);
    // Coolify's policy refusal carries no reason of its own.
    return advice.message.startsWith("Coolify refused the token") ? { ...advice, message: SERVICE_ENV_FORBIDDEN } : advice;
  }
  if (res.status === 404) {
    return { status: "not-found", where, httpStatus: 404, message: `The token's team has no service ${resource.uuid} on ${host}.` };
  }
  if (!res.ok) return unexpected("Coolify", res.status, where);
  const rows = await jsonBody(res);
  if (!Array.isArray(rows)) {
    return { status: "failed", where, httpStatus: res.status, message: `${host} did not answer with the variables of service ${resource.uuid}.` };
  }
  const name = shortText(service.name) ?? resource.uuid;
  const containers = containerNames(service);
  const reach = containers.length > 0
    ? `Every variable reaches all of its containers (${containers.join(", ")}), and any added later.`
    : "Every variable reaches all of its containers, and any added later.";
  // What Coolify returned, not why: a row listed without its value is
  // withheld (no read:sensitive, or shown once), and an empty list says
  // nothing either way.
  const withheld = rows.filter((r) => isRecord(r) && !("value" in r)).length;
  const unreadable =
    withheld === 0
      ? ""
      : withheld === rows.length
        ? " Coolify returned none of their values to this token (reading them takes its read:sensitive permission): repairs rewrite every value, and the compose file is likely unreadable too."
        : ` Coolify withheld ${withheld} of ${rows.length} values from this token (shown once, or no read:sensitive): repairs rewrite those.`;
  return {
    status: "ok",
    where,
    message: `The token can manage the variables of service ${name}. ${reach}${unreadable} The first push shows whether it may also write them.`,
  };
}
