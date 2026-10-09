// SPDX-License-Identifier: Apache-2.0
import { foreign, isRecord, jsonBody, unexpected, unreachable, type AccessCheck, type AccessCheckWhere } from "./access.js";
import {
  AdapterError,
  DEFAULT_TIMEOUT_MS,
  type AdapterRequest,
  type NameOutcome,
  type PlatformAdapter,
  type SyncItem,
} from "./types.js";

/**
 * Coolify adapter. Base identity is the instance origin — the admin's choice
 * of host is the trust decision (ADR-0031 §8); the adapter additionally
 * requires https, follows no redirects, and pins the configured host.
 * Coolify tokens are inherently instance-wide, so the Connection is the
 * truthful scoping unit. Env values can be read back, so the repair pass may
 * verify-and-fix instead of force-writing.
 *
 * Destination record: `applicationUuid` is the identity (the exclusivity
 * key); the remaining fields are per-target options the engine passes
 * through untouched:
 * - `buildTime` ("true" | "false"): whether keys Varlatch manages are
 *   available at build time. Values baked into a build (VITE_*, NEXT_PUBLIC_*)
 *   are invisible to it otherwise. Absent = Coolify's own default for new
 *   keys, and existing keys keep whatever the operator set.
 * - `deployAction` ("deploy" | "restart"): what the redeploy trigger does.
 *   "deploy" (default) queues a forced rebuild, the only action that
 *   re-bakes build-time values; "restart" only recreates the container
 *   with the current runtime env — faster, and enough for runtime-only apps.
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
 * - The start/restart actions accept POST on every version and, since
 *   v4.3, POST only (GET answers 405).
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

/** Flags for a new key: the option when set, otherwise Coolify's default. */
function createFlags(style: FlagStyle, buildTime: boolean | undefined): Record<string, boolean> {
  if (buildTime === undefined) return {};
  return style === "current"
    ? { is_buildtime: buildTime, is_runtime: true }
    : { is_build_time: buildTime };
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
      is_literal: Boolean(row.is_literal),
      is_multiline: Boolean(row.is_multiline),
      is_shown_once: Boolean(row.is_shown_once),
      is_buildtime: buildTime ?? Boolean(row.is_buildtime),
      // A runtime-only request must stay reachable at runtime; otherwise
      // keep the operator's choice (a build-only var stays build-only).
      is_runtime: buildTime === false ? true : (row.is_runtime ?? true),
    };
  }
  if (style === "legacy") {
    return {
      is_literal: Boolean(row.is_literal),
      is_build_time: buildTime ?? Boolean(row.is_build_time),
    };
  }
  // Unknown vocabulary: send nothing we cannot name.
  return {};
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

/** Production env rows only: the endpoint merges preview-deployment rows in. */
async function listEnvs(req: AdapterRequest): Promise<CoolifyEnv[]> {
  const app = req.destination.applicationUuid as string;
  const res = await request(req, "GET", `/applications/${app}/envs`);
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

  validateName(name: string): string | null {
    if (!NAME_PATTERN.test(name)) {
      return "Coolify env keys allow only letters, digits, and _, not starting with a digit";
    }
    return null;
  },

  canonicalizeName(name: string): string {
    return name;
  },

  async writeValues(req: AdapterRequest, items: SyncItem[]): Promise<NameOutcome[]> {
    const app = req.destination.applicationUuid as string;
    const path = `/applications/${app}/envs`;
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
      const row = existing.get(item.name);
      let res: Response;
      if (row) {
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
        if (res.status === 422 && buildTime !== undefined && style === undefined) {
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
    const app = req.destination.applicationUuid as string;
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
      const res = await request(req, "DELETE", `/applications/${app}/envs/${uuid}`);
      outcomes.push(
        res.ok || res.status === 404
          ? { name, ok: true }
          : { name, ok: false, error: `HTTP ${res.status}` },
      );
    }
    return outcomes;
  },

  async readValues(req: AdapterRequest): Promise<Map<string, string>> {
    return new Map((await listEnvs(req)).map((e) => [e.key, e.value ?? ""]));
  },

  /**
   * Deploy (forced rebuild, so build-time values are re-baked and no cached
   * layer can serve a stale one) unless the target opted for a restart.
   * Throws on a non-2xx so the caller can surface "pushed but not
   * redeployed" instead of reporting a phantom success.
   */
  async triggerRedeploy(req: AdapterRequest): Promise<void> {
    if (req.shouldAbort && (await req.shouldAbort())) return;
    const app = req.destination.applicationUuid as string;
    const restart = req.destination.deployAction === "restart";
    const res = await request(
      req,
      "POST",
      restart ? `/applications/${app}/restart` : `/applications/${app}/start?force=true`,
    );
    if (!res.ok) {
      throw new AdapterError(`Coolify ${restart ? "restart" : "deploy"} failed (${res.status})`);
    }
  },

  /**
   * The instance first (/version needs the read permission, so a token, the
   * API switch and the IP allowlist are all exercised), then, for a
   * destination, the application itself. Coolify tokens are team-scoped:
   * another team's application is a 404 like a mistyped UUID.
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
      const app = req.destination.applicationUuid;
      if (!app) return { status: "ok", where, message: "Coolify accepted the token." };

      where = "destination";
      const res = await request(req, "GET", `/applications/${app}`);
      if (res.ok) {
        const found = await jsonBody(res);
        if (!isRecord(found) || found.uuid !== app) {
          return {
            status: "failed",
            where,
            httpStatus: res.status,
            message: `${host} did not answer with application ${app}. Check the instance URL and the UUID.`,
          };
        }
        return {
          status: "ok",
          where,
          message: `The token can read application ${app}. The first push shows whether it may also write its variables.`,
        };
      }
      if (res.status === 401) return TOKEN_REJECTED;
      if (res.status === 403) return await forbidden(res, where);
      if (res.status === 404) {
        return {
          status: "not-found",
          where,
          httpStatus: 404,
          message: `The token's team has no application ${app} on ${host}. Copy the UUID from the application's URL in Coolify.`,
        };
      }
      return unexpected("Coolify", res.status, where);
    } catch (err) {
      return unreachable(host, err, where);
    }
  },
};
