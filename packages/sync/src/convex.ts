// SPDX-License-Identifier: Apache-2.0
import { unexpected, unreachable, type AccessCheck } from "./access.js";
import {
  AdapterError,
  DEFAULT_TIMEOUT_MS,
  type AdapterRequest,
  type NameOutcome,
  type PlatformAdapter,
  type SyncItem,
} from "./types.js";

/**
 * Convex adapter: one adapter for Convex Cloud deployments and self-hosted
 * Convex backends. Base identity is the deployment URL as an https origin
 * (https://happy-animal-123.convex.cloud, or a self-hosted origin) — pinned
 * like the Coolify adapter: https required, no redirects followed. The URL is
 * always explicit, never derived from a deploy key's embedded deployment
 * name: keys can point at custom domains, and an explicit URL keeps cloud and
 * self-hosted on one code path.
 *
 * Both credential kinds are per-deployment — a cloud deploy key
 * (CONVEX_DEPLOY_KEY) or a self-hosted admin key
 * (CONVEX_SELF_HOSTED_ADMIN_KEY) — so the honest scoping unit is one
 * Connection per deployment, and the base identity IS the destination: the
 * destination record is empty and the destination key is stable ("").
 *
 * Convex API compatibility — verified against the convex-js CLI and the
 * open-source backend (both deployment kinds expose the same routes under
 * the deployment URL, authenticated with `Authorization: Convex <key>`):
 * - Read: POST /api/query running the system query the CLI's `env list`
 *   uses (_system/cli/queryEnvironmentVariables); returns [{name, value}].
 * - Write/delete: POST /api/update_environment_variables with
 *   {changes: [{name, value}]}, value null meaning delete — the CLI's
 *   `env set`/`env remove` route. One batch call is one transaction;
 *   deleting an absent name succeeds (already converged).
 * - Names: /^[A-Za-z_][A-Za-z0-9_]*$/, at most 256 chars, case-sensitive
 *   (backend NAME_REGEX + MAX_NAME_LENGTH); the backend forbids exactly the
 *   system names CONVEX_CLOUD_URL and CONVEX_SITE_URL. Values are limited
 *   to 8 KiB (backend MAX_VALUE_LENGTH, measured in UTF-8 bytes) — checked
 *   locally so one oversized value cannot poison the batch. The backend
 *   also enforces per-deployment count and aggregate-size limits; those
 *   still reject a batch as a whole.
 *
 * - Access check: GET /api/check_admin_key, the dashboard's own key check;
 *   it answers {isReadOnly, allowedOps} (an empty list allows everything)
 *   and 403 for a key made for another deployment.
 *
 * Functions read env vars live on each call — there is no restart concept,
 * so supportsRedeploy is false and no triggerRedeploy exists.
 */

const NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
const MAX_NAME_LENGTH = 256;
const MAX_VALUE_BYTES = 8 * 1024;
/** The backend's forbidden system names (not a blanket CONVEX_ prefix ban). */
const RESERVED_NAMES = new Set(["CONVEX_CLOUD_URL", "CONVEX_SITE_URL"]);

const ENV_LIST_QUERY = "_system/cli/queryEnvironmentVariables";

interface ConvexEnvVar {
  name: string;
  value: string;
}

/** POST with a body; GET without one (the access check). */
async function request(
  req: AdapterRequest,
  path: string,
  body?: unknown,
): Promise<Response> {
  const url = new URL(`${req.baseIdentity}${path}`);
  // Host pinning: the base identity is an https origin; nothing (including a
  // redirect, which we refuse to follow) may move a request off it.
  const fetchImpl = req.fetchImpl ?? fetch;
  try {
    return await fetchImpl(url.toString(), {
      method: body === undefined ? "GET" : "POST",
      headers: {
        Authorization: `Convex ${req.credential}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      redirect: "error",
      signal: AbortSignal.timeout(req.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    });
  } catch (err) {
    throw new AdapterError(err instanceof Error ? err.name : "fetch failed");
  }
}

/**
 * One batch update per the CLI's own route: the whole batch is one
 * transaction, so every name shares the request's outcome.
 */
async function updateEnvironmentVariables(
  req: AdapterRequest,
  changes: { name: string; value: string | null }[],
): Promise<NameOutcome[]> {
  if (req.shouldAbort && (await req.shouldAbort())) return [];
  const res = await request(req, "/api/update_environment_variables", { changes });
  return changes.map(({ name }) =>
    res.ok ? { name, ok: true } : { name, ok: false, error: `HTTP ${res.status}` },
  );
}

export const convexAdapter: PlatformAdapter = {
  platform: "convex",
  credentialScopeUnit: "destination",
  supportsReadBack: true,
  supportsRedeploy: false,

  canonicalizeBaseIdentity(raw: string): string {
    let url: URL;
    try {
      url = new URL(raw.trim());
    } catch {
      throw new AdapterError("Invalid Convex deployment URL", false);
    }
    if (url.protocol !== "https:") {
      throw new AdapterError("Convex deployment URL must be https", false);
    }
    if (url.username || url.password) {
      throw new AdapterError("Convex deployment URL must not contain userinfo credentials", false);
    }
    if (url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) {
      throw new AdapterError("Convex deployment URL must be a bare origin (https://host[:port])", false);
    }
    return url.origin.toLowerCase();
  },

  canonicalizeDestination(raw: Record<string, unknown>) {
    // The base identity IS the deployment: there is nothing to narrow to,
    // so the destination is empty and its key is stable.
    for (const [field, value] of Object.entries(raw)) {
      if (value !== undefined && value !== null && value !== "") {
        throw new AdapterError(
          `Convex destinations take no fields (got ${field}): the Connection's deployment URL is the destination`,
          false,
        );
      }
    }
    return { destination: {}, key: "" };
  },

  validateName(name: string): string | null {
    if (!NAME_PATTERN.test(name)) {
      return "Convex env var names allow only letters, digits, and _, not starting with a digit";
    }
    if (name.length > MAX_NAME_LENGTH) {
      return `Convex env var names are limited to ${MAX_NAME_LENGTH} characters`;
    }
    if (RESERVED_NAMES.has(name)) return `${name} is a reserved Convex system name`;
    return null;
  },

  canonicalizeName(name: string): string {
    return name;
  },

  async writeValues(req: AdapterRequest, items: SyncItem[]): Promise<NameOutcome[]> {
    // The batch is one transaction: a value over the backend's 8 KiB limit
    // would fail every name with it, so oversized items are failed locally
    // and only the rest enter the batch.
    const oversized = new Map<string, NameOutcome>();
    const sendable: SyncItem[] = [];
    for (const item of items) {
      if (Buffer.byteLength(item.value, "utf8") > MAX_VALUE_BYTES) {
        oversized.set(item.name, {
          name: item.name,
          ok: false,
          error: `value exceeds Convex's ${MAX_VALUE_BYTES}-byte limit`,
        });
      } else {
        sendable.push(item);
      }
    }
    const sent =
      sendable.length > 0
        ? await updateEnvironmentVariables(
            req,
            sendable.map(({ name, value }) => ({ name, value })),
          )
        : [];
    const byName = new Map(sent.map((o) => [o.name, o]));
    // Input order, but an aborted batch stays visibly cut short: only names
    // that were actually decided (locally or on the wire) get an outcome.
    return items
      .map((item) => oversized.get(item.name) ?? byName.get(item.name))
      .filter((o): o is NameOutcome => o !== undefined);
  },

  async deleteNames(req: AdapterRequest, names: string[]): Promise<NameOutcome[]> {
    return updateEnvironmentVariables(
      req,
      names.map((name) => ({ name, value: null })),
    );
  },

  async readValues(req: AdapterRequest): Promise<Map<string, string>> {
    const res = await request(req, "/api/query", {
      path: ENV_LIST_QUERY,
      args: {},
      format: "json",
    });
    if (!res.ok) {
      throw new AdapterError(
        `Convex env query failed (${res.status})`,
        res.status !== 401 && res.status !== 403 && res.status !== 404,
      );
    }
    const parsed = (await res.json()) as { status?: string; value?: unknown };
    // A UDF-level error body never enters the message: it is server-composed
    // text we do not control.
    if (parsed.status !== "success" || !Array.isArray(parsed.value)) {
      throw new AdapterError("Convex env query failed (udf error)");
    }
    return new Map(
      (parsed.value as ConvexEnvVar[])
        .filter((e) => e && typeof e.name === "string")
        .map((e) => [e.name, typeof e.value === "string" ? e.value : ""]),
    );
  },

  async checkAccess(req: AdapterRequest): Promise<AccessCheck> {
    const host = new URL(req.baseIdentity).host;
    // The deployment is both the Connection and the destination.
    const where = "connection";
    try {
      const res = await request(req, "/api/check_admin_key");
      if (res.status === 401 || res.status === 403) {
        return {
          status: "credential-rejected",
          where,
          httpStatus: res.status,
          message: "Convex rejected the key for this deployment. A key works only for the deployment it was made for: check that it matches this URL.",
        };
      }
      if (res.status === 404) {
        return { status: "not-found", where, httpStatus: 404, message: `No Convex deployment answered at ${host}. Check the deployment URL.` };
      }
      if (!res.ok) return unexpected("Convex", res.status, where);
      let key: { isReadOnly?: unknown; allowedOps?: unknown };
      try {
        key = (await res.json()) as typeof key;
      } catch {
        return { status: "failed", where, httpStatus: res.status, message: `${host} answered, but not like a Convex deployment. Check the deployment URL.` };
      }
      const ops = Array.isArray(key.allowedOps) ? key.allowedOps : [];
      if (key.isReadOnly === true || (ops.length > 0 && !ops.includes("WriteEnvironmentVariables"))) {
        return {
          status: "permission-missing",
          where,
          httpStatus: res.status,
          message: "Convex accepted the key, but it may not change environment variables. Use a deploy key with full access, or the admin key.",
        };
      }
      return { status: "ok", where, message: "Convex accepted the key, and it may set environment variables." };
    } catch (err) {
      return unreachable(host, err, where);
    }
  },
};
