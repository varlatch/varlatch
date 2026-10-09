// SPDX-License-Identifier: Apache-2.0
import { isRecord, jsonBody, unexpected, unreachable, type AccessCheck, type AccessCheckWhere } from "./access.js";
import { sealedBox } from "./sealedbox.js";
import {
  AdapterError,
  DEFAULT_TIMEOUT_MS,
  type AdapterRequest,
  type NameOutcome,
  type PlatformAdapter,
  type SyncItem,
} from "./types.js";

/**
 * GitHub Actions secrets adapter. Base identity is the repository owner;
 * the destination is one repository, optionally narrowed to a repository
 * environment (the platform-side namespace). Values are encrypted client-side
 * with the destination's public key (libsodium sealed box) — GitHub never
 * returns secret values, so this platform cannot verify-and-fix; the repair
 * pass force-writes instead.
 */

const API = "https://api.github.com";
const OWNER_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37})$/;
const REPO_PATTERN = /^[A-Za-z0-9._-]{1,100}$/;
/** GitHub stores secret names uppercased; GITHUB_ is reserved. */
const NAME_PATTERN = /^[A-Z_][A-Z0-9_]*$/;

interface PublicKey {
  key_id: string;
  key: string;
}

function headers(credential: string): Record<string, string> {
  return {
    Authorization: `Bearer ${credential}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "varlatch-sync",
    "Content-Type": "application/json",
  };
}

function secretsBase(req: AdapterRequest): string {
  const { repo, environment } = req.destination;
  const repoPath = `${API}/repos/${req.baseIdentity}/${repo}`;
  return environment
    ? `${repoPath}/environments/${encodeURIComponent(environment)}/secrets`
    : `${repoPath}/actions/secrets`;
}

const TOKEN_REJECTED: AccessCheck = {
  status: "credential-rejected",
  where: "connection",
  httpStatus: 401,
  message: "GitHub rejected the token: it is mistyped, expired, or revoked.",
};

/** GitHub signals its primary rate limit with a 403 as well as a 429. */
function rateLimited(res: Response): boolean {
  return res.status === 429 || res.headers.get("x-ratelimit-remaining") === "0";
}

/** A 200 that is not GitHub's API: a proxy or a sign-in page in the way. */
function notGitHub(where: AccessCheckWhere): AccessCheck {
  return {
    status: "failed",
    where,
    httpStatus: 200,
    message: "The answer from api.github.com was not GitHub's. A proxy between this server and GitHub may be in the way.",
  };
}

function refused(res: Response, where: AccessCheckWhere): AccessCheck {
  return unexpected("GitHub", rateLimited(res) ? 429 : res.status, where);
}

async function request(
  req: AdapterRequest,
  method: string,
  url: string,
  body?: unknown,
): Promise<Response> {
  const fetchImpl = req.fetchImpl ?? fetch;
  try {
    return await fetchImpl(url, {
      method,
      headers: headers(req.credential),
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      redirect: "error",
      signal: AbortSignal.timeout(req.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    });
  } catch (err) {
    throw new AdapterError(err instanceof Error ? err.name : "fetch failed", true, { cause: err });
  }
}

export const githubActionsAdapter: PlatformAdapter = {
  platform: "github-actions",
  credentialScopeUnit: "destination",
  supportsReadBack: false,
  supportsRedeploy: false,

  canonicalizeBaseIdentity(raw: string): string {
    const owner = raw.trim().replace(/^@/, "");
    if (!OWNER_PATTERN.test(owner)) {
      throw new AdapterError("Invalid GitHub owner (user or organization login)", false);
    }
    return owner.toLowerCase();
  },

  canonicalizeDestination(raw: Record<string, unknown>) {
    const repo = typeof raw.repo === "string" ? raw.repo.trim() : "";
    if (!REPO_PATTERN.test(repo)) {
      throw new AdapterError("Invalid GitHub repository name", false);
    }
    const environment =
      typeof raw.environment === "string" && raw.environment.trim() !== ""
        ? raw.environment.trim()
        : undefined;
    if (environment !== undefined && environment.length > 255) {
      throw new AdapterError("Invalid GitHub environment name", false);
    }
    const destination = {
      repo: repo.toLowerCase(),
      ...(environment !== undefined ? { environment } : {}),
    };
    return {
      destination,
      key: environment !== undefined ? `${destination.repo}#${environment}` : destination.repo,
    };
  },

  validateName(name: string): string | null {
    const canonical = name.toUpperCase();
    if (!NAME_PATTERN.test(canonical)) {
      return "GitHub secret names allow only letters, digits, and _, not starting with a digit";
    }
    if (canonical.startsWith("GITHUB_")) return "GITHUB_-prefixed secret names are reserved";
    if (canonical.length > 200) return "GitHub secret names are limited to 200 characters";
    return null;
  },

  canonicalizeName(name: string): string {
    return name.toUpperCase();
  },

  async writeValues(req: AdapterRequest, items: SyncItem[]): Promise<NameOutcome[]> {
    const base = secretsBase(req);
    const keyRes = await request(req, "GET", `${base}/public-key`);
    if (!keyRes.ok) {
      throw new AdapterError(
        `GitHub public key fetch failed (${keyRes.status})`,
        keyRes.status !== 401 && keyRes.status !== 403 && keyRes.status !== 404,
      );
    }
    const publicKey = (await keyRes.json()) as PublicKey;
    const recipient = new Uint8Array(Buffer.from(publicKey.key, "base64"));

    const outcomes: NameOutcome[] = [];
    for (const item of items) {
      if (req.shouldAbort && (await req.shouldAbort())) break;
      const sealed = sealedBox(new Uint8Array(Buffer.from(item.value, "utf8")), recipient);
      const res = await request(req, "PUT", `${base}/${encodeURIComponent(item.name)}`, {
        encrypted_value: Buffer.from(sealed).toString("base64"),
        key_id: publicKey.key_id,
      });
      outcomes.push(
        res.ok ? { name: item.name, ok: true } : { name: item.name, ok: false, error: `HTTP ${res.status}` },
      );
    }
    return outcomes;
  },

  async deleteNames(req: AdapterRequest, names: string[]): Promise<NameOutcome[]> {
    const base = secretsBase(req);
    const outcomes: NameOutcome[] = [];
    for (const name of names) {
      if (req.shouldAbort && (await req.shouldAbort())) break;
      const res = await request(req, "DELETE", `${base}/${encodeURIComponent(name)}`);
      // A 404 is converged: the name is already absent.
      outcomes.push(
        res.ok || res.status === 404
          ? { name, ok: true }
          : { name, ok: false, error: `HTTP ${res.status}` },
      );
    }
    return outcomes;
  },

  /**
   * The owner first (a bad token is a 401 on any route), then, for a
   * destination, the public-key read every push starts with: it needs
   * Secrets (repository secrets) or Environments (environment secrets)
   * read permission. GitHub answers 404 for a repository outside the
   * token's selection, so a missing environment is told apart by reading
   * the repository itself.
   */
  async checkAccess(req: AdapterRequest): Promise<AccessCheck> {
    const owner = req.baseIdentity;
    const { repo, environment } = req.destination;
    let where: AccessCheckWhere = "connection";
    try {
      const user = await request(req, "GET", `${API}/users/${owner}`);
      if (user.status === 401) return TOKEN_REJECTED;
      if (user.status === 404) {
        return { status: "not-found", where, httpStatus: 404, message: `GitHub has no user or organization named ${owner}.` };
      }
      if (!user.ok) return refused(user, where);
      const account = await jsonBody(user);
      if (!isRecord(account) || typeof account.login !== "string") return notGitHub(where);
      if (!repo) return { status: "ok", where, message: `GitHub accepted the token, and ${owner} exists.` };

      where = "destination";
      const place = environment ? `${owner}/${repo} (environment ${environment})` : `${owner}/${repo}`;
      const permission = environment ? "Environments" : "Secrets";
      const key = await request(req, "GET", `${secretsBase(req)}/public-key`);
      if (key.ok) {
        const publicKey = await jsonBody(key);
        if (!isRecord(publicKey) || typeof publicKey.key_id !== "string" || typeof publicKey.key !== "string") {
          return notGitHub(where);
        }
        return {
          status: "ok",
          where,
          message: `The token can read the secrets of ${place}. The first push shows whether it may also write them.`,
        };
      }
      if (key.status === 401) return TOKEN_REJECTED;
      if (key.status === 403 && !rateLimited(key)) {
        return {
          status: "permission-missing",
          where,
          httpStatus: 403,
          message: `GitHub refused the token access to the secrets of ${place}. Give it ${permission}: Read and write, and check that the organization approved it.`,
        };
      }
      if (key.status === 404) {
        if (environment && (await request(req, "GET", `${API}/repos/${owner}/${repo}`)).ok) {
          return {
            status: "not-found",
            where,
            httpStatus: 404,
            message: `${owner}/${repo} has no environment named ${environment}. Create it in the repository settings, or leave the field empty for repository secrets.`,
          };
        }
        return {
          status: "not-found",
          where,
          httpStatus: 404,
          message: `GitHub cannot find ${owner}/${repo} with this token. Check the name, and that the token's repository access includes it.`,
        };
      }
      return refused(key, where);
    } catch (err) {
      return unreachable("api.github.com", err, where);
    }
  },
};
