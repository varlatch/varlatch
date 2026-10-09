// SPDX-License-Identifier: AGPL-3.0-or-later
import type { AccessCheck } from "@varlatch/sync";
import type { Envelope } from "../crypto/aead.js";
import { decryptGitHubAppKey } from "../crypto/hierarchy.js";
import type { AppCtx } from "./ctx.js";
import { GITHUB_API, GITHUB_HEADERS, GITHUB_TIMEOUT_MS, GITHUB_UNREACHABLE, NOT_GITHUB, appRequest, readJwtRefusal } from "./githubjwt.js";
import { orgKekOf, type OrgRow } from "./orgs.js";

/**
 * Installation tokens for App Connections (ADR-0047 Decision 3): one hour,
 * minted per use, narrowed to what the use needs, never stored, and handled
 * as opaque strings.
 *
 * | Use               | Repositories    | Permissions                                       |
 * |-------------------|-----------------|---------------------------------------------------|
 * | push              | the destination | secrets (environments) write, metadata read       |
 * | destination-check | the destination | secrets (environments) read, metadata read        |
 * | connection-check  | the installation| metadata read                                     |
 * | listing           | the installation| metadata read                                     |
 *
 * Nothing here throws (finding F of the spike): no answer from GitHub is a
 * result like any other.
 */

export type MintUse = "push" | "destination-check" | "connection-check" | "listing";

/** What an App Connection mints with: its App's identifiers and key, and its installation. */
export interface AppCredential {
  githubAppId: number;
  clientId: string;
  privateKeyPem: string;
  installationId: number;
  /** The installation's account: the Connection's base identity. */
  owner: string;
}

export type Minted = { ok: true; token: string } | { ok: false; check: AccessCheck };

/** Pages of the installation's list read to establish membership: 3,000 repositories. */
const MAX_MEMBERSHIP_PAGES = 30;

export function narrowing(use: MintUse, destination: Record<string, string> = {}): { repositories?: string[]; permissions: Record<string, string> } {
  const scoped = destination.environment ? "environments" : "secrets";
  switch (use) {
    case "push":
      return { repositories: [destination.repo!], permissions: { [scoped]: "write", metadata: "read" } };
    case "destination-check":
      return { repositories: [destination.repo!], permissions: { [scoped]: "read", metadata: "read" } };
    case "connection-check":
    case "listing":
      return { permissions: { metadata: "read" } };
  }
}

/** The App Credential of a Connection's App, from its stored row; null when the App is gone. */
export function appCredentialFrom(
  ctx: AppCtx,
  org: OrgRow,
  row: {
    app_row_id: string | null;
    app_github_id: string | number | null;
    app_client_id: string | null;
    app_key_envelope: Envelope | string | null;
    app_removed_at: string | Date | null;
    github_installation_id: string | number | null;
    base_identity: string;
  },
): AppCredential | null {
  if (!row.app_row_id || row.app_removed_at || !row.app_key_envelope || row.app_github_id === null || !row.app_client_id || row.github_installation_id === null) {
    return null;
  }
  const envelope = typeof row.app_key_envelope === "string" ? (JSON.parse(row.app_key_envelope) as Envelope) : row.app_key_envelope;
  return {
    githubAppId: Number(row.app_github_id),
    clientId: row.app_client_id,
    privateKeyPem: decryptGitHubAppKey(orgKekOf(ctx, org), org.id, row.app_row_id, envelope),
    installationId: Number(row.github_installation_id),
    owner: row.base_identity,
  };
}

export const APP_REMOVED: AccessCheck = {
  status: "credential-rejected",
  where: "connection",
  message: "This Connection's GitHub App was removed from Varlatch, so Varlatch can no longer act for it.",
};

export async function mintInstallationToken(
  fetchImpl: typeof fetch,
  cred: AppCredential,
  use: MintUse,
  destination: Record<string, string> = {},
  now: number = Date.now(),
): Promise<Minted> {
  const { res, claims } = await appRequest(fetchImpl, `/app/installations/${cred.installationId}/access_tokens`, cred.clientId, cred.privateKeyPem, now, {
    method: "POST",
    body: JSON.stringify(narrowing(use, destination)),
  });
  if (!res) {
    return { ok: false, check: { ...GITHUB_UNREACHABLE, message: "Varlatch could not reach api.github.com to issue a token for the App. Check that this server can reach it, then try again." } };
  }
  if (res.status === 401) return { ok: false, check: readJwtRefusal(res, claims) };
  if (res.status === 404) {
    return {
      ok: false,
      check: {
        status: "credential-rejected",
        where: "connection",
        httpStatus: 404,
        message: `The GitHub App is no longer installed on ${cred.owner}. Install it again on GitHub, or choose another installation.`,
      },
    };
  }
  if (res.status === 422) return { ok: false, check: await explain422(fetchImpl, cred, destination, now) };
  if (!res.ok) {
    return { ok: false, check: { status: "failed", where: "connection", httpStatus: res.status, message: `GitHub refused to issue a token for the App (HTTP ${res.status}).` } };
  }
  const body = (await res.json().catch(() => undefined)) as Record<string, unknown> | undefined;
  // Opaque: no assumption about the token's length or format.
  if (!body || typeof body !== "object" || Array.isArray(body) || typeof body.token !== "string" || body.token.length === 0) {
    return { ok: false, check: NOT_GITHUB(res.status) };
  }
  return { ok: true, token: body.token };
}

/**
 * A 422 at minting has more than one documented cause: a repository
 * outside the installation (or missing), or a permission the App or the
 * installation lacks. 422 alone establishes neither (finding B of the
 * spike, held on real GitHub). The repository is read with an
 * installation-wide metadata token, and every step must be GitHub's own
 * answer: GitHub's 404 places it outside the installation, or nowhere. A
 * 200 does not place it inside, since an App can read any public
 * repository's metadata: membership then comes from the installation's own
 * list, and only a complete list rules it out. Anything else keeps the 422
 * qualified.
 */
async function explain422(fetchImpl: typeof fetch, cred: AppCredential, destination: Record<string, string>, now: number): Promise<AccessCheck> {
  const where = destination.repo ? `${cred.owner}/${destination.repo}` : cred.owner;
  const unclear: AccessCheck = {
    status: "failed",
    where: destination.repo ? "destination" : "connection",
    httpStatus: 422,
    message: destination.repo
      ? `GitHub refused to issue a token for ${where}. The repository may be outside the App's installation, or the App may lack a permission; Varlatch could not tell which.`
      : "GitHub refused to issue a token for the App's installation. The App, or its installation, may lack a permission Varlatch needs.",
  };
  if (!destination.repo) return unclear;
  const metadata = await mintInstallationToken(fetchImpl, cred, "listing", {}, now);
  if (!metadata.ok) return unclear;
  let read: Response;
  try {
    read = await fetchImpl(`${GITHUB_API}/repos/${encodeURIComponent(cred.owner)}/${encodeURIComponent(destination.repo)}`, {
      headers: { ...GITHUB_HEADERS, Authorization: `Bearer ${metadata.token}` },
      redirect: "error",
      signal: AbortSignal.timeout(GITHUB_TIMEOUT_MS),
    });
  } catch {
    return unclear;
  }
  const body = (await read.json().catch(() => undefined)) as Record<string, unknown> | undefined;
  const isRecord = body !== undefined && body !== null && typeof body === "object" && !Array.isArray(body);
  if (read.status === 404 && isRecord && typeof body.message === "string") {
    return {
      status: "not-found",
      where: "destination",
      httpStatus: 422,
      message: `The App's installation cannot see ${where}: it is not among the installation's repositories, or does not exist. Add it in the installation's settings on GitHub.`,
    };
  }
  if (read.status === 200 && isRecord && typeof body.full_name === "string" && body.full_name.toLowerCase() === where.toLowerCase()) {
    const member = await installationIncludes(fetchImpl, metadata.token, where);
    if (member === "yes") {
      return {
        status: "failed",
        where: "connection",
        httpStatus: 422,
        message: `GitHub refused a token for ${where}, though the App's installation includes it. The App, or its installation, may lack a permission Varlatch needs; an organization owner may need to approve the App's permissions on GitHub.`,
      };
    }
    if (member === "no") {
      return {
        status: "not-found",
        where: "destination",
        httpStatus: 422,
        message: `${where} is not among the App installation's repositories. Add it in the installation's settings on GitHub.`,
      };
    }
  }
  return unclear;
}

/**
 * Whether the installation's own list holds the repository: 'yes' as soon
 * as it appears; 'no' only from a complete list (every page GitHub's, the
 * last one short, and as many repositories as total_count says); 'unknown'
 * otherwise, including past the page limit.
 */
async function installationIncludes(fetchImpl: typeof fetch, token: string, where: string): Promise<"yes" | "no" | "unknown"> {
  const target = where.toLowerCase();
  let seen = 0;
  for (let page = 1; page <= MAX_MEMBERSHIP_PAGES; page++) {
    let res: Response;
    try {
      res = await fetchImpl(`${GITHUB_API}/installation/repositories?per_page=100&page=${page}`, {
        headers: { ...GITHUB_HEADERS, Authorization: `Bearer ${token}` },
        redirect: "error",
        signal: AbortSignal.timeout(GITHUB_TIMEOUT_MS),
      });
    } catch {
      return "unknown";
    }
    if (!res.ok) return "unknown";
    const body = (await res.json().catch(() => undefined)) as Record<string, unknown> | undefined;
    if (!body || typeof body !== "object" || Array.isArray(body) || typeof body.total_count !== "number" || !Array.isArray(body.repositories)) {
      return "unknown";
    }
    const repos = body.repositories as unknown[];
    for (const repo of repos) {
      const r = repo as Record<string, unknown> | null;
      if (!r || typeof r !== "object" || typeof r.full_name !== "string") return "unknown";
      if (r.full_name.toLowerCase() === target) return "yes";
    }
    seen += repos.length;
    if (repos.length < 100) return seen === body.total_count ? "no" : "unknown";
  }
  return "unknown";
}

/** The App's view of one installation (Decision 2), signed as the App. */
export async function readInstallation(
  fetchImpl: typeof fetch,
  app: { githubAppId: number; clientId: string; privateKeyPem: string },
  installationId: number,
  now: number = Date.now(),
): Promise<{ ok: true; account: { login: string; type: "organization" | "user" }; suspended: boolean } | { ok: false; check: AccessCheck }> {
  const { res, claims } = await appRequest(fetchImpl, `/app/installations/${installationId}`, app.clientId, app.privateKeyPem, now);
  if (!res) return { ok: false, check: GITHUB_UNREACHABLE };
  if (res.status === 401) return { ok: false, check: readJwtRefusal(res, claims) };
  if (res.status === 404) {
    return { ok: false, check: { status: "not-found", where: "connection", httpStatus: 404, message: `Installation ${installationId} is not an installation of this GitHub App.` } };
  }
  if (!res.ok) {
    return { ok: false, check: { status: "failed", where: "connection", httpStatus: res.status, message: `GitHub refused to read the installation (HTTP ${res.status}).` } };
  }
  const body = (await res.json().catch(() => undefined)) as Record<string, unknown> | undefined;
  const account = body?.account as Record<string, unknown> | undefined;
  if (
    !body || typeof body !== "object" || Array.isArray(body) ||
    body.id !== installationId || body.app_id !== app.githubAppId ||
    !account || typeof account.login !== "string" || !/^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(account.login) ||
    (account.type !== "Organization" && account.type !== "User")
  ) {
    return { ok: false, check: NOT_GITHUB(res.status) };
  }
  return {
    ok: true,
    account: { login: account.login, type: account.type === "Organization" ? "organization" : "user" },
    suspended: body.suspended_at !== null && body.suspended_at !== undefined,
  };
}
