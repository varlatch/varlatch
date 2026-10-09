// SPDX-License-Identifier: AGPL-3.0-or-later
import { createSign } from "node:crypto";
import type { AccessCheck } from "@varlatch/sync";

/**
 * The App's own requests to GitHub (ADR-0047 Decision 3): a JWT signed with
 * the App's private key (RS256), and what a refusal of it establishes.
 */

export const GITHUB_API = "https://api.github.com";
export const GITHUB_TIMEOUT_MS = 10_000;
export const GITHUB_HEADERS = { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "varlatch" };

export interface JwtClaims {
  iat: number;
  exp: number;
}

/** iat 60 s back for clock skew, exp 9 minutes ahead: exp - iat is GitHub's 10-minute limit. */
export function appJwtClaims(now: number): JwtClaims {
  const seconds = Math.floor(now / 1000);
  return { iat: seconds - 60, exp: seconds + 540 };
}

/** `issuer` is the client id, as GitHub recommends, or the App id when only that is known (import). */
export function signAppJwt(issuer: string, privateKeyPem: string, now: number): { jwt: string; claims: JwtClaims } {
  const claims = appJwtClaims(now);
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ ...claims, iss: issuer })).toString("base64url");
  const signature = createSign("RSA-SHA256").update(`${header}.${payload}`).sign(privateKeyPem).toString("base64url");
  return { jwt: `${header}.${payload}.${signature}`, claims };
}

/**
 * A JWT GitHub refused (401), read as only the evidence allows (finding A of
 * the ADR-0047 spike, held on real GitHub): the JWT's own time claims are
 * judged against GitHub's Date header, by GitHub's rules (iat in the past;
 * exp in the future, and at most 10 minutes ahead). Valid at GitHub's time:
 * time was not the reason, so the key is. Invalid: the clock is reason
 * enough, and whether the key is also refused cannot be told yet. No usable
 * Date header: both are named. GitHub's message text is never read.
 */
export function readJwtRefusal(res: Response, claims: JwtClaims): AccessCheck {
  const theirs = Date.parse(res.headers.get("date") ?? "");
  if (Number.isNaN(theirs)) {
    return {
      status: "failed",
      where: "connection",
      httpStatus: res.status,
      message: "GitHub refused the App's signed request. Its key may have been deleted on GitHub, or this server's clock may be off; Varlatch cannot tell which.",
    };
  }
  const at = Math.floor(theirs / 1000);
  if (claims.iat <= at && claims.exp > at && claims.exp <= at + 600) {
    return {
      status: "credential-rejected",
      where: "connection",
      httpStatus: res.status,
      message: "GitHub refused the App's key, though the request was valid at GitHub's time: the key was deleted on GitHub, or belongs to another App.",
    };
  }
  const offMinutes = Math.max(1, Math.round(Math.abs(claims.iat + 60 - at) / 60));
  const direction = claims.iat + 60 > at ? "ahead of" : "behind";
  return {
    status: "failed",
    where: "connection",
    httpStatus: res.status,
    message: `This server's clock is about ${offMinutes} minute${offMinutes === 1 ? "" : "s"} ${direction} GitHub's, which is enough for GitHub to refuse the App's signed requests. Set the clock right, then try again: until then, Varlatch cannot tell whether GitHub also refuses the key.`,
  };
}

/** A request signed as the App. Never throws: no answer is `undefined`. */
export async function appRequest(
  fetchImpl: typeof fetch,
  path: string,
  issuer: string,
  privateKeyPem: string,
  now: number = Date.now(),
  init: { method?: string; body?: string } = {},
): Promise<{ res: Response | undefined; claims: JwtClaims }> {
  const { jwt, claims } = signAppJwt(issuer, privateKeyPem, now);
  try {
    const res = await fetchImpl(`${GITHUB_API}${path}`, {
      method: init.method ?? "GET",
      headers: { ...GITHUB_HEADERS, Authorization: `Bearer ${jwt}`, ...(init.body ? { "Content-Type": "application/json" } : {}) },
      ...(init.body ? { body: init.body } : {}),
      redirect: "error",
      signal: AbortSignal.timeout(GITHUB_TIMEOUT_MS),
    });
    return { res, claims };
  } catch {
    return { res: undefined, claims };
  }
}

export const GITHUB_UNREACHABLE: AccessCheck = {
  status: "unreachable",
  where: "connection",
  message: "Varlatch could not reach api.github.com. Check that this server can reach it, then try again.",
};

export const NOT_GITHUB = (httpStatus: number): AccessCheck => ({
  status: "failed",
  where: "connection",
  httpStatus,
  message: "The answer from api.github.com was not GitHub's. A proxy between this server and GitHub may be in the way.",
});
