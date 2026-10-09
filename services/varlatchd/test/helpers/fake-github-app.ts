// SPDX-License-Identifier: AGPL-3.0-or-later
import { createPublicKey, generateKeyPairSync, verify, type KeyObject } from "node:crypto";

/**
 * GitHub's App side as a fetch stub (ADR-0047), as GitHub documents it and
 * as the real-GitHub check saw it: an App JWT is RS256, issued as the
 * client id or the App id, verified against the App's current keys, and
 * judged by time at GitHub's clock (iat in the past, exp in the future and
 * at most 10 minutes ahead), with a Date header on every answer. A key
 * deleted on GitHub answers 401 "A JSON web token could not be decoded";
 * a bad time, 401 "Bad credentials".
 */

export interface FakeApp {
  id: number;
  slug: string;
  clientId: string;
  owner: { login: string; id: number; type: "Organization" | "User" };
  permissions: Record<string, string>;
  keys: KeyObject[];
}

export interface FakeInstallation {
  id: number;
  appId: number;
  account: { login: string; id: number; type: "Organization" | "User" };
  repositorySelection: "all" | "selected";
  suspendedAt: string | null;
}

export function fakeGitHubApps() {
  const apps = new Map<number, FakeApp>();
  const installations = new Map<number, FakeInstallation>();
  const calls: { method: string; path: string; issuer?: string }[] = [];
  const state = { clockOffsetMs: 0, sendDate: true };
  let nextInstallation = 169698431;

  const githubNow = () => Date.now() + state.clockOffsetMs;
  const answer = (status: number, body: unknown) =>
    Response.json(body, { status, headers: state.sendDate ? { date: new Date(githubNow()).toUTCString() } : {} });

  function appFromJwt(authorization: string | null): FakeApp | Response {
    const jwt = authorization?.match(/^Bearer (.+)$/)?.[1];
    const parts = jwt?.split(".");
    if (!parts || parts.length !== 3) return answer(401, { message: "A JSON web token could not be decoded" });
    let header: { alg?: string };
    let payload: { iat?: number; exp?: number; iss?: string | number };
    try {
      header = JSON.parse(Buffer.from(parts[0]!, "base64url").toString("utf8"));
      payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8"));
    } catch {
      return answer(401, { message: "A JSON web token could not be decoded" });
    }
    if (header.alg !== "RS256") return answer(401, { message: "A JSON web token could not be decoded" });
    const app = [...apps.values()].find((a) => a.clientId === payload.iss || String(a.id) === String(payload.iss));
    const signed = Buffer.from(`${parts[0]}.${parts[1]}`);
    const signature = Buffer.from(parts[2]!, "base64url");
    if (!app || !app.keys.some((key) => verify("RSA-SHA256", signed, key, signature))) {
      return answer(401, { message: "A JSON web token could not be decoded" });
    }
    const at = Math.floor(githubNow() / 1000);
    if (typeof payload.iat !== "number" || typeof payload.exp !== "number" || payload.iat > at || payload.exp <= at || payload.exp > at + 600) {
      return answer(401, { message: "Bad credentials" });
    }
    return app;
  }

  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    calls.push({ method, path: `${url.pathname}${url.search}` });
    if (url.origin !== "https://api.github.com") return answer(404, { message: "Not Found" });
    const authorization = new Headers(init?.headers).get("authorization");

    if (url.pathname === "/app" || url.pathname.startsWith("/app/")) {
      try {
        const payload = JSON.parse(Buffer.from(authorization?.split(" ")[1]?.split(".")[1] ?? "", "base64url").toString("utf8"));
        calls[calls.length - 1]!.issuer = String(payload.iss);
      } catch {
        // not a JWT: recorded without an issuer
      }
      const app = appFromJwt(authorization);
      if (app instanceof Response) return app;
      if (url.pathname === "/app" && method === "GET") {
        return answer(200, { id: app.id, slug: app.slug, client_id: app.clientId, owner: app.owner, name: app.slug, permissions: app.permissions, events: [] });
      }
      if (url.pathname === "/app/installations" && method === "GET") {
        const perPage = Math.min(Number(url.searchParams.get("per_page") ?? 30), 100);
        const page = Number(url.searchParams.get("page") ?? 1);
        const all = [...installations.values()].filter((i) => i.appId === app.id);
        return answer(
          200,
          all.slice((page - 1) * perPage, page * perPage).map((i) => ({
            id: i.id,
            app_id: i.appId,
            account: i.account,
            target_type: i.account.type,
            repository_selection: i.repositorySelection,
            suspended_at: i.suspendedAt,
          })),
        );
      }
    }
    return answer(404, { message: "Not Found" });
  }) as typeof fetch;

  return {
    fetchImpl,
    calls,
    state,
    /** An App registered on GitHub; returns its first private key. */
    addApp(app: Omit<FakeApp, "keys">): string {
      const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
      apps.set(app.id, { ...app, keys: [publicKey] });
      return privateKey.export({ type: "pkcs1", format: "pem" }) as string;
    },
    /** The owner generated another key on GitHub. */
    addKey(appId: number): string {
      const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
      apps.get(appId)!.keys.push(publicKey);
      return privateKey.export({ type: "pkcs1", format: "pem" }) as string;
    },
    /** The owner deleted a key on GitHub. */
    deleteKey(appId: number, pem: string) {
      const app = apps.get(appId)!;
      const der = createPublicKey(pem).export({ type: "spki", format: "der" });
      app.keys = app.keys.filter((k) => !k.export({ type: "spki", format: "der" }).equals(der));
    },
    install(appId: number, account: FakeInstallation["account"], repositorySelection: "all" | "selected" = "selected", suspendedAt: string | null = null): number {
      const id = nextInstallation++;
      installations.set(id, { id, appId, account, repositorySelection, suspendedAt });
      return id;
    },
    app: (id: number) => apps.get(id),
  };
}
