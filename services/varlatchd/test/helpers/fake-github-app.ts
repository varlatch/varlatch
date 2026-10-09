// SPDX-License-Identifier: AGPL-3.0-or-later
import { createPublicKey, generateKeyPairSync, randomBytes, verify, type KeyObject } from "node:crypto";
import { sealedBoxOpen } from "@varlatch/sync";

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

export interface FakeRepo {
  name: string;
  private: boolean;
  archived?: boolean;
  environments?: string[];
}

export interface FakeInstallation {
  id: number;
  appId: number;
  account: { login: string; id: number; type: "Organization" | "User" };
  repositorySelection: "all" | "selected";
  suspendedAt: string | null;
  repos: FakeRepo[];
}

interface FakeToken {
  installationId: number;
  /** Lower-case names, or null for the whole installation. */
  repos: string[] | null;
  permissions: Record<string, string>;
}

/** An X25519 keypair as raw bytes, the shape GitHub's repository public key has. */
function boxKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  return {
    publicKey: new Uint8Array(Buffer.from(publicKey.export({ format: "jwk" }).x!, "base64url")),
    secretKey: new Uint8Array(Buffer.from(privateKey.export({ format: "jwk" }).d!, "base64url")),
  };
}

export function fakeGitHubApps() {
  const apps = new Map<number, FakeApp>();
  const installations = new Map<number, FakeInstallation>();
  const calls: { method: string; path: string; issuer?: string }[] = [];
  const state = { clockOffsetMs: 0, sendDate: true, sendExpiryHeader: true };
  let nextInstallation = 169698431;
  const tokens = new Map<string, FakeToken>();
  /** Every token minted: what was asked for (for narrowing assertions). */
  const mints: { installationId: number; repositories: string[] | null; permissions: Record<string, string> }[] = [];
  /** Repositories on an account outside every installation. */
  const accountRepos = new Map<string, FakeRepo>();
  const keys = new Map<string, ReturnType<typeof boxKeyPair>>();
  const secrets = new Map<string, Uint8Array>();
  const keyOf = (place: string) => keys.get(place) ?? (keys.set(place, boxKeyPair()), keys.get(place)!);
  const LEVELS = ["read", "write", "admin"];
  const allows = (granted: string | undefined, needed: string) => granted !== undefined && LEVELS.indexOf(granted) >= LEVELS.indexOf(needed);

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
      let m = url.pathname.match(/^\/app\/installations\/(\d+)$/);
      if (m && method === "GET") {
        const installation = installations.get(Number(m[1]));
        if (!installation || installation.appId !== app.id) return answer(404, { message: "Not Found" });
        return answer(200, {
          id: installation.id,
          app_id: installation.appId,
          account: installation.account,
          target_type: installation.account.type,
          repository_selection: installation.repositorySelection,
          suspended_at: installation.suspendedAt,
        });
      }
      m = url.pathname.match(/^\/app\/installations\/(\d+)\/access_tokens$/);
      if (m && method === "POST") {
        const installation = installations.get(Number(m[1]));
        if (!installation || installation.appId !== app.id) return answer(404, { message: "Not Found" });
        if (installation.suspendedAt) return answer(403, { message: "This installation has been suspended" });
        const asked = JSON.parse(String(init?.body ?? "{}")) as { repositories?: string[]; permissions?: Record<string, string> };
        const permissions = asked.permissions ?? app.permissions;
        for (const [name, level] of Object.entries(permissions)) {
          if (!allows(app.permissions[name], level)) return answer(422, { message: "The permissions requested are not granted to this installation." });
        }
        let repos: string[] | null = null;
        if (asked.repositories) {
          for (const name of asked.repositories) {
            if (!installation.repos.some((r) => r.name.toLowerCase() === name.toLowerCase())) {
              return answer(422, { message: "There is at least one repository that does not exist or is not accessible to the parent installation." });
            }
          }
          repos = asked.repositories.map((n) => n.toLowerCase());
        }
        const token = `ghs_${randomBytes(18).toString("base64url")}`;
        tokens.set(token, { installationId: installation.id, repos, permissions });
        mints.push({ installationId: installation.id, repositories: repos, permissions });
        return answer(201, {
          token,
          expires_at: new Date(githubNow() + 3600_000).toISOString(),
          permissions,
          repository_selection: repos ? "selected" : installation.repositorySelection,
          ...(repos ? { repositories: installation.repos.filter((r) => repos!.includes(r.name.toLowerCase())).map((r) => ({ name: r.name })) } : {}),
        });
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

    // Installation-token endpoints.
    const bearer = authorization?.match(/^(?:Bearer|token) (ghs_.+)$/)?.[1];
    const entry = bearer ? tokens.get(bearer) : undefined;
    if (!entry) return answer(401, { message: "Bad credentials" });
    const installation = installations.get(entry.installationId)!;
    const tokenAnswer = (status: number, body?: unknown) =>
      body === undefined
        ? new Response(null, { status, headers: { ...(state.sendDate ? { date: new Date(githubNow()).toUTCString() } : {}), ...(state.sendExpiryHeader ? { "github-authentication-token-expiration": "2026-11-08 09:30:00 UTC" } : {}) } })
        : Response.json(body, { status, headers: { ...(state.sendDate ? { date: new Date(githubNow()).toUTCString() } : {}), ...(state.sendExpiryHeader ? { "github-authentication-token-expiration": "2026-11-08 09:30:00 UTC" } : {}) } });
    const owner = installation.account.login.toLowerCase();
    const visible = (o: string, repo: string) =>
      o.toLowerCase() === owner
        ? installation.repos.find((r) => r.name.toLowerCase() === repo.toLowerCase() && (entry.repos === null || entry.repos.includes(r.name.toLowerCase())))
        : undefined;

    if (url.pathname === "/installation/repositories" && method === "GET") {
      const perPage = Math.min(Number(url.searchParams.get("per_page") ?? 30), 100);
      const page = Number(url.searchParams.get("page") ?? 1);
      const all = installation.repos.filter((r) => entry.repos === null || entry.repos.includes(r.name.toLowerCase()));
      return tokenAnswer(200, {
        total_count: all.length,
        repository_selection: installation.repositorySelection,
        repositories: all.slice((page - 1) * perPage, page * perPage).map((r) => ({
          name: r.name,
          full_name: `${installation.account.login}/${r.name}`,
          owner: { login: installation.account.login },
          private: r.private,
          archived: r.archived ?? false,
        })),
      });
    }
    let m = url.pathname.match(/^\/users\/([^/]+)$/);
    if (m && method === "GET") return tokenAnswer(200, { login: installation.account.login, type: installation.account.type });
    m = url.pathname.match(/^\/repos\/([^/]+)\/([^/]+)$/);
    if (m && method === "GET") {
      const repo = visible(m[1]!, m[2]!) ?? (accountRepos.get(`${m[1]}/${m[2]}`.toLowerCase())?.private === false ? accountRepos.get(`${m[1]}/${m[2]}`.toLowerCase()) : undefined);
      return repo
        ? tokenAnswer(200, { name: repo.name, full_name: `${m[1]}/${repo.name}`, private: repo.private, archived: repo.archived ?? false })
        : tokenAnswer(404, { message: "Not Found" });
    }
    m = url.pathname.match(/^\/repos\/([^/]+)\/([^/]+)(?:\/environments\/([^/]+))?\/(?:actions\/)?secrets\/([^/]+)$/);
    if (m) {
      const [, o, r, env, last] = m;
      const repo = visible(o!, r!);
      if (!repo) return tokenAnswer(404, { message: "Not Found" });
      if (env !== undefined && !(repo.environments ?? ["production"]).includes(decodeURIComponent(env))) return tokenAnswer(404, { message: "Not Found" });
      const permission = env !== undefined ? "environments" : "secrets";
      const place = `${owner}/${repo.name.toLowerCase()}/${env ?? ""}`;
      if (last === "public-key" && method === "GET") {
        if (!allows(entry.permissions[permission], "read")) return tokenAnswer(403, { message: "Resource not accessible by integration" });
        return tokenAnswer(200, { key_id: `key-${place}`, key: Buffer.from(keyOf(place).publicKey).toString("base64") });
      }
      if (!allows(entry.permissions[permission], "write")) return tokenAnswer(403, { message: "Resource not accessible by integration" });
      if (method === "PUT") {
        const body = JSON.parse(String(init?.body ?? "{}")) as { encrypted_value: string };
        secrets.set(`${place}/${decodeURIComponent(last!)}`, new Uint8Array(Buffer.from(body.encrypted_value, "base64")));
        return tokenAnswer(201);
      }
      if (method === "DELETE") {
        secrets.delete(`${place}/${decodeURIComponent(last!)}`);
        return tokenAnswer(204);
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
    install(
      appId: number,
      account: FakeInstallation["account"],
      repositorySelection: "all" | "selected" = "selected",
      suspendedAt: string | null = null,
      repos: FakeRepo[] = [],
    ): number {
      const id = nextInstallation++;
      installations.set(id, { id, appId, account, repositorySelection, suspendedAt, repos });
      return id;
    },
    installation: (id: number) => installations.get(id),
    /** A repository on an account, outside every installation. */
    createRepository(owner: string, repo: FakeRepo) {
      accountRepos.set(`${owner}/${repo.name}`.toLowerCase(), repo);
    },
    mints,
    /** A secret as written, decrypted with the repository's key: undefined when absent. */
    secret(owner: string, repo: string, environment: string | undefined, name: string): string | undefined {
      const place = `${owner.toLowerCase()}/${repo.toLowerCase()}/${environment ?? ""}`;
      const sealed = secrets.get(`${place}/${name}`);
      if (!sealed) return undefined;
      const key = keyOf(place);
      return Buffer.from(sealedBoxOpen(sealed, key.publicKey, key.secretKey)!).toString("utf8");
    },
    app: (id: number) => apps.get(id),
  };
}
