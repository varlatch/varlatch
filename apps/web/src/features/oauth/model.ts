// SPDX-License-Identifier: AGPL-3.0-or-later
import type { OAuthConnection, OAuthItem, OAuthProviderInput, OAuthStatus } from "@varlatch/protocol";

/** What the pages make of an OAuth connection (ADR-0062). No React, no network, and nothing here ever holds a token. */

export const CAPABILITY = "oauth.connections";

export const PRESETS = [
  { value: "google", label: "Google" },
  { value: "microsoft", label: "Microsoft" },
  { value: "generic", label: "Another provider" },
] as const;
export type Preset = (typeof PRESETS)[number]["value"];

/** What the form holds; the client secret is sent once and kept nowhere. */
export interface FormState {
  preset: Preset;
  tenant: string;
  issuer: string;
  /** Endpoints instead of an issuer. */
  byEndpoints: boolean;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  revocationEndpoint: string;
  userinfoEndpoint: string;
  grant: "authorization_code" | "client_credentials";
  clientId: string;
  clientSecret: string;
  scopes: string;
  hosts: string;
  /** The other hosts of the provider's that the person said are its own. */
  confirmedHosts: string[];
}

export const emptyForm: FormState = {
  preset: "google",
  tenant: "",
  issuer: "",
  byEndpoints: false,
  authorizationEndpoint: "",
  tokenEndpoint: "",
  revocationEndpoint: "",
  userinfoEndpoint: "",
  grant: "authorization_code",
  clientId: "",
  clientSecret: "",
  scopes: "",
  hosts: "",
  confirmedHosts: [],
};

const words = (text: string) => text.split(/[\s,]+/).filter(Boolean);

export function providerOf(f: FormState): OAuthProviderInput {
  const none = f.clientSecret === "" ? ({ tokenEndpointAuthMethod: "none" } as const) : {};
  const named = f.grant === "authorization_code" && f.confirmedHosts.length > 0 ? { endpointHosts: f.confirmedHosts } : {};
  if (f.preset === "google") return { preset: "google", ...none };
  if (f.preset === "microsoft") return { preset: "microsoft", tenant: f.tenant.trim(), ...none };
  if (!f.byEndpoints) return { preset: "generic", issuer: f.issuer.trim(), ...named, ...none };
  const opt = (k: "authorizationEndpoint" | "revocationEndpoint" | "userinfoEndpoint") => (f[k].trim() ? { [k]: f[k].trim() } : {});
  return {
    preset: "generic",
    tokenEndpoint: f.tokenEndpoint.trim(),
    ...(f.grant === "authorization_code" ? opt("authorizationEndpoint") : {}),
    ...opt("revocationEndpoint"),
    ...(f.grant === "authorization_code" ? opt("userinfoEndpoint") : {}),
    ...named,
    ...none,
  };
}

export function inputOf(f: FormState, item: string) {
  return {
    item,
    provider: providerOf(f),
    grant: f.grant,
    clientId: f.clientId.trim(),
    ...(f.clientSecret ? { clientSecret: f.clientSecret } : {}),
    scopes: words(f.scopes),
    hosts: words(f.hosts),
  };
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Whether the provider's part of the form can be sent. */
export function providerReady(f: FormState): boolean {
  if (f.preset === "google") return f.grant === "authorization_code";
  if (f.preset === "microsoft") return UUID.test(f.tenant.trim());
  if (!f.byEndpoints) return /^https:\/\/\S+$/.test(f.issuer.trim());
  return /^https:\/\/\S+$/.test(f.tokenEndpoint.trim()) && (f.grant !== "authorization_code" || /^https:\/\/\S+$/.test(f.authorizationEndpoint.trim()));
}

/** An https address's host, with its port when that is not 443; null for anything else. */
export function hostOf(url: string): string | null {
  try {
    const u = new URL(url.trim());
    return u.protocol === "https:" && u.host !== "" && u.username === "" && u.password === "" ? u.host : null;
  } catch {
    return null;
  }
}

/** The presets' hosts, as the server has them. */
const PRESET_HOSTS = {
  google: ["oauth2.googleapis.com", "accounts.google.com", "openidconnect.googleapis.com", "www.googleapis.com"],
  microsoft: ["login.microsoftonline.com", "graph.microsoft.com"],
} as const;

/**
 * Every host the client secret, a code or a token goes to, or the browser,
 * the token endpoint's first: what is shown before a secret is typed. Null
 * while it is not known: an issuer is asked first (discovered).
 */
export function endpointHostsOf(f: FormState, discovered: readonly string[] | null): string[] | null {
  if (f.preset !== "generic") return [...PRESET_HOSTS[f.preset]];
  if (!f.byEndpoints) return discovered ? [...discovered] : null;
  const token = hostOf(f.tokenEndpoint);
  const personal = f.grant === "authorization_code";
  const others = [personal ? f.authorizationEndpoint : "", f.revocationEndpoint, personal ? f.userinfoEndpoint : ""].filter((u) => u.trim() !== "").map(hostOf);
  if (token === null || others.includes(null)) return null;
  return [token, ...[...new Set(others as string[])].filter((h) => h !== token).sort()];
}

/** The ones among them that nobody typed: each is confirmed, or the connection is not made. */
export function unnamedHosts(f: FormState, hosts: readonly string[] | null): string[] {
  if (f.preset !== "generic" || !hosts) return [];
  const given = f.byEndpoints ? hosts[0] : hostOf(f.issuer);
  return hosts.filter((h) => h !== given);
}

/** The redirect URI to register: the token endpoint's host, and a provider's other ones. */
export function redirectFor(f: FormState, redirectBase: string | null | undefined, discovered: readonly string[] | null = null): string | null {
  if (!redirectBase || f.grant !== "authorization_code") return null;
  const hosts = endpointHostsOf(f, discovered);
  if (!hosts) return null;
  return redirectBase + (f.preset === "generic" ? hosts : hosts.slice(0, 1)).map((h) => encodeURIComponent(h).replace(/%3A/g, ":")).join("~");
}

type Tone = "ok" | "warn" | "error" | "muted" | "live";

export const STATUS: Record<OAuthStatus, { label: string; tone: Tone }> = {
  not_connected: { label: "Not connected", tone: "muted" },
  connected: { label: "Connected", tone: "ok" },
  refreshing: { label: "Refreshing", tone: "live" },
  failing: { label: "Failing, tried again", tone: "warn" },
  needs_reconnect: { label: "Needs to be connected again", tone: "error" },
  revoked: { label: "Disconnected", tone: "muted" },
};

export function statusOf(c: Pick<OAuthItem, "status" | "paused">): { label: string; tone: Tone } {
  if (c.paused) return { label: "Paused", tone: "warn" };
  return STATUS[c.status] ?? { label: c.status, tone: "muted" };
}

const REASONS: Record<string, string> = {
  "refused-by-provider": "The provider refuses the refresh token: consent was withdrawn there, or the token was used elsewhere or expired.",
  "refresh-answer-lost": "The provider's answer to a refresh was lost, and it refuses the refresh token that was used for it.",
  "no-refresh-token": "The provider gave no refresh token, and the access token ended.",
  "account-mismatch": "The provider answered for another account.",
  "outbound-refused": "This installation's outbound policy refuses the provider's endpoint.",
  unreachable: "The provider could not be reached.",
  timeout: "The provider did not answer in time.",
  "server-error": "The provider answered with a server error.",
  "rate-limited": "The provider asks to wait.",
  invalid_client: "The provider does not accept the client ID and secret.",
};

export function reasonText(reason: string | null): string | null {
  if (!reason) return null;
  return REASONS[reason] ?? `The provider's answer was not usable (${reason}).`;
}

/** "alice@example.com", or what kind it is: shown where an item's value would be. */
export function connectionLabel(c: OAuthItem | undefined): string | null {
  if (!c) return null;
  return [c.account ?? "", statusOf(c).label.toLowerCase()].filter(Boolean).join(" · ");
}

/** What connecting it does to the account: whether a change has to be confirmed. */
export function knownAccount(c: OAuthConnection): string | null {
  return c.account?.label ?? null;
}

// ---------------------------------------------------------------------------
// Across the provider: where to come back to. Nothing secret: the state is in
// the address the browser is sent to anyway.

export interface Pending {
  org: string;
  project: string;
  env: string;
  item: string;
}
const key = (state: string) => `varlatch.oauth.${state}`;

export function remember(state: string, pending: Pending, storage: Pick<Storage, "setItem"> = sessionStorage): void {
  storage.setItem(key(state), JSON.stringify(pending));
}

/** Once: a page loaded again does not begin again. */
export function recall(state: string, storage: Pick<Storage, "getItem" | "removeItem"> = sessionStorage): Pending | null {
  const raw = storage.getItem(key(state));
  storage.removeItem(key(state));
  if (!raw) return null;
  try {
    const p = JSON.parse(raw) as Pending;
    return typeof p.org === "string" && typeof p.project === "string" && typeof p.env === "string" && typeof p.item === "string" ? p : null;
  } catch {
    return null;
  }
}

/** Only an https address is gone to. */
export function safeToOpen(url: string): boolean {
  try {
    return new URL(url).protocol === "https:";
  } catch {
    return false;
  }
}
