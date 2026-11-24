// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Environment, OAuthConnection } from "@varlatch/protocol";
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("window", globalThis);
});
const api = {
  listOAuthConnections: vi.fn(),
  createOAuthConnection: vi.fn(),
  discoverOAuthProvider: vi.fn(),
  getOAuthConnection: vi.fn(),
  updateOAuthConnection: vi.fn(),
  startOAuthAuthorization: vi.fn(),
  completeOAuthAuthorization: vi.fn(),
  refreshOAuthConnection: vi.fn(),
  disconnectOAuthConnection: vi.fn(),
  effectiveConfiguration: vi.fn(),
  discloseSecrets: vi.fn(),
};
const confirm = vi.fn();
const toast = { success: vi.fn(), error: vi.fn() };
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api, authEpoch: 0, accessEpoch: 0 }) }));
vi.mock("../src/shell/Shell", () => ({ errorMessage: (err: unknown) => (err instanceof Error ? err.message : String(err)) }));
vi.mock("../src/components/Toast", () => ({ useToast: () => toast }));
vi.mock("../src/components/CodeBlock", () => ({ CopyButton: () => null }));
vi.mock("../src/lib/tailnetConnection", async (original) => ({
  ...(await original<object>()),
  useTailnetConnection: () => ({ connection: { status: "idle" }, client: null }),
}));
vi.mock("../src/components/Dialog", () => ({
  useConfirm: () => confirm,
  Dialog: ({ open, children, footer }: { open: boolean; children: React.ReactNode; footer: React.ReactNode }) =>
    open ? (
      <div>
        {children}
        {footer}
      </div>
    ) : null,
}));
vi.mock("react-router-dom", () => ({ Link: ({ to, children, ...p }: { to: string; children: React.ReactNode }) => <a href={to} {...p}>{children}</a> }));
import { describeEvent, emptyResolver, segmentsText } from "../src/features/audit/describe";
import { takeArrival, takeFromAddress } from "../src/features/oauth/arrival";
import { OAuthCallbackPage } from "../src/features/oauth/OAuthCallbackPage";
import { OAuthDialog } from "../src/features/oauth/OAuthDialog";
import { OAuthPanel } from "../src/features/oauth/OAuthPanel";
import { connectionLabel, emptyForm, endpointHostsOf, hostOf, unnamedHosts, inputOf, providerOf, providerReady, reasonText, recall, redirectFor, remember, safeToOpen, statusOf } from "../src/features/oauth/model";
import { useExport } from "../src/features/values/useExport";

/** OAuth connections (ADR-0062): made and connected here, and nothing here ever holds a token. */

const base = "https://varlatch.example/oauth/callback/";
const connection: OAuthConnection = {
  item: "MAIL_TOKEN",
  environmentId: "env_1",
  versionId: "ver_1",
  provider: { preset: "generic", tokenEndpoint: "https://idp.example/token", endpointHosts: ["idp.example", "api.idp.example"], tokenEndpointAuthMethod: "client_secret_basic" },
  grant: "authorization_code",
  clientId: "client-1",
  hasClientSecret: true,
  scopes: ["openid", "mail.read"],
  hosts: ["api.example.com:443"],
  status: "connected",
  reason: null,
  paused: false,
  account: { id: "sub-alice", label: "alice@example.com" },
  grantedScopes: ["openid"],
  missingScopes: ["mail.read"],
  hasRefreshToken: true,
  accessTokenExpiresAt: "2099-01-01T00:00:00.000Z",
  refreshTokenExpiresAt: null,
  connectedBy: "idn_1",
  connectedAt: "2026-11-24T00:00:00.000Z",
  refreshedAt: "2026-11-24T00:00:00.000Z",
  retryAt: null,
  createdBy: "idn_1",
  createdAt: "2026-11-24T00:00:00.000Z",
  redirectUri: `${base}idp.example`,
};

let root: ReactTestRenderer | undefined;
const flush = () => act(async () => void (await new Promise((r) => setTimeout(r, 0))));
const render = async (node: React.ReactElement) => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
  });
  await flush();
  await flush();
};
const all = (id: string) => root!.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const one = (id: string) => all(id)[0]!;
const text = (node: ReactTestInstance): string => node.children.map((c) => (typeof c === "string" ? c : text(c))).join("");
const page = () => JSON.stringify(root!.toJSON());
const type = (id: string, value: string) => act(async () => one(id).props.onChange({ target: { value } }));
const press = async (id: string) => {
  await act(async () => one(id).props.onClick());
  await flush();
};
const stored = new Map<string, string>();
const storage = { getItem: (k: string) => stored.get(k) ?? null, setItem: (k: string, v: string) => void stored.set(k, v), removeItem: (k: string) => void stored.delete(k) };

beforeEach(() => {
  for (const f of [...Object.values(api), confirm, toast.success, toast.error]) f.mockReset();
  stored.clear();
  vi.stubGlobal("sessionStorage", storage);
});
afterEach(async () => {
  if (root) await act(async () => root!.unmount());
  root = undefined;
  vi.unstubAllGlobals();
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("window", globalThis);
});

describe("the model", () => {
  it("makes what is sent", () => {
    const f = { ...emptyForm, clientId: " c ", clientSecret: "s", scopes: "a, b\n c", hosts: "x.example y.example" };
    expect(inputOf(f, "X")).toEqual({ item: "X", provider: { preset: "google" }, grant: "authorization_code", clientId: "c", clientSecret: "s", scopes: ["a", "b", "c"], hosts: ["x.example", "y.example"] });
    expect(inputOf({ ...f, clientSecret: "" }, "X")).not.toHaveProperty("clientSecret");
    expect(providerOf({ ...f, clientSecret: "" })).toEqual({ preset: "google", tokenEndpointAuthMethod: "none" });
    expect(providerOf({ ...f, preset: "generic", issuer: "https://i.example " })).toEqual({ preset: "generic", issuer: "https://i.example" });
    expect(
      providerOf({ ...f, preset: "generic", byEndpoints: true, grant: "client_credentials", authorizationEndpoint: "https://a", tokenEndpoint: "https://t", userinfoEndpoint: "https://u", revocationEndpoint: "https://r" }),
    ).toEqual({ preset: "generic", tokenEndpoint: "https://t", revocationEndpoint: "https://r" });
  });

  it("asks for a tenant, not for common", () => {
    const f = { ...emptyForm, preset: "microsoft" as const };
    expect(providerReady({ ...f, tenant: "common" })).toBe(false);
    expect(providerReady({ ...f, tenant: "9188040d-6c67-4c5b-b112-36a304b66dad" })).toBe(true);
    expect(providerReady({ ...emptyForm, preset: "generic", issuer: "http://i.example" })).toBe(false);
    expect(providerReady({ ...emptyForm, preset: "generic", byEndpoints: true, tokenEndpoint: "https://t.example/t" })).toBe(false);
  });

  it("knows the redirect URI of a provider whose token endpoint it knows", () => {
    expect(redirectFor(emptyForm, base)).toBe(`${base}oauth2.googleapis.com`);
    expect(redirectFor({ ...emptyForm, preset: "microsoft" }, base)).toBe(`${base}login.microsoftonline.com`);
    expect(redirectFor({ ...emptyForm, preset: "generic", issuer: "https://i.example" }, base)).toBeNull();
    expect(redirectFor({ ...emptyForm, preset: "generic", byEndpoints: true, tokenEndpoint: "https://T.example:8443/x" }, base)).toBe(`${base}t.example:8443`);
    expect(redirectFor({ ...emptyForm, preset: "generic", byEndpoints: true, tokenEndpoint: "http://t.example" }, base)).toBeNull();
    expect(redirectFor(emptyForm, null)).toBeNull();
    // With every host of a provider's that has several.
    expect(redirectFor({ ...emptyForm, preset: "generic", issuer: "https://i.example" }, base, ["t.example", "a.example"])).toBe(`${base}t.example~a.example`);
    expect(
      redirectFor({ ...emptyForm, preset: "generic", byEndpoints: true, tokenEndpoint: "https://t.example/x", authorizationEndpoint: "https://z.example", userinfoEndpoint: "https://a.example/me", revocationEndpoint: "https://t.example/r" }, base),
    ).toBe(`${base}t.example~a.example~z.example`);
  });

  it("knows every host before a secret is typed, and which nobody typed", () => {
    const f = { ...emptyForm, preset: "generic" as const };
    expect(endpointHostsOf(emptyForm, null)![0]).toBe("oauth2.googleapis.com");
    expect(unnamedHosts(emptyForm, endpointHostsOf(emptyForm, null))).toEqual([]);
    expect(endpointHostsOf({ ...f, issuer: "https://i.example" }, null)).toBeNull();
    expect(unnamedHosts({ ...f, issuer: "https://i.example" }, ["t.example", "i.example"])).toEqual(["t.example"]);
    const by = { ...f, byEndpoints: true, tokenEndpoint: "https://T.example:443/t", authorizationEndpoint: "https://t.example/a", revocationEndpoint: "https://evil.example/r" };
    expect(endpointHostsOf(by, null)).toEqual(["t.example", "evil.example"]);
    expect(unnamedHosts(by, endpointHostsOf(by, null))).toEqual(["evil.example"]);
    expect(endpointHostsOf({ ...by, revocationEndpoint: "http://t.example" }, null)).toBeNull();
    expect(providerOf({ ...by, confirmedHosts: ["evil.example"], clientSecret: "x" })).toHaveProperty("endpointHosts", ["evil.example"]);
    expect(providerOf({ ...by, confirmedHosts: ["evil.example"], clientSecret: "x", grant: "client_credentials" })).not.toHaveProperty("endpointHosts");
    expect(hostOf("https://user:pw@t.example")).toBeNull();
  });

  it("names states and reasons in words", () => {
    expect(connectionLabel({ preset: "google", grant: "authorization_code", status: "needs_reconnect", paused: false, account: "a@b" })).toBe("a@b · needs to be connected again");
    expect(statusOf({ status: "connected", paused: true }).label).toBe("Paused");
    expect(reasonText("refresh-answer-lost")).toContain("lost");
    expect(reasonText("made_up")).toContain("made_up");
    expect(reasonText(null)).toBeNull();
  });

  it("remembers where to come back to, once", () => {
    remember("s1", { org: "o", project: "p", env: "e", item: "I" });
    expect(recall("s1")).toEqual({ org: "o", project: "p", env: "e", item: "I" });
    expect(recall("s1")).toBeNull();
    stored.set("varlatch.oauth.s2", "{}");
    expect(recall("s2")).toBeNull();
    stored.set("varlatch.oauth.s3", "nonsense");
    expect(recall("s3")).toBeNull();
  });

  it("goes to https only", () => {
    expect(safeToOpen("https://idp.example/x")).toBe(true);
    for (const bad of ["http://idp.example", "javascript:alert(1)", "data:text/html,x", "//x", ""]) expect(safeToOpen(bad)).toBe(false);
  });
});

describe("making one", () => {
  it("sends the secret once and keeps none of it", async () => {
    api.listOAuthConnections.mockResolvedValue({ items: [], nextCursor: null, redirectBase: base });
    api.createOAuthConnection.mockResolvedValue(connection);
    const onSaved = vi.fn(async () => {});
    await render(<OAuthDialog open org="acme" project="api" env="production" exists={(n) => n === "TAKEN"} onClose={() => {}} onSaved={onSaved} />);
    expect(text(one("oauth-redirect"))).toBe(`${base}oauth2.googleapis.com`);
    await type("oauth-name", "mail token");
    await type("oauth-client", "client-1");
    await type("oauth-secret", "made-up-secret");
    await type("oauth-scopes", "https://mail.example/read");
    expect(one("oauth-secret").props.type).toBe("password");
    await press("confirm-oauth");
    expect(api.createOAuthConnection).toHaveBeenCalledWith("acme", "api", "production", {
      item: "MAIL_TOKEN", provider: { preset: "google" }, grant: "authorization_code", clientId: "client-1", clientSecret: "made-up-secret", scopes: ["https://mail.example/read"], hosts: [],
    });
    expect(onSaved).toHaveBeenCalledWith("MAIL_TOKEN");
    expect(page()).not.toContain("made-up-secret");
    await type("oauth-name", "TAKEN");
    expect(one("confirm-oauth").props.disabled).toBe(true);
  });

  it("shows where the secret goes before it can be typed", async () => {
    api.listOAuthConnections.mockResolvedValue({ items: [], nextCursor: null, redirectBase: base });
    api.discoverOAuthProvider.mockResolvedValue({ provider: { ...connection.provider, endpointHosts: ["idp.example", "evil.example"] } });
    api.createOAuthConnection.mockResolvedValue(connection);
    await render(<OAuthDialog open org="acme" project="api" env="production" exists={() => false} onClose={() => {}} onSaved={async () => {}} />);
    expect(one("oauth-secret").props.disabled).toBe(false);
    expect(text(one("oauth-endpoint-hosts"))).toContain("oauth2.googleapis.com");
    await act(async () => root!.root.findAll((n) => n.props["data-testid"] === "oauth-preset" && typeof n.props.onChange === "function")[0]!.props.onChange("generic"));
    expect(one("oauth-secret").props.disabled).toBe(true);
    await type("oauth-name", "MAIL_TOKEN");
    await type("oauth-client", "client-1");
    await type("oauth-issuer", "https://idp.example");
    await press("oauth-discover");
    expect(text(one("oauth-endpoint-hosts"))).toBe("idp.exampleevil.example");
    expect(text(one("oauth-redirect"))).toBe(`${base}idp.example~evil.example`);
    // Nobody typed the other one: it is confirmed first.
    expect(one("oauth-secret").props.disabled).toBe(true);
    const checkbox = () => root!.root.findAll((n) => n.props["data-testid"] === "oauth-confirm-hosts" && typeof n.props.onChange === "function")[0]!;
    await act(async () => checkbox().props.onChange(true));
    expect(one("oauth-secret").props.disabled).toBe(false);
    await type("oauth-secret", "made-up-secret");
    await press("confirm-oauth");
    expect(api.createOAuthConnection.mock.calls[0]![3].provider).toEqual({ preset: "generic", issuer: "https://idp.example", endpointHosts: ["evil.example"] });
  });

  it("takes back the secret and the confirmation with another provider", async () => {
    api.listOAuthConnections.mockResolvedValue({ items: [], nextCursor: null, redirectBase: base });
    await render(<OAuthDialog open org="acme" project="api" env="production" exists={() => false} onClose={() => {}} onSaved={async () => {}} />);
    await type("oauth-secret", "made-up-secret");
    await act(async () => root!.root.findAll((n) => n.props["data-testid"] === "oauth-preset" && typeof n.props.onChange === "function")[0]!.props.onChange("generic"));
    expect(one("oauth-secret").props.value).toBe("");
    expect(one("oauth-secret").props.disabled).toBe(true);
  });

  it("changes one without its provider, and asks for no secret", async () => {
    api.updateOAuthConnection.mockResolvedValue(connection);
    await render(<OAuthDialog open org="acme" project="api" env="production" connection={connection} exists={() => false} onClose={() => {}} onSaved={async () => {}} />);
    expect(all("oauth-preset")).toHaveLength(0);
    expect(text(one("oauth-endpoint-hosts"))).toBe("idp.exampleapi.idp.example");
    await type("oauth-hosts", "api.example.com *.mail.example");
    await press("confirm-oauth");
    expect(api.updateOAuthConnection).toHaveBeenCalledWith("acme", "api", "production", "MAIL_TOKEN", {
      scopes: ["openid", "mail.read"], hosts: ["api.example.com", "*.mail.example"], expectedVersionId: "ver_1",
    });
  });
});

describe("connecting", () => {
  const panel = <OAuthPanel org="acme" project="api" env="production" item="MAIL_TOKEN" own onChanged={() => {}} />;
  const assign = vi.fn();
  beforeEach(() => {
    assign.mockReset();
    vi.stubGlobal("location", { assign, origin: "https://varlatch.example", pathname: "/", search: "" });
  });

  it("shows whose it is, and goes to the provider", async () => {
    api.getOAuthConnection.mockResolvedValue(connection);
    api.startOAuthAuthorization.mockResolvedValue({ authorizationUrl: "https://idp.example/authorize?x", state: "st", redirectUri: "r", expiresAt: "2099" });
    confirm.mockResolvedValueOnce(false).mockResolvedValue(true);
    await render(panel);
    expect(text(one("oauth-account"))).toBe("alice@example.com");
    expect(text(one("oauth-endpoint-hosts"))).toBe("idp.example api.idp.example");
    expect(text(one("oauth-status"))).toBe("Connected");
    expect(text(one("oauth-missing"))).toContain("mail.read");
    await press("oauth-connect");
    expect(api.startOAuthAuthorization).not.toHaveBeenCalled();
    expect(confirm.mock.calls[0]![0].body).toContain("idp.example, api.idp.example");
    await press("oauth-connect");
    expect(api.startOAuthAuthorization).toHaveBeenCalledWith("acme", "api", "production", "MAIL_TOKEN", { expectedVersionId: "ver_1" });
    expect(assign).toHaveBeenCalledWith("https://idp.example/authorize?x");
    expect(recall("st")).toEqual({ org: "acme", project: "api", env: "production", item: "MAIL_TOKEN" });
  });

  it("asks before another account, and goes nowhere unsafe", async () => {
    api.getOAuthConnection.mockResolvedValue(connection);
    api.startOAuthAuthorization.mockResolvedValue({ authorizationUrl: "javascript:alert(1)", state: "st", redirectUri: "r", expiresAt: "2099" });
    confirm.mockResolvedValue(false);
    await render(panel);
    await press("oauth-another");
    expect(api.startOAuthAuthorization).not.toHaveBeenCalled();
    confirm.mockResolvedValue(true);
    await press("oauth-another");
    expect(api.startOAuthAuthorization).toHaveBeenCalledWith("acme", "api", "production", "MAIL_TOKEN", { confirmAccountChange: true, expectedVersionId: "ver_1" });
    expect(assign).not.toHaveBeenCalled();
    expect(toast.error).toHaveBeenCalled();
  });

  it("says why it needs a person, pauses and disconnects", async () => {
    api.getOAuthConnection.mockResolvedValue({ ...connection, status: "needs_reconnect", reason: "refresh-answer-lost", missingScopes: [] });
    api.updateOAuthConnection.mockResolvedValue(connection);
    api.disconnectOAuthConnection.mockResolvedValue({ atProvider: "failed", connection });
    confirm.mockResolvedValue(true);
    await render(panel);
    expect(text(one("oauth-reason"))).toContain("lost");
    expect(all("oauth-refresh")).toHaveLength(0);
    await press("oauth-pause");
    expect(api.updateOAuthConnection).toHaveBeenCalledWith("acme", "api", "production", "MAIL_TOKEN", { paused: true });
    await press("oauth-disconnect");
    expect(api.disconnectOAuthConnection).toHaveBeenCalledWith("acme", "api", "production", "MAIL_TOKEN");
    expect(toast.success.mock.calls[0]![1].description).toContain("withdraw the consent");
  });

  it("is connected where it is, not where it is inherited", async () => {
    await render(<OAuthPanel org="acme" project="api" env="production/x" item="MAIL_TOKEN" own={false} onChanged={() => {}} />);
    expect(api.getOAuthConnection).not.toHaveBeenCalled();
  });
});

describe("coming back", () => {
  const replaceState = vi.fn();
  const at = (pathname: string, search: string) => {
    vi.stubGlobal("location", { origin: "https://varlatch.example", pathname, search });
    vi.stubGlobal("history", { replaceState });
  };
  beforeEach(() => replaceState.mockReset());

  it("takes the code out of the address, and sends it on once", async () => {
    at("/oauth/callback/idp.example", "?code=c0de&state=st&iss=https%3A%2F%2Fidp.example");
    remember("st", { org: "acme", project: "api", env: "production", item: "MAIL_TOKEN" });
    api.completeOAuthAuthorization.mockResolvedValue({ outcome: "connected", connection });
    await render(<OAuthCallbackPage />);
    expect(replaceState).toHaveBeenCalledWith(null, "", "/oauth/callback/idp.example");
    expect(api.completeOAuthAuthorization).toHaveBeenCalledTimes(1);
    expect(api.completeOAuthAuthorization).toHaveBeenCalledWith("acme", "api", "production", "MAIL_TOKEN", {
      state: "st", code: "c0de", iss: "https://idp.example", redirectUri: "https://varlatch.example/oauth/callback/idp.example",
    });
    expect(one("oauth-callback").props["data-status"]).toBe("connected");
    expect(one("oauth-back").props.href).toBe("/o/acme/p/api/e/production?item=MAIL_TOKEN");
    expect(page()).not.toContain("c0de");
    expect(stored.size).toBe(0);
  });

  it("has the code out of the address before the page is there", () => {
    at("/oauth/callback/idp.example", "?code=c0de&state=st");
    takeFromAddress();
    expect(replaceState).toHaveBeenCalledWith(null, "", "/oauth/callback/idp.example");
    expect(takeArrival()).toEqual({ state: "st", code: "c0de", redirectUri: "https://varlatch.example/oauth/callback/idp.example" });
    expect(takeArrival()).toBeNull();
    for (const [pathname, search] of [["/", "?code=x"], ["/oauth/callback2/x", "?code=x"], ["/oauth/callback/x", ""]] as const) {
      replaceState.mockReset();
      at(pathname, search);
      takeFromAddress();
      expect(replaceState).not.toHaveBeenCalled();
      expect(takeArrival()).toBeNull();
    }
  });

  it("sends nothing on that was not begun in this tab", async () => {
    at("/oauth/callback/idp.example", "?code=c0de&state=other");
    await render(<OAuthCallbackPage />);
    expect(api.completeOAuthAuthorization).not.toHaveBeenCalled();
    expect(one("oauth-callback").props["data-status"]).toBe("nothing");
    expect(replaceState).toHaveBeenCalled();
  });

  it("says which account it is when it is another one", async () => {
    at("/oauth/callback/idp.example", "?code=c&state=st");
    remember("st", { org: "acme", project: "api", env: "production", item: "MAIL_TOKEN" });
    api.completeOAuthAuthorization.mockResolvedValue({
      outcome: "refused", reason: "account-mismatch", message: "This is another account.", account: { id: "2", label: "mallory@example.com" }, previousAccount: { id: "1", label: "alice@example.com" },
    });
    await render(<OAuthCallbackPage />);
    expect(text(one("oauth-callback"))).toContain("Connected before: alice@example.com. Now: mallory@example.com.");
  });

  it("passes the provider's refusal on", async () => {
    at("/oauth/callback/idp.example", "?error=access_denied&error_description=secret&state=st");
    remember("st", { org: "acme", project: "api", env: "production", item: "MAIL_TOKEN" });
    api.completeOAuthAuthorization.mockResolvedValue({ outcome: "failed", reason: "access-denied", message: "Access was not given at the provider." });
    await render(<OAuthCallbackPage />);
    expect(api.completeOAuthAuthorization.mock.calls[0]![4]).toEqual({ state: "st", error: "access_denied", redirectUri: "https://varlatch.example/oauth/callback/idp.example" });
  });
});

describe("elsewhere", () => {
  it("is never exported, nor asked for", async () => {
    api.effectiveConfiguration.mockResolvedValue({
      items: [
        { name: "API_KEY", sensitive: true, source: "self", value: null },
        { name: "MAIL_TOKEN", sensitive: true, source: "self", value: null, oauth: { preset: "google", grant: "authorization_code", status: "connected", paused: false } },
      ],
      callerView: { withheld: [], unexpanded: [] },
    });
    api.discloseSecrets.mockResolvedValue({ items: [{ name: "API_KEY", versionId: "v", value: "x" }], withheld: [] });
    const env = { id: "env_1", projectId: "prj_1", name: "production", kind: "shared", tier: "production", createdAt: "2026-10-01T00:00:00Z" } as Environment;
    let got: ReturnType<typeof useExport> | undefined;
    const Probe = () => {
      got = useExport("acme", "api", env);
      return null;
    };
    await render(<Probe />);
    await act(async () => got!.setIncludeSecrets(true));
    const built = await got!.build();
    expect(built.text).toContain("# MAIL_TOKEN: OAuth connection, never exported");
    expect(api.discloseSecrets.mock.calls[0]![3].items).toEqual(["API_KEY"]);
  });

  it("is described in the audit log", () => {
    const say = (eventType: string, metadata: Record<string, unknown>) =>
      segmentsText(describeEvent({ eventType, decision: "info", resource: { itemName: "MAIL_TOKEN" }, metadata: { connection: "oauth", ...metadata } } as never, emptyResolver).segments);
    expect(say("sync.connection_created", { account: "alice@example.com" })).toBe("connected MAIL_TOKEN of alice@example.com");
    expect(say("sync.connection_created", { account: "alice@example.com", endpointHosts: "idp.example,api.idp.example" })).toBe("connected MAIL_TOKEN of alice@example.com, at idp.example, api.idp.example");
    expect(say("sync.connection_credential_replaced", { outcome: "refreshed" })).toBe("refreshed MAIL_TOKEN");
    expect(say("sync.connection_credential_replaced", { outcome: "reconnected", account: "m@e", accountChanged: true })).toContain("to another account");
    expect(say("sync.connection_checked", { outcome: "needs-reconnect", reason: "refresh-answer-lost" })).toContain("refresh answer lost");
    expect(say("sync.connection_checked", { outcome: "failing", reason: "timeout" })).toBe("could not refresh MAIL_TOKEN: timeout");
    expect(say("sync.connection_revoked", { atProvider: "revoked" })).toBe("disconnected MAIL_TOKEN, and revoked its tokens");
    expect(segmentsText(describeEvent({ eventType: "value.written", decision: "info", resource: { itemName: "MAIL_TOKEN" }, metadata: { oauth: true } } as never, emptyResolver).segments)).toContain("added the OAuth connection MAIL_TOKEN");
    // A Platform Connection's are as they were.
    expect(segmentsText(describeEvent({ eventType: "sync.connection_created", decision: "info", resource: {}, metadata: { platform: "coolify" } } as never, emptyResolver).segments)).toContain("Coolify");
  });
});
