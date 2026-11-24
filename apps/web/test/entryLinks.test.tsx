// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { EntryLinkView } from "@varlatch/protocol";

const TOKEN = `vlt_entry_${"a".repeat(43)}`;
const page = vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const listeners: Record<string, (() => void)[]> = {};
  const location = { protocol: "https:", hostname: "varlatch.example", host: "varlatch.example", pathname: "/entry", hash: "" };
  const replaced: string[] = [];
  vi.stubGlobal("window", globalThis);
  vi.stubGlobal("location", location);
  vi.stubGlobal("history", { replaceState: (_s: unknown, _t: string, to: string) => ((location.hash = ""), replaced.push(to)) });
  vi.stubGlobal("addEventListener", (n: string, f: () => void) => void (listeners[n] ??= []).push(f));
  vi.stubGlobal("removeEventListener", (n: string, f: () => void) => void (listeners[n] = (listeners[n] ?? []).filter((x) => x !== f)));
  return { listeners, location, replaced };
});
const session = vi.hoisted(() => ({ browserSession: vi.fn(), authPost: vi.fn(), signInWithPasskey: vi.fn(), signOut: vi.fn() }));
vi.mock("../src/lib/varlatchdSession", () => session);
vi.mock("../src/lib/theme", () => ({ showPreferredTheme: () => undefined }));
const api = { listEntryLinks: vi.fn(), createEntryLink: vi.fn(), cancelEntryLink: vi.fn(), listIdentities: vi.fn() };
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api }) }));
vi.mock("../src/shell/Shell", () => ({ errorMessage: (err: unknown) => (err instanceof Error ? err.message : String(err)) }));
vi.mock("../src/components/Toast", () => ({ useToast: () => ({ success: vi.fn(), error: vi.fn() }) }));
vi.mock("../src/components/CodeBlock", () => ({ CopyButton: () => null }));
vi.mock("../src/components/Dialog", () => ({
  Dialog: ({ open, children, footer }: { open: boolean; children: React.ReactNode; footer: React.ReactNode }) =>
    open ? (
      <div>
        {children}
        {footer}
      </div>
    ) : null,
}));
import { describeEvent, emptyResolver, segmentsText } from "../src/features/audit/describe";
import { actorOf, isVarlatchEvent } from "../src/features/audit/parts";
import { EntryApp, secureEnough } from "../src/features/entry/EntryApp";
import { EntryLinksPanel } from "../src/features/entry/EntryLinksPanel";
import { strayEnds, takeToken } from "../src/features/entry/client";

/** Entry links (ADR-0063): the page a value is entered on, and asking for one. */

const view: EntryLinkView = {
  restrictedTo: "anyone",
  signInRequired: false,
  organization: "Acme",
  project: "API",
  environment: "production",
  item: "PROVIDER_KEY",
  accepts: "value",
  replace: false,
  description: "The key of the account.",
  requestedBy: { name: "orders-app", kind: "service" },
  expiresAt: "2099-01-01T00:00:00.000Z",
  expiresInSeconds: 600,
};

let root: ReactTestRenderer | undefined;
const flush = () => act(async () => void (await new Promise((r) => setTimeout(r, 0))));
const render = async (node: React.ReactElement) => {
  await act(async () => {
    root = create(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{node}</QueryClientProvider>);
  });
  await flush();
};
const all = (id: string) => root!.root.findAll((n: ReactTestInstance) => n.props["data-testid"] === id && typeof n.type === "string");
const one = (id: string) => all(id)[0]!;
const text = () => JSON.stringify(root!.toJSON());
const type = async (value: string) => {
  await act(async () => one("entry-value").props.onChange({ target: { value } }));
};
const send = async () => {
  await act(async () => one("entry-form").props.onSubmit({ preventDefault: () => undefined }));
  await flush();
};

type Asked = { path: string; body: Record<string, unknown>; init: RequestInit };
let asked: Asked[] = [];
let answers: Record<string, (body: Record<string, unknown>, init: RequestInit) => [number, unknown]> = {};
const refusal = (status: number, code: string, message: string, reason?: string): [number, unknown] => [status, { error: { code, message, ...(reason ? { details: { reason } } : {}) } }];

beforeEach(() => {
  asked = [];
  page.replaced.length = 0;
  page.location.hash = `#${TOKEN}`;
  page.location.protocol = "https:";
  answers = { "/v1/entry-links/lookup": () => [200, view], "/v1/entry-links/submit": () => [200, { status: "entered" }] };
  vi.stubGlobal("fetch", async (path: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body)) as Record<string, unknown>;
    asked.push({ path, body, init });
    const [status, json] = answers[path]!(body, init);
    return { ok: status < 400, status, json: async () => json };
  });
  for (const f of Object.values(session)) f.mockReset();
  session.browserSession.mockResolvedValue({ csrfToken: "c", identityId: null });
  session.signOut.mockResolvedValue(undefined);
  session.signInWithPasskey.mockResolvedValue(undefined);
});
afterEach(async () => {
  await act(async () => root?.unmount());
  root = undefined;
});

describe("the link's secret", () => {
  it("is taken out of the address at once, and is nothing else's", () => {
    expect(takeToken()).toBe(TOKEN);
    expect(page.replaced).toEqual(["/entry"]);
    for (const hash of ["", "#", "#x", "#vlt_entry_", "#vlt_entry_<script>", `#${TOKEN}%00`, `#${TOKEN}&x=1`, "#/evil"]) {
      page.location.hash = hash;
      expect(takeToken()).toBe("");
    }
  });
  it("is sent in bodies alone, with no cookie and no referrer", async () => {
    await render(<EntryApp />);
    await type("made-up");
    await send();
    expect(asked.map((a) => a.path)).toEqual(["/v1/entry-links/lookup", "/v1/entry-links/submit"]);
    for (const a of asked) {
      expect(a.init).toMatchObject({ method: "POST", credentials: "omit", referrerPolicy: "no-referrer", cache: "no-store", redirect: "error" });
      expect(a.body.token).toBe(TOKEN);
      expect(JSON.stringify(a.init.headers)).not.toContain(TOKEN);
    }
  });
});

describe("the page", () => {
  it("says what is asked for, and whose words are whose", async () => {
    await render(<EntryApp />);
    for (const s of ["Acme", "PROVIDER_KEY", "production", "orders-app", "These are not Varlatch's words", "not through whoever"]) expect(text()).toContain(s);
    expect(root!.root.findAll((n) => n.type === "blockquote")[0]!.children).toEqual(["The key of the account."]);
    expect(root!.root.findAll((n) => n.type === "a")).toEqual([]);
    expect(all("entry-replaces")).toEqual([]);
  });
  it("masks the value, keeps no copy of it, and shows it nowhere afterwards", async () => {
    await render(<EntryApp />);
    expect(one("entry-value").props).toMatchObject({ type: "password", autoComplete: "off", spellCheck: false });
    expect(one("entry-submit").props.disabled).toBe(true);
    await type("made-up 7f3a");
    await send();
    expect(asked[1]!.body).toEqual({ token: TOKEN, value: "made-up 7f3a" });
    expect(all("entry-done")).toHaveLength(1);
    expect(text()).not.toContain("made-up 7f3a");
    expect(all("entry-form")).toEqual([]);
  });
  it("keeps the lines of a pasted value, and warns of stray ends", async () => {
    await render(<EntryApp />);
    const prevented = vi.fn();
    await act(async () => one("entry-value").props.onPaste({ clipboardData: { getData: () => "-----BEGIN\nAAAA\n-----END\n" }, preventDefault: prevented }));
    expect(prevented).toHaveBeenCalled();
    expect(one("entry-value").type).toBe("textarea");
    expect(one("entry-value").props.className).toContain("text-security:disc");
    expect(one("entry-value").props.value).toBe("-----BEGIN\nAAAA\n-----END\n");
    expect(all("entry-stray")).toHaveLength(1);
    expect([strayEnds(""), strayEnds("a b"), strayEnds(" a"), strayEnds("a\n")]).toEqual([false, false, true, true]);
    await send();
    expect(asked[1]!.body.value).toBe("-----BEGIN\nAAAA\n-----END\n");
  });
  it("clears the value when the browser leaves the page", async () => {
    await render(<EntryApp />);
    await type("made-up");
    await act(async () => page.listeners.pagehide!.forEach((f) => f()));
    expect(one("entry-value").props.value).toBe("");
  });
  it("takes a seed where one is asked for", async () => {
    answers["/v1/entry-links/lookup"] = () => [200, { ...view, accepts: "otpauth" }];
    answers["/v1/entry-links/submit"] = () => refusal(422, "VALIDATION_FAILED", "otpauth: not a URI");
    await render(<EntryApp />);
    await type(" otpauth://totp/x?secret=made-up ");
    await send();
    expect(asked[1]!.body).toEqual({ token: TOKEN, otpauth: "otpauth://totp/x?secret=made-up" });
    // What can be put right keeps the form and what was typed.
    expect(text()).toContain("otpauth: not a URI");
    expect(one("entry-value").props.value).not.toBe("");
  });
  it("says why a link cannot be used, and drops the value then", async () => {
    for (const [answer, says] of [
      [refusal(404, "RESOURCE_NOT_FOUND", "There is no such entry link"), "This link is not known"],
      [refusal(410, "CONSUMED", "A value was entered"), "A value was entered already"],
      [refusal(410, "EXPIRED", "This link has expired"), "This link has ended"],
      [refusal(403, "PERMISSION_DENIED", "Whoever made this link may not", "requester-not-allowed"), "This link cannot be used"],
      [refusal(501, "NOT_IMPLEMENTED_YET", "not built"), "This link cannot be used"],
    ] as const) {
      answers["/v1/entry-links/lookup"] = () => answer;
      page.location.hash = `#${TOKEN}`;
      await render(<EntryApp />);
      expect(one("entry-stopped")).toBeDefined();
      expect(text()).toContain(says);
      await act(async () => root!.unmount());
    }
    answers["/v1/entry-links/lookup"] = () => [200, view];
    answers["/v1/entry-links/submit"] = () => refusal(409, "STATE_CHANGED", "The value changed after this link was made");
    page.location.hash = `#${TOKEN}`;
    await render(<EntryApp />);
    await type("made-up");
    await send();
    expect(text()).toContain("The value changed meanwhile");
    expect(text()).not.toContain("made-up");
  });
  it("asks for the link again when there is none, and for HTTPS", async () => {
    page.location.hash = "";
    await render(<EntryApp />);
    expect(text()).toContain("Open your link again");
    expect(asked).toEqual([]);
    await act(async () => root!.unmount());
    page.location.hash = `#${TOKEN}`;
    page.location.protocol = "http:";
    await render(<EntryApp />);
    expect(text()).toContain("This page needs HTTPS");
    expect(asked).toEqual([]);
    expect([secureEnough({ protocol: "http:", hostname: "localhost" }), secureEnough({ protocol: "http:", hostname: "x.example" })]).toEqual([true, false]);
  });
});

describe("another link opened in the tab", () => {
  const SECOND = `vlt_entry_${"b".repeat(43)}`;
  const second = { ...view, item: "OTHER_KEY", project: "Other" };
  const held = () => {
    let free: (answer: [number, unknown]) => void = () => undefined;
    const answer = new Promise<[number, unknown]>((r) => (free = r));
    return {
      answer,
      free: async (a: [number, unknown]) => {
        await act(async () => free(a));
        await flush();
      },
    };
  };
  const serve = (by: (path: string, token: string) => [number, unknown] | Promise<[number, unknown]>) =>
    vi.stubGlobal("fetch", async (path: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body)) as Record<string, unknown>;
      asked.push({ path, body, init });
      const [status, json] = await by(path, String(body.token));
      return { ok: status < 400, status, json: async () => json };
    });
  const open = async () => {
    page.location.hash = `#${SECOND}`;
    await act(async () => page.listeners.hashchange!.forEach((f) => f()));
    await flush();
  };
  it("drops what was asked about the first", async () => {
    for (const late of [[200, view], refusal(410, "EXPIRED", "This link has ended"), [200, { restrictedTo: "member", signInRequired: true }]] as [number, unknown][]) {
      const first = held();
      serve((_, token) => (token === TOKEN ? first.answer : [200, second]));
      page.location.hash = `#${TOKEN}`;
      await render(<EntryApp />);
      await open();
      expect(text()).toContain("OTHER_KEY");
      await first.free(late);
      expect(text()).toContain("OTHER_KEY");
      expect(text()).not.toContain("PROVIDER_KEY");
      expect(session.browserSession).not.toHaveBeenCalled();
      await type("made-up");
      await send();
      expect(asked.at(-1)!).toMatchObject({ path: "/v1/entry-links/submit", body: { token: SECOND } });
      await act(async () => root!.unmount());
    }
  });
  it("drops what became of a value sent with the first, and of a sign-in", async () => {
    const sent = held();
    serve((path, token) => (path.endsWith("submit") ? sent.answer : [200, token === TOKEN ? view : second]));
    await render(<EntryApp />);
    await type("made-up");
    await send();
    await open();
    expect(text()).toContain("OTHER_KEY");
    await sent.free([200, { status: "entered" }]);
    expect(text()).toContain("OTHER_KEY");
    expect(one("entry-value").props.value).toBe("");
    await type("another");
    await send();
    expect(asked.at(-1)!.body.token).toBe(SECOND);
    await act(async () => root!.unmount());

    let done: () => void = () => undefined;
    session.signInWithPasskey.mockReturnValue(new Promise<void>((r) => (done = r)));
    session.authPost.mockResolvedValue({ ok: true, json: async () => ({ token: "vlt_web_made_up" }) });
    serve((_, token) => [200, token === TOKEN ? { restrictedTo: "member", signInRequired: true } : second]);
    page.location.hash = `#${TOKEN}`;
    await render(<EntryApp />);
    await act(async () => one("entry-sign-in-button").props.onClick());
    await open();
    session.browserSession.mockResolvedValue({ csrfToken: "c", identityId: "idn_1" });
    await act(async () => done());
    await flush();
    expect(text()).toContain("OTHER_KEY");
    await type("x");
    await send();
    expect((asked.at(-1)!.init.headers as Record<string, string>).Authorization).toBeUndefined();
  });
});

describe("a link for a person", () => {
  const forMember = (body: Record<string, unknown>, init: RequestInit): [number, unknown] =>
    (init.headers as Record<string, string>).Authorization ? [200, { ...view, restrictedTo: "member" }] : [200, { restrictedTo: "member", signInRequired: true }];
  beforeEach(() => {
    answers["/v1/entry-links/lookup"] = forMember;
    session.authPost.mockResolvedValue({ ok: true, json: async () => ({ token: "vlt_web_made_up" }) });
  });
  it("shows no name before the sign-in, and enters as the person", async () => {
    await render(<EntryApp />);
    expect(one("entry-sign-in")).toBeDefined();
    expect(text()).not.toContain("PROVIDER_KEY");
    session.browserSession.mockResolvedValue({ csrfToken: "c", identityId: "idn_1" });
    await act(async () => one("entry-sign-in-button").props.onClick());
    await flush();
    expect(session.signInWithPasskey).toHaveBeenCalledOnce();
    expect(session.signOut).not.toHaveBeenCalled();
    expect(text()).toContain("PROVIDER_KEY");
    await type("made-up");
    await send();
    expect((asked.at(-1)!.init.headers as Record<string, string>).Authorization).toBe("Bearer vlt_web_made_up");
  });
  it("uses the session there is, and offers another when it is somebody else's", async () => {
    session.browserSession.mockResolvedValue({ csrfToken: "c", identityId: "idn_1" });
    answers["/v1/entry-links/lookup"] = (b, i) => ((i.headers as Record<string, string>).Authorization ? refusal(403, "PERMISSION_DENIED", "This link is for somebody else", "not-for-you") : forMember(b, i));
    await render(<EntryApp />);
    expect(session.signInWithPasskey).not.toHaveBeenCalled();
    expect(one("entry-wrong-person")).toBeDefined();
    answers["/v1/entry-links/lookup"] = forMember;
    await act(async () => one("entry-sign-in-button").props.onClick());
    await flush();
    expect(session.signOut).toHaveBeenCalledOnce();
    expect(session.signInWithPasskey).toHaveBeenCalledOnce();
    expect(text()).toContain("PROVIDER_KEY");
  });
});

describe("asking for a value", () => {
  const panel = <EntryLinksPanel org="acme" project="api" env="production" item="PROVIDER_KEY" has={false} seed={false} />;
  it("makes a link for a member, shows its address once, and cancels", async () => {
    api.listEntryLinks.mockResolvedValue({ items: [{ id: "enl_1", item: "PROVIDER_KEY", status: "pending", restrictedTo: "member", expiresAt: "2099-01-01T00:00:00.000Z" }, { id: "enl_2", item: "OTHER", status: "pending" }, { id: "enl_3", item: "PROVIDER_KEY", status: "entered" }], nextCursor: null });
    api.createEntryLink.mockResolvedValue({ link: {}, url: `https://varlatch.example/entry#${TOKEN}` });
    api.cancelEntryLink.mockResolvedValue(undefined);
    await render(panel);
    expect([all("entry-link-enl_1").length, all("entry-link-enl_2").length, all("entry-link-enl_3").length]).toEqual([1, 0, 0]);
    await act(async () => one("entry-ask").props.onClick());
    await act(async () => one("entry-words").props.onChange({ target: { value: " The key. " } }));
    await act(async () => one("entry-make").props.onClick());
    await flush();
    expect(api.createEntryLink).toHaveBeenCalledWith("acme", "api", "production", { item: "PROVIDER_KEY", restrictedTo: "member", ttlSeconds: 900, description: "The key." });
    expect(one("entry-url").children).toEqual([`https://varlatch.example/entry#${TOKEN}`]);
    await act(async () => one("entry-link-enl_1").findAll((n) => n.type === "button")[0]!.props.onClick());
    expect(api.cancelEntryLink).toHaveBeenCalledWith("acme", "api", "production", "enl_1");
  });
  it("asks to replace what there is", async () => {
    api.listEntryLinks.mockResolvedValue({ items: [], nextCursor: null });
    api.createEntryLink.mockClear();
    await render(<EntryLinksPanel org="acme" project="api" env="production" item="PORTAL_OTP" has seed />);
    await act(async () => one("entry-ask").props.onClick());
    await act(async () => one("entry-make").props.onClick());
    expect(api.createEntryLink).toHaveBeenCalledWith("acme", "api", "production", { item: "PORTAL_OTP", restrictedTo: "member", ttlSeconds: 900, replace: true, accepts: "otpauth" });
  });
});

describe("the audit log", () => {
  const event = (over: Record<string, unknown>) => ({ eventType: "capability.issued", decision: "info", occurredAt: "2026-11-24T00:00:00Z", actorIdentityId: "idn_1", resource: {}, metadata: {}, ...over }) as never;
  const sentence = (e: never) => segmentsText(describeEvent(e, emptyResolver).segments);
  const link = { entryLinkId: "enl_1", itemName: "PROVIDER_KEY" };
  it("says what was asked, entered, refused and cancelled", () => {
    expect(sentence(event({ resource: link, metadata: { entryLink: "member", replace: false } }))).toContain("asked a member for PROVIDER_KEY");
    expect(sentence(event({ resource: link, metadata: { entryLink: "anyone", replace: true } }))).toContain("asked anyone with a link to replace PROVIDER_KEY");
    expect(sentence(event({ eventType: "capability.denied", resource: link }))).toContain("was refused to enter PROVIDER_KEY with a link");
    expect(sentence(event({ eventType: "capability.revoked", resource: link }))).toContain("cancelled the link to enter PROVIDER_KEY");
    expect(sentence(event({ eventType: "capability.revoked", resource: link, metadata: { reason: "credential-ended" } }))).toContain(
      "ended, by revoking what made it, the link to enter PROVIDER_KEY",
    );
    expect(sentence(event({ eventType: "value.written", resource: { itemName: "PROVIDER_KEY" }, metadata: { entryLinkId: "enl_1" } }))).toContain("set PROVIDER_KEY with a link");
  });
  it("does not say Varlatch did what somebody unknown did", () => {
    const written = event({ eventType: "value.written", actorIdentityId: null, resource: { itemName: "X" }, metadata: { entryLinkId: "enl_1", entryLink: "anyone" } });
    expect(actorOf(written, new Map()).name).toBe("Whoever had the link");
    expect(isVarlatchEvent(written)).toBe(false);
    expect(isVarlatchEvent(event({ eventType: "sync.delivered", actorIdentityId: null }))).toBe(true);
  });
});
