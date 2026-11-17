// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestRenderer } from "react-test-renderer";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
vi.hoisted(() => {
  vi.stubGlobal("location", { origin: "https://varlatch.example", hostname: "varlatch.example" });
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
});
vi.mock("better-auth/client", () => ({ createAuthClient: () => ({ signOut: async () => {}, signIn: { passkey: async () => ({}) } }) }));
vi.mock("@better-auth/passkey/client", () => ({ passkeyClient: () => ({}) }));
import { SessionProvider } from "../src/lib/session";
import {
  endpointRequestInit,
  PERMISSION_PROBE_TIMEOUT_MS,
  PROBE_TIMEOUT_MS,
  probeTimeout,
  READ_TIMEOUT_MS,
  supportsTargetAddressSpace,
  TailnetConnectionProvider,
  TailnetUnreachableError,
  useTailnetConnection,
} from "../src/lib/tailnetConnection";
import { TailnetConnectStatus } from "../src/features/values/TailnetOnly";

/**
 * The dashboard's side of the tailnet browser endpoint (ADR-0046 Decision 5,
 * test plan 13), with the real session and connection providers and a
 * stubbed network: what goes where, and when.
 */

const ENDPOINT = "https://varlatch.example.ts.net:8688";
const DEVICE = { recognized: true, tailnet: "example.ts.net", nodeId: "nLAPTOP", nodeName: "laptop", tags: ["tag:prod"] };

type Sent = { url: string; method: string; credentials: RequestCredentials | undefined; auth: string | undefined };
let sent: Sent[];
let endpointConfigured: boolean;
/** How the endpoint answers; the default never answers until aborted. */
let endpoint: (url: string, init: RequestInit) => Promise<Response>;
let state: ReturnType<typeof useTailnetConnection>;
let root: ReactTestRenderer | undefined;
let client: QueryClient;

const never = (_url: string, init: RequestInit) =>
  new Promise<Response>((_, reject) => init.signal?.addEventListener("abort", () => reject(init.signal!.reason)));

beforeEach(() => {
  sent = [];
  endpointConfigured = true;
  endpoint = never;
  vi.stubGlobal("document", new EventTarget());
  vi.stubGlobal("fetch", async (input: unknown, init: RequestInit = {}) => {
    const url = String(input);
    const headers = (init.headers ?? {}) as Record<string, string>;
    sent.push({ url, method: init.method ?? "GET", credentials: init.credentials, auth: headers.Authorization });
    if (url.startsWith(ENDPOINT)) return endpoint(url, init);
    if (url.endsWith("/auth/varlatch-token")) return Response.json({ token: "bearer-1", identityId: "idn_me" });
    if (url.endsWith("/v1/meta")) return Response.json({ apiMajor: 1, serverVersion: "x", capabilities: ["tailnet.browser-reads", "environments.tailnet-required"] });
    if (url.endsWith("/v1/tailnet/endpoint")) return Response.json({ browserEndpoint: endpointConfigured ? ENDPOINT : null });
    return Response.json({ items: [] });
  });
});
afterEach(async () => {
  if (root) await act(async () => root!.unmount());
  root = undefined;
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.stubGlobal("location", { origin: "https://varlatch.example", hostname: "varlatch.example" });
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
});

function Probe() {
  state = useTailnetConnection();
  return null;
}
async function mount() {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(
      <QueryClientProvider client={client}>
        <SessionProvider>
          <TailnetConnectionProvider>
            <Probe />
          </TailnetConnectionProvider>
        </SessionProvider>
      </QueryClientProvider>,
    );
  });
  // The meta and endpoint queries settle.
  for (let i = 0; i < 5; i++) await act(async () => void (await new Promise((r) => setTimeout(r, 0))));
}
/** What a connection status renders, as text. */
async function statusText(connection: typeof state.connection): Promise<string> {
  let shown!: ReactTestRenderer;
  await act(async () => {
    shown = create(<TailnetConnectStatus connection={connection} connect={() => {}} />);
  });
  const text = JSON.stringify(shown.toJSON());
  await act(async () => shown.unmount());
  return text;
}
const toEndpoint = () => sent.filter((r) => r.url.startsWith(ENDPOINT));
const connect = async () => {
  await act(async () => state.connect());
  for (let i = 0; i < 5; i++) await act(async () => void (await new Promise((r) => setTimeout(r, 0))));
};

describe("the tailnet browser endpoint, from the dashboard", () => {
  it("sends nothing to the endpoint until the person connects, and claims no connection from configuration alone", async () => {
    await mount();
    expect(state.connection).toEqual({ status: "idle", endpoint: ENDPOINT });
    expect(state.client).toBeNull();
    expect(toEndpoint()).toEqual([]);
    const text = await statusText(state.connection);
    expect(text).toContain("Connect to tailnet");
    expect(text).toContain("(configured)");
    expect(text).not.toMatch(/Connected/);
  });

  it("offers nothing where no endpoint is configured", async () => {
    endpointConfigured = false;
    await mount();
    expect(state.connection).toEqual({ status: "unavailable" });
    await connect();
    expect(toEndpoint()).toEqual([]);
  });

  it("connects on the explicit action: one GET of the device check, with the bearer and without cookies", async () => {
    endpoint = async () => Response.json(DEVICE);
    await mount();
    await connect();
    expect(toEndpoint()).toEqual([{ url: `${ENDPOINT}/v1/tailnet/context`, method: "GET", credentials: "omit", auth: "Bearer bearer-1" }]);
    expect(state.connection).toMatchObject({ status: "connected", endpoint: ENDPOINT, device: { nodeId: "nLAPTOP" } });
    expect(state.client).not.toBeNull();
    const shown = await statusText(state.connection);
    expect(shown).toContain("Connected from this browser as laptop (checked by Varlatch)");
  });

  it("gives up after four seconds and says the endpoint did not answer from this browser", async () => {
    await mount();
    vi.useFakeTimers();
    await act(async () => state.connect());
    expect(state.connection.status).toBe("connecting");
    await act(async () => void vi.advanceTimersByTime(PROBE_TIMEOUT_MS - 1));
    expect(state.connection.status).toBe("connecting");
    await act(async () => void (await vi.advanceTimersByTimeAsync(2)));
    expect(state.connection).toMatchObject({ status: "unreachable", blockedByPolicy: false });
    expect(PROBE_TIMEOUT_MS).toBe(4_000);
    vi.useRealTimers();
    const shown = await statusText(state.connection);
    expect(shown).toContain("The tailnet endpoint did not answer from this browser.");
    expect(shown).toContain(
      "The browser may need permission to reach devices on your local network: allow it in the prompt or in this site's settings, then press Try again.",
    );
  });

  it("tells a block by the page's own security policy apart", async () => {
    endpoint = async (url) => {
      const violation = Object.assign(new Event("securitypolicyviolation"), { blockedURI: url });
      document.dispatchEvent(violation);
      throw new TypeError("Failed to fetch");
    };
    await mount();
    await connect();
    expect(state.connection).toMatchObject({ status: "unreachable", blockedByPolicy: true });
  });

  it("says why Varlatch did not recognize the device", async () => {
    endpoint = async () => Response.json({ recognized: false, reason: "shared" });
    await mount();
    await connect();
    expect(state.connection).toMatchObject({ status: "unrecognized", reason: "shared" });
    expect(state.client).toBeNull();
    const shown = await statusText(state.connection);
    expect(shown).toContain("shared into the tailnet from another one");
  });

  it("never sends a disclosure again when the endpoint stops answering, and checks the connection instead", async () => {
    endpoint = async () => Response.json(DEVICE);
    await mount();
    await connect();
    const reader = state.client!;
    endpoint = async () => {
      throw new TypeError("Failed to fetch");
    };
    let failure: unknown;
    await act(async () => {
      failure = await reader.discloseSecrets("acme", "api", "production", { scope: "all-authorized-secrets" }).catch((e: unknown) => e);
    });
    for (let i = 0; i < 5; i++) await act(async () => void (await new Promise((r) => setTimeout(r, 0))));
    expect(failure).toBeInstanceOf(TailnetUnreachableError);
    const disclosures = toEndpoint().filter((r) => r.url.endsWith("/disclosures"));
    expect(disclosures).toHaveLength(1);
    expect(disclosures[0]).toMatchObject({ method: "POST", credentials: "omit" });
    // The connection was checked again, and it is gone.
    expect(toEndpoint().filter((r) => r.url.endsWith("/v1/tailnet/context"))).toHaveLength(2);
    expect(state.connection.status).toBe("unreachable");
    expect(state.client).toBeNull();
  });

  it("drops values read through the endpoint once the tab is no longer connected as that device", async () => {
    endpoint = async () => Response.json(DEVICE);
    await mount();
    await connect();
    client.setQueryData(["effective-values", "acme", "api", "production", true, "tailnet:nLAPTOP"], { secret: "read through the tailnet" });
    client.setQueryData(["effective-values", "acme", "api", "development", false, "ordinary"], { plain: "kept" });
    endpoint = async () => Response.json({ recognized: false, reason: "unrecognized" });
    await connect();
    expect(state.connection.status).toBe("unrecognized");
    expect(client.getQueryData(["effective-values", "acme", "api", "production", true, "tailnet:nLAPTOP"])).toBeUndefined();
    expect(client.getQueryData(["effective-values", "acme", "api", "development", false, "ordinary"])).toEqual({ plain: "kept" });
  });

  describe("deadlines cover a token re-exchange (review regression)", () => {
    /** The dashboard's own token exchange stalls until `release` is called. */
    let release: () => void;
    const stallExchange = () => {
      const usual = globalThis.fetch;
      let answer!: (r: Response) => void;
      const stalled = new Promise<Response>((r) => (answer = r));
      release = () => answer(Response.json({ token: "bearer-2", identityId: "idn_me" }));
      vi.stubGlobal("fetch", async (input: unknown, init: RequestInit = {}) => {
        if (String(input).endsWith("/auth/varlatch-token")) {
          sent.push({ url: String(input), method: init.method ?? "GET", credentials: init.credentials, auth: undefined });
          return stalled;
        }
        return usual(input as RequestInfo, init);
      });
    };

    it("Connect settles at four seconds while the re-exchange after a 401 stalls", async () => {
      await mount();
      stallExchange();
      endpoint = async () => new Response(null, { status: 401 });
      vi.useFakeTimers();
      await act(async () => state.connect());
      await act(async () => void (await vi.advanceTimersByTimeAsync(PROBE_TIMEOUT_MS - 1)));
      expect(state.connection.status).toBe("connecting");
      await act(async () => void (await vi.advanceTimersByTimeAsync(2)));
      expect(state.connection).toMatchObject({ status: "unreachable" });
      // The exchange lands late: nothing is asked again.
      const before = toEndpoint().length;
      await act(async () => {
        release();
        await vi.advanceTimersByTimeAsync(10);
      });
      expect(toEndpoint()).toHaveLength(before);
      expect(state.connection.status).toBe("unreachable");
    });

    it("a protected read settles at its deadline, and a disclosure given up on is never sent again", async () => {
      endpoint = async () => Response.json(DEVICE);
      await mount();
      await connect();
      const reader = state.client!;
      stallExchange();
      endpoint = async (url) => (url.endsWith("/v1/tailnet/context") ? Response.json(DEVICE) : new Response(null, { status: 401 }));
      vi.useFakeTimers();
      let read: unknown = "pending";
      let disclosure: unknown = "pending";
      await act(async () => {
        void reader.effectiveConfiguration("acme", "api", "production", { includeValues: true }).then(
          () => (read = "resolved"),
          (e: unknown) => (read = e),
        );
        void reader.discloseSecrets("acme", "api", "production", { scope: "all-authorized-secrets" }).then(
          () => (disclosure = "resolved"),
          (e: unknown) => (disclosure = e),
        );
      });
      await act(async () => void (await vi.advanceTimersByTimeAsync(READ_TIMEOUT_MS - 1)));
      expect(read).toBe("pending");
      expect(disclosure).toBe("pending");
      await act(async () => void (await vi.advanceTimersByTimeAsync(2)));
      expect(read).toBeInstanceOf(TailnetUnreachableError);
      expect(disclosure).toBeInstanceOf(TailnetUnreachableError);
      // The re-exchange lands after the deadline: the disclosure is not replayed, and neither is the read.
      await act(async () => {
        release();
        await vi.advanceTimersByTimeAsync(PROBE_TIMEOUT_MS + 10);
      });
      expect(toEndpoint().filter((r) => r.url.endsWith("/disclosures"))).toHaveLength(1);
      expect(toEndpoint().filter((r) => r.url.includes("/effective-configuration"))).toHaveLength(1);
    });
  });
});

/** A Request that reads RequestInit as a browser does: only the members it knows, and throws on a value its enum lacks. */
const browserRequest = (known: string[], accepts: (value: unknown) => boolean = () => true) =>
  class {
    constructor(_url: string, init: Record<string, unknown> = {}) {
      for (const member of known) {
        const value = init[member];
        if (member === "targetAddressSpace" && value !== undefined && !accepts(value)) throw new TypeError(`bad targetAddressSpace: ${String(value)}`);
      }
    }
  } as unknown as typeof Request;
/** Current Chromium: Local Network Access's address spaces. */
const localNetworkAccess = () => browserRequest(["credentials", "signal", "targetAddressSpace"], (v) => ["loopback", "local", "public"].includes(String(v)));
/** Older Chromium (135): reads the option, but "local" means loopback and "loopback" does not exist. */
const olderChromium = () => browserRequest(["credentials", "signal", "targetAddressSpace"], (v) => ["local", "private", "public"].includes(String(v)));

/**
 * Chromium's Local Network Access: a public page reaching the endpoint on a
 * tailnet address asks the user first. Requests to the endpoint say so up
 * front with targetAddressSpace "local", only where the browser takes it
 * with that meaning.
 */
describe("the endpoint's request options", () => {
  it("finds targetAddressSpace where the browser takes Local Network Access's values", () => {
    expect(supportsTargetAddressSpace(localNetworkAccess())).toBe(true);
  });

  it("finds none where the browser never reads it, or has no Request", () => {
    expect(supportsTargetAddressSpace(browserRequest(["credentials", "signal"]))).toBe(false);
    expect(supportsTargetAddressSpace(undefined)).toBe(false);
  });

  it("finds none in older Chromium, which accepts \"local\" but means loopback by it", () => {
    expect(supportsTargetAddressSpace(olderChromium())).toBe(false);
  });

  it("finds none where the browser rejects \"local\"", () => {
    expect(supportsTargetAddressSpace(browserRequest(["targetAddressSpace"], (v) => v === "loopback" || v === "public"))).toBe(false);
  });

  it("declares the local network only where supported, and never sends cookies", () => {
    const signal = new AbortController().signal;
    expect(endpointRequestInit({ method: "POST", signal }, true)).toEqual({ method: "POST", signal, credentials: "omit", targetAddressSpace: "local" });
    expect(endpointRequestInit({ method: "POST", signal }, false)).toEqual({ method: "POST", signal, credentials: "omit" });
    expect(endpointRequestInit({ credentials: "include" } as RequestInit, false)).toEqual({ credentials: "omit" });
  });

  for (const [browser, makeRequest, expected] of [
    ["current Chromium", localNetworkAccess, "local"],
    ["older Chromium", olderChromium, undefined],
    ["a browser without the option", () => browserRequest(["credentials", "signal"]), undefined],
  ] as const) {
    it(`sends Connect with targetAddressSpace ${expected ?? "absent"} in ${browser}`, async () => {
      vi.stubGlobal("Request", makeRequest());
      let init: RequestInit | undefined;
      endpoint = async (_url, given) => {
        init = given;
        return Response.json(DEVICE);
      };
      await mount();
      await connect();
      expect(state.connection.status).toBe("connected");
      expect(init?.credentials).toBe("omit");
      expect((init as { targetAddressSpace?: string }).targetAddressSpace).toBe(expected);
    });
  }
});

/**
 * The first Connect where the browser may show its local network prompt
 * waits long enough for the person to answer it; otherwise, and once this
 * tab has connected, the probe keeps its short limit.
 */
describe("the Connect deadline", () => {
  it("gives a pending permission prompt time only on the first connect where the browser takes targetAddressSpace", () => {
    expect(probeTimeout(true, false)).toBe(PERMISSION_PROBE_TIMEOUT_MS);
    expect(probeTimeout(false, false)).toBe(PROBE_TIMEOUT_MS);
    expect(probeTimeout(true, true)).toBe(PROBE_TIMEOUT_MS);
    expect(probeTimeout(false, true)).toBe(PROBE_TIMEOUT_MS);
    expect(PERMISSION_PROBE_TIMEOUT_MS).toBe(30_000);
  });

  it("waits up to thirty seconds, saying so after four, where the browser may be asking", async () => {
    vi.stubGlobal("Request", localNetworkAccess());
    await mount();
    vi.useFakeTimers();
    await act(async () => state.connect());
    await act(async () => void (await vi.advanceTimersByTimeAsync(PROBE_TIMEOUT_MS + 1)));
    expect(state.connection).toEqual({ status: "connecting", endpoint: ENDPOINT, awaitingPermission: true });
    // Still under fake timers: switching clocks would drop the probe's deadline.
    expect(await statusText(state.connection)).toContain("Waiting for this browser to allow local network access.");
    await act(async () => void (await vi.advanceTimersByTimeAsync(PERMISSION_PROBE_TIMEOUT_MS - PROBE_TIMEOUT_MS - 2)));
    expect(state.connection.status).toBe("connecting");
    await act(async () => void (await vi.advanceTimersByTimeAsync(2)));
    expect(state.connection).toMatchObject({ status: "unreachable", blockedByPolicy: false });
  });

  it("keeps four seconds once this tab has connected", async () => {
    vi.stubGlobal("Request", localNetworkAccess());
    endpoint = async () => Response.json(DEVICE);
    await mount();
    await connect();
    expect(state.connection.status).toBe("connected");
    endpoint = never;
    vi.useFakeTimers();
    await act(async () => state.connect());
    await act(async () => void (await vi.advanceTimersByTimeAsync(PROBE_TIMEOUT_MS + 1)));
    expect(state.connection).toMatchObject({ status: "unreachable", blockedByPolicy: false });
  });

  it("keeps four seconds, with no waiting note, where the browser does not take targetAddressSpace", async () => {
    vi.stubGlobal("Request", browserRequest(["credentials", "signal"]));
    await mount();
    vi.useFakeTimers();
    await act(async () => state.connect());
    await act(async () => void (await vi.advanceTimersByTimeAsync(PROBE_TIMEOUT_MS - 1)));
    expect(state.connection).toEqual({ status: "connecting", endpoint: ENDPOINT });
    await act(async () => void (await vi.advanceTimersByTimeAsync(2)));
    expect(state.connection).toMatchObject({ status: "unreachable", blockedByPolicy: false });
  });
});

/**
 * A probe in flight stops with the provider, and when the identity or the
 * endpoint changes: its request is aborted, its timers cleared and its
 * listener removed then, not when it would have settled up to 30 seconds
 * later.
 */
describe("a Connect probe that is no longer wanted", () => {
  let probeSignal: AbortSignal | undefined;
  let listening: number;
  let baseline: number;
  /** Starts a probe that waits on the browser's permission prompt: a request, two timers, a listener. */
  async function startProbe() {
    vi.stubGlobal("Request", localNetworkAccess());
    const doc = document;
    listening = 0;
    vi.spyOn(doc, "addEventListener").mockImplementation(function (this: EventTarget, type: string) {
      if (type === "securitypolicyviolation") listening++;
    } as typeof doc.addEventListener);
    vi.spyOn(doc, "removeEventListener").mockImplementation(function (this: EventTarget, type: string) {
      if (type === "securitypolicyviolation") listening--;
    } as typeof doc.removeEventListener);
    probeSignal = undefined;
    endpoint = (_url, init) => {
      probeSignal = init.signal ?? undefined;
      return never(_url, init);
    };
    await mount();
    vi.useFakeTimers();
    baseline = vi.getTimerCount();
    await act(async () => state.connect());
    await act(async () => void (await vi.advanceTimersByTimeAsync(0)));
    expect(state.connection).toEqual({ status: "connecting", endpoint: ENDPOINT });
    expect(probeSignal?.aborted).toBe(false);
    expect(listening).toBe(1);
    expect(vi.getTimerCount()).toBe(baseline + 2);
  }

  it("stops when the provider unmounts", async () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    await startProbe();
    await act(async () => root!.unmount());
    root = undefined;
    client.clear();
    await act(async () => void (await vi.advanceTimersByTimeAsync(0)));
    expect(probeSignal?.aborted).toBe(true);
    expect(listening).toBe(0);
    // Not even the zero-delay wait for a policy violation: the probe ended
    // before it could report anything.
    expect(vi.getTimerCount()).toBe(0);
    await act(async () => void (await vi.advanceTimersByTimeAsync(PERMISSION_PROBE_TIMEOUT_MS + 1)));
    expect(errors.mock.calls.filter(([m]) => !String(m).includes("react-test-renderer is deprecated"))).toEqual([]);
  });

  it("stops when the endpoint changes, and the new one stays unconnected", async () => {
    await startProbe();
    endpointConfigured = false;
    await act(async () => void (await client.invalidateQueries({ queryKey: ["tailnet-endpoint"] })));
    await act(async () => void (await vi.advanceTimersByTimeAsync(0)));
    expect(state.connection).toEqual({ status: "unavailable" });
    expect(probeSignal?.aborted).toBe(true);
    expect(listening).toBe(0);
    expect(vi.getTimerCount()).toBe(baseline);
    await act(async () => void (await vi.advanceTimersByTimeAsync(PERMISSION_PROBE_TIMEOUT_MS + 1)));
    expect(state.connection).toEqual({ status: "unavailable" });
  });

  it("is replaced by a new Connect, which stops the first", async () => {
    await startProbe();
    const first = probeSignal!;
    await act(async () => state.connect());
    await act(async () => void (await vi.advanceTimersByTimeAsync(0)));
    expect(first.aborted).toBe(true);
    expect(probeSignal).not.toBe(first);
    expect(probeSignal?.aborted).toBe(false);
    expect(listening).toBe(1);
    expect(vi.getTimerCount()).toBe(baseline + 2);
  });
});
