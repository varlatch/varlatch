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
  PROBE_TIMEOUT_MS,
  READ_TIMEOUT_MS,
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
