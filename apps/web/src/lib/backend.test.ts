// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { backendOf, detectBackend } from "./backend";

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });

/** A fetch that answers /v1/meta with each of `answers` in turn: a Response, or an Error to throw. */
function scripted(answers: (Response | Error)[]) {
  const calls: string[] = [];
  const fetchMeta = (async (input: RequestInfo | URL) => {
    calls.push(String(input));
    const next = answers.shift();
    if (!next) throw new Error("no more answers");
    if (next instanceof Error) throw next;
    return next;
  }) as typeof fetch;
  return { fetchMeta, calls };
}

describe("the clients /v1/meta chooses", () => {
  it("keeps Better Auth and Convex for a server without auth.session", () => {
    expect(backendOf(["auth.device", "identity.whoami"])).toEqual({ session: "better-auth", realtime: "convex" });
  });
  it("takes the Go server's own session, and no Convex client, with auth.session", () => {
    expect(backendOf(["identity.whoami", "auth.session"])).toEqual({ session: "varlatchd", realtime: "none" });
  });
  it("takes the Go server's server-sent events with realtime.sse", () => {
    expect(backendOf(["identity.whoami", "auth.session", "realtime.sse"])).toEqual({ session: "varlatchd", realtime: "sse" });
  });
});

describe("detecting the server", () => {
  const sleeps: number[] = [];
  const sleep = async (ms: number) => void sleeps.push(ms);

  it("never guesses from a failure: it waits, asks again, and takes the Go server's answer", async () => {
    sleeps.length = 0;
    const waits: string[] = [];
    const { fetchMeta, calls } = scripted([
      new TypeError("network down"),
      json(502, { error: "bad gateway" }),
      json(200, { capabilities: ["identity.whoami", "auth.session"] }),
    ]);
    const backend = await detectBackend({ fetch: fetchMeta, sleep, onWaiting: (why) => waits.push(why) });
    expect(backend).toEqual({ session: "varlatchd", realtime: "none" });
    expect(calls).toEqual(["/v1/meta", "/v1/meta", "/v1/meta"]);
    expect(waits).toEqual(["connecting", "connecting"]);
    expect(sleeps).toEqual([1000, 2000]);
  });

  it("chooses the TypeScript server only from a successful answer without auth.session", async () => {
    sleeps.length = 0;
    const waits: string[] = [];
    const { fetchMeta } = scripted([
      json(503, { error: { code: "MAINTENANCE", message: "Installation maintenance; retry later" } }, { "Retry-After": "7" }),
      json(200, { notMeta: true }),
      json(200, { capabilities: ["identity.whoami", "auth.device"] }),
    ]);
    const backend = await detectBackend({ fetch: fetchMeta, sleep, onWaiting: (why) => waits.push(why) });
    expect(backend).toEqual({ session: "better-auth", realtime: "convex" });
    // Maintenance waits its Retry-After; an answer that is not the meta
    // document chooses nothing either.
    expect(waits).toEqual(["maintenance", "connecting"]);
    expect(sleeps).toEqual([7000, 1000]);
  });

  it("gives up a request that does not answer, and asks again", async () => {
    sleeps.length = 0;
    let first = true;
    const fetchMeta = ((_: RequestInfo | URL, init?: RequestInit) => {
      if (first) {
        first = false;
        return new Promise<Response>((_, reject) => init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError"))));
      }
      return Promise.resolve(json(200, { capabilities: ["auth.session"] }));
    }) as typeof fetch;
    expect(await detectBackend({ fetch: fetchMeta, sleep, timeoutMs: 10 })).toEqual({ session: "varlatchd", realtime: "none" });
    expect(sleeps).toEqual([1000]);
  });
});
