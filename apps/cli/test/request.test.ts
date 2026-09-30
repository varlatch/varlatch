// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { RequestUsageError, brokerFromEnv, parseRequestArgs } from "../src/request.js";

/** `varlatch request`'s curl-like subset and its Broker discovery (ADR-0043 Decision 6). */

const files: Record<string, string> = { "body.json": '{"key":"vlch_ph_v1_x"}\n', "-": "from stdin" };
const read = (spec: string) => {
  if (!(spec in files)) throw new RequestUsageError(`cannot read ${spec} (ENOENT)`);
  return Buffer.from(files[spec] as string);
};
const parse = (...args: string[]) => parseRequestArgs(args, read);

describe("parseRequestArgs", () => {
  it("a bare URL is a GET with Accept */*", () => {
    const o = parse("https://api.example.com/v1/x?a=1");
    expect(o.method).toBe("GET");
    expect(o.url.href).toBe("https://api.example.com/v1/x?a=1");
    expect(o.headers).toEqual([["Accept", "*/*"]]);
    expect(o.body).toBeNull();
    expect(o).toMatchObject({ output: null, include: false });
  });

  it("headers keep their order and case; -X sets the method", () => {
    const o = parse("-X", "DELETE", "-H", "Authorization: Bearer vlch_ph_v1_x", "-H", "X-Two:  2 ", "https://a.example/");
    expect(o.method).toBe("DELETE");
    expect(o.headers).toEqual([["Authorization", "Bearer vlch_ph_v1_x"], ["X-Two", "2"], ["Accept", "*/*"]]);
  });

  it("-d is a form POST by default; --json sets the JSON headers; an explicit Content-Type wins", () => {
    expect(parse("-d", "a=1", "https://a.example/")).toMatchObject({
      method: "POST",
      body: Buffer.from("a=1"),
      headers: [["Content-Type", "application/x-www-form-urlencoded"], ["Accept", "*/*"]],
    });
    expect(parse("--json", '{"a":1}', "https://a.example/").headers).toEqual([
      ["Content-Type", "application/json"],
      ["Accept", "application/json"],
    ]);
    expect(parse("-H", "Content-Type: text/plain", "-d", "x", "https://a.example/").headers).toEqual([
      ["Content-Type", "text/plain"],
      ["Accept", "*/*"],
    ]);
  });

  it("@file and @- read the bytes as they are", () => {
    expect(parse("--data", "@body.json", "https://a.example/").body?.toString()).toBe('{"key":"vlch_ph_v1_x"}\n');
    expect(parse("--json", "@-", "https://a.example/").body?.toString()).toBe("from stdin");
  });

  it("-o and -i", () => {
    expect(parse("-o", "out.json", "-i", "https://a.example/")).toMatchObject({ output: "out.json", include: true });
  });

  it.each([
    [["https://a.example/", "https://b.example/"], /give one URL/],
    [[], /give the URL/],
    [["ftp://a.example/"], /not an HTTP URL/],
    [["api.example.com/x"], /not an absolute URL/],
    [["https://u:p@a.example/"], /credentials in the URL/],
    [["-H", "no colon here", "https://a.example/"], /expects '<name>: <value>'/],
    [["-H", "X-A: a\r\nX-B: b", "https://a.example/"], /cannot contain a line break/],
    [["-X", "GET /", "https://a.example/"], /not an HTTP method/],
    [["-d", "a", "--json", "b", "https://a.example/"], /give the body once/],
    [["--data", "@missing", "https://a.example/"], /cannot read missing/],
    [["--compressed", "https://a.example/"], /unknown option --compressed/],
    [["-H"], /-H needs a value/],
  ])("refuses %j", (args, message) => {
    expect(() => parse(...(args as string[]))).toThrow(message);
  });
});

describe("brokerFromEnv", () => {
  const run = { VARLATCH_AGENT_RUN: "run_0123456789abcdef" };

  it("the loopback proxy with the per-run credential, as an agent-safe run sets it", () => {
    expect(brokerFromEnv({ ...run, HTTPS_PROXY: "http://vlt:tok%2Fen@127.0.0.1:43210" })).toEqual({
      host: "127.0.0.1",
      port: 43210,
      authorization: `Basic ${Buffer.from("vlt:tok/en").toString("base64")}`,
    });
  });

  it("refuses outside an agent-safe run, even with a proxy set", () => {
    expect(brokerFromEnv({ HTTPS_PROXY: "http://vlt:t@127.0.0.1:1" })).toMatchObject({ refusal: expect.stringMatching(/VARLATCH_AGENT_RUN is not set/) });
  });

  it("refuses a run without a Broker, and a proxy that is not this run's Broker", () => {
    expect(brokerFromEnv(run)).toMatchObject({ refusal: expect.stringMatching(/has no Broker/) });
    for (const proxy of ["http://proxy.corp.example:3128", "http://127.0.0.1:3128", "https://vlt:t@127.0.0.1:1", "not a url"]) {
      expect(brokerFromEnv({ ...run, HTTPS_PROXY: proxy })).toHaveProperty("refusal");
    }
  });
});
