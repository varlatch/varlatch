// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import {
  canonicalizeHost,
  destinationMatches,
  formatSelector,
  parseDestinationSelector,
} from "../src/authz/destination.js";

function sel(raw: string) {
  const parsed = parseDestinationSelector(raw);
  if (!parsed) throw new Error(`selector did not parse: ${raw}`);
  return parsed;
}

describe("canonicalizeHost", () => {
  it("lowercases and strips one trailing dot", () => {
    expect(canonicalizeHost("API.Example.COM.")).toBe("api.example.com");
  });

  it("punycodes unicode hosts", () => {
    expect(canonicalizeHost("münchen.example")).toBe("xn--mnchen-3ya.example");
  });

  it("rejects credentials, paths, schemes, and empty labels", () => {
    for (const bad of ["user@host.com", "host.com/path", "http://host.com", "a..b", "", " ", "host com"]) {
      expect(canonicalizeHost(bad)).toBeNull();
    }
  });

  it("passes IP literals through", () => {
    expect(canonicalizeHost("127.0.0.1")).toBe("127.0.0.1");
    expect(canonicalizeHost("::1")).toBe("::1");
  });
});

describe("parseDestinationSelector", () => {
  it("defaults to port 443", () => {
    expect(sel("api.example.com")).toEqual({ host: "api.example.com", wildcard: false, port: 443 });
  });

  it("parses explicit ports and wildcards", () => {
    expect(sel("api.example.com:8443").port).toBe(8443);
    expect(sel("*.example.com")).toEqual({ host: "example.com", wildcard: true, port: 443 });
    expect(formatSelector(sel("*.Example.com:80"))).toBe("*.example.com:80");
  });

  it("parses bracketed IPv6", () => {
    expect(sel("[::1]:8080")).toEqual({ host: "::1", wildcard: false, port: 8080 });
  });

  it("rejects malformed selectors", () => {
    for (const bad of ["", "*.1.2.3.4", "a*.example.com", "host:0", "host:99999", "host:abc", "::1:443", "u@h", "*"]) {
      expect(parseDestinationSelector(bad)).toBeNull();
    }
  });
});

describe("destinationMatches", () => {
  const wild = sel("*.example.com");

  it("wildcard matches subdomains at any depth", () => {
    expect(destinationMatches(wild, { host: "api.example.com", port: 443 })).toBe(true);
    expect(destinationMatches(wild, { host: "a.b.example.com", port: 443 })).toBe(true);
  });

  it("wildcard never matches the apex", () => {
    expect(destinationMatches(wild, { host: "example.com", port: 443 })).toBe(false);
  });

  it("naive suffix tricks do not match", () => {
    expect(destinationMatches(wild, { host: "evilexample.com", port: 443 })).toBe(false);
    expect(destinationMatches(sel("api.example.com"), { host: "xapi.example.com", port: 443 })).toBe(false);
  });

  it("port is part of the constraint", () => {
    expect(destinationMatches(sel("api.example.com"), { host: "api.example.com", port: 8443 })).toBe(false);
    expect(destinationMatches(sel("api.example.com:8443"), { host: "api.example.com", port: 8443 })).toBe(true);
  });

  it("canonicalizes the exercised destination before comparing", () => {
    expect(destinationMatches(sel("api.example.com"), { host: "API.example.com.", port: 443 })).toBe(true);
  });

  it("IP literals match exactly and never via wildcard", () => {
    expect(destinationMatches(sel("127.0.0.1:9000"), { host: "127.0.0.1", port: 9000 })).toBe(true);
    expect(destinationMatches(wild, { host: "1.2.3.4", port: 443 })).toBe(false);
  });
});
