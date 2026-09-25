// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import {
  TRANSPORT_OWNED_HEADERS,
  TargetError,
  canonicalTargets,
  describeTargets,
  formatTarget,
  jsonPointerTokens,
  parseTarget,
} from "../src/targets.js";

describe("substitution targets", () => {
  it("parses each kind into its canonical form", () => {
    expect(formatTarget(parseTarget("header:X-Api-Key"))).toBe("header:x-api-key");
    expect(parseTarget("query:api key")).toEqual({ kind: "query", location: "api key" });
    expect(parseTarget("form:client_secret")).toEqual({ kind: "form", location: "client_secret" });
    expect(parseTarget("json:/a~1b/0")).toEqual({ kind: "json", location: "/a~1b/0" });
  });

  it("rejects unknown kinds, malformed locations, and every transport-owned header", () => {
    for (const bad of ["authorization", "path:/x", "header:", "header:bad name", "query:", "json:", "json:a", "json:/a~2", "json:/a~"]) {
      expect(() => parseTarget(bad), bad).toThrow(TargetError);
    }
    for (const header of [...TRANSPORT_OWNED_HEADERS, "X-Forwarded-Proto", "HOST"]) {
      expect(() => parseTarget(`header:${header}`), header).toThrow(/transport-owned/);
    }
  });

  it("decodes JSON Pointer tokens", () => {
    expect(jsonPointerTokens("/a~1b/c~0d/~01")).toEqual(["a/b", "c~d", "~1"]);
  });

  it("requires one to four distinct targets for every item, and none for anything else", () => {
    expect(canonicalTargets(["B", "A"], { A: ["query:k", "header:X"], B: ["json:/p"] })).toEqual({
      A: ["header:x", "query:k"],
      B: ["json:/p"],
    });
    expect(() => canonicalTargets(["A"], {})).toThrow("A has no substitution target");
    expect(() => canonicalTargets(["A"], { A: ["header:a", "header:b", "header:c", "header:d", "header:e"] })).toThrow("at most 4");
    expect(() => canonicalTargets(["A"], { A: ["header:X", "header:x"] })).toThrow("repeats a target");
    expect(() => canonicalTargets(["A"], { A: ["header:x"], B: ["header:y"] })).toThrow("not an item");
  });

  it("describes targets for audit as names and locations only", () => {
    expect(describeTargets({ B: ["json:/p"], A: ["header:x", "query:k"] })).toBe("A=header:x;A=query:k;B=json:/p");
  });
});
