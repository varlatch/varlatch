// SPDX-License-Identifier: AGPL-3.0-or-later
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * The structural guard of ADR-0057 Decision 9: varlatchd makes outbound
 * requests through net/outbound.ts only. A request anywhere else in
 * services/varlatchd/src (a global fetch, a fetch default, http.request or
 * https.request, a new Agent, an undici import, an S3 client, a raw
 * net/tls connect) fails this test, unless the file and function are on the
 * list below, each with the reason its destination comes from host
 * configuration only. Adding to the list is a reviewed change that must
 * show that.
 */

const SRC = fileURLToPath(new URL("../src", import.meta.url));

type Kind = "fetch-call" | "fetch-value" | "http-request" | "agent" | "undici" | "s3" | "socket";

const PATTERNS: { kind: Kind; pattern: RegExp }[] = [
  // The global fetch, called (not a property such as app.fetch, a private #fetch, or fetchImpl).
  { kind: "fetch-call", pattern: /(^|[^.\w#$])fetch\s*\(/ },
  { kind: "fetch-call", pattern: /globalThis\.fetch\b/ },
  // The global fetch as a value: a default, a fallback, an argument.
  { kind: "fetch-value", pattern: /(=|\?\?|\|\||[(,:]\s)\s*fetch\s*[,);]/ },
  { kind: "fetch-value", pattern: /(=|\?\?|\|\|)\s*fetch\s*$/ },
  // node:http and node:https clients.
  { kind: "http-request", pattern: /\bhttps?\.(request|get)\s*\(/ },
  { kind: "http-request", pattern: /import\s*\{[^}]*\b(request|get)\b[^}]*\}\s*from\s*["']node:https?["']/ },
  { kind: "agent", pattern: /new\s+[\w.]*Agent\b/ },
  { kind: "undici", pattern: /from\s*["']undici["']/ },
  { kind: "s3", pattern: /new\s+S3Client\b|from\s*["']@aws-sdk\// },
  // @varlatch/backup/s3's client builder: the audit export's comes from the policy (OutboundPolicy.storageClient).
  { kind: "s3", pattern: /(^|[^.\w])storageClient\s*\(/ },
  { kind: "socket", pattern: /\b(net|tls)\.connect\s*\(|import\s*\{[^}]*\bconnect\b[^}]*\}\s*from\s*["']node:(net|tls)["']/ },
];

/**
 * The named exceptions (ADR-0057 Decision 9), by file, function and kind.
 * `*` is the whole file.
 */
const EXCEPTIONS: { file: string; functions: string[]; kinds: Kind[]; reason: string }[] = [
  { file: "net/outbound.ts", functions: ["*"], kinds: ["fetch-call", "fetch-value", "http-request", "agent", "undici", "s3", "socket"], reason: "the policy itself" },
  {
    file: "mirror/publisher.ts",
    functions: ["callMutation", "syncAllMirrors", "syncNewMirrorEvents", "purgeRetiredMirrors"],
    kinds: ["fetch-value"],
    reason: "the Convex mirror at VARLATCH_CONVEX_URL: callMutation is its only request; the others pass its fetch down",
  },
  { file: "backup/control.ts", functions: ["startBackupControl"], kinds: ["fetch-call"], reason: "the Convex /version probe at VARLATCH_CONVEX_URL" },
  { file: "doctor.ts", functions: ["observeFunctionsViaQuery"], kinds: ["fetch-call"], reason: "doctor's Convex /api/query probe at VARLATCH_CONVEX_URL" },
  { file: "backup/control.ts", functions: ["<imports>", "control"], kinds: ["http-request"], reason: "the backup control's Unix socket in the state directory" },
  { file: "control-entry.ts", functions: ["<imports>", "<module>"], kinds: ["http-request"], reason: "the backup control's Unix socket in the state directory" },
  { file: "tailnet/localapi.ts", functions: ["localApiGet"], kinds: ["http-request"], reason: "tailscaled's LocalAPI on the Unix socket the host configured" },
  { file: "enroll/page.ts", functions: ["*"], kinds: ["fetch-call"], reason: "browser code embedded as a string: it runs in the person's browser" },
  { file: "enroll/client.ts", functions: ["*"], kinds: ["fetch-call"], reason: "browser code, bundled for the enrollment page" },
];

const DECLARATION = /^(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:function\*?\s+([\w$]+)|(?:const|let|var)\s+([\w$]+)\s*=|class\s+([\w$]+))/;

/** The top-level declaration a line belongs to: its name, `<imports>` for an import, or `<module>`. */
function enclosing(lines: string[], index: number): string {
  if (/^\s*import\b/.test(lines[index] as string)) return "<imports>";
  for (let i = index; i >= 0; i--) {
    const line = lines[i] as string;
    if (line.trim() === "" || /^\s/.test(line) || /^(\)|\/\/|\/\*|\*)/.test(line)) continue;
    const match = DECLARATION.exec(line);
    return match ? ((match[1] ?? match[2] ?? match[3]) as string) : "<module>";
  }
  return "<module>";
}

export interface Violation {
  file: string;
  line: number;
  kind: Kind;
  function: string;
  text: string;
}

/** Every request outside net/outbound.ts that no exception covers. */
export function scan(files: Map<string, string>): Violation[] {
  const violations: Violation[] = [];
  for (const [file, source] of files) {
    const lines = source.split("\n");
    lines.forEach((text, i) => {
      if (/^\s*(\/\/|\*|\/\*)/.test(text)) return;
      for (const { kind, pattern } of PATTERNS) {
        if (!pattern.test(text)) continue;
        const fn = enclosing(lines, i);
        const excused = EXCEPTIONS.some(
          (e) => e.file === file && e.kinds.includes(kind) && (e.functions.includes("*") || e.functions.includes(fn)),
        );
        if (!excused) violations.push({ file, line: i + 1, kind, function: fn, text: text.trim() });
      }
    });
  }
  return violations;
}

function sources(dir: string, out = new Map<string, string>()): Map<string, string> {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) sources(path, out);
    else if (name.endsWith(".ts")) out.set(relative(SRC, path).split("\\").join("/"), readFileSync(path, "utf8"));
  }
  return out;
}

describe("outbound requests go through net/outbound.ts (ADR-0057 Decision 9)", () => {
  it("finds no request outside the module and the named exceptions", () => {
    expect(scan(sources(SRC))).toEqual([]);
  });

  it("every exception is still needed", () => {
    const tree = sources(SRC);
    for (const exception of EXCEPTIONS.filter((e) => e.file !== "net/outbound.ts")) {
      const source = tree.get(exception.file);
      expect(source, exception.file).toBeDefined();
      const withoutIt = new Map(tree);
      // Dropping the exception must surface the request it covers.
      const index = EXCEPTIONS.indexOf(exception);
      EXCEPTIONS.splice(index, 1);
      try {
        expect(scan(withoutIt).some((v) => v.file === exception.file), `${exception.file}: ${exception.reason}`).toBe(true);
      } finally {
        EXCEPTIONS.splice(index, 0, exception);
      }
    }
  });

  it("fails on a bare fetch in a domain file", () => {
    const files = new Map([["domain/example.ts", "export async function send(url: string) {\n  return await fetch(url);\n}\n"]]);
    expect(scan(files)).toMatchObject([{ file: "domain/example.ts", kind: "fetch-call", function: "send" }]);
  });

  it("fails on a fetch default, http.request, a new Agent, undici and an S3 client", () => {
    const files = new Map([
      ["domain/a.ts", "export async function a(fetchImpl: typeof fetch = fetch) {}\n"],
      ["domain/b.ts", "export function b(x?: typeof fetch) {\n  const f = x ?? fetch;\n}\n"],
      ["domain/c.ts", 'import https from "node:https";\nexport function c() {\n  https.request("https://x");\n}\n'],
      ["domain/d.ts", 'import { Agent } from "undici";\nexport const d = new Agent();\n'],
      ["domain/e.ts", 'import { S3Client } from "@aws-sdk/client-s3";\nexport function e() {\n  return new S3Client({});\n}\n'],
    ]);
    const kinds = scan(files).map((v) => `${v.file}:${v.kind}`);
    expect(kinds).toEqual(expect.arrayContaining(["domain/a.ts:fetch-value", "domain/b.ts:fetch-value", "domain/c.ts:http-request", "domain/d.ts:undici", "domain/d.ts:agent", "domain/e.ts:s3"]));
  });

  it("allows mirror/publisher.ts's callMutation, and fails a new request elsewhere in that file", () => {
    const publisher = readFileSync(join(SRC, "mirror/publisher.ts"), "utf8");
    expect(scan(new Map([["mirror/publisher.ts", publisher]]))).toEqual([]);
    const added = `${publisher}\nexport async function leak(url: string) {\n  return fetch(url);\n}\n`;
    expect(scan(new Map([["mirror/publisher.ts", added]]))).toMatchObject([{ function: "leak", kind: "fetch-call" }]);
    const defaulted = `${publisher}\nexport async function other(fetchImpl: typeof fetch = fetch) {}\n`;
    expect(scan(new Map([["mirror/publisher.ts", defaulted]]))).toMatchObject([{ function: "other", kind: "fetch-value" }]);
  });

  it("allows the Convex probes and the local sockets as they are", () => {
    const tree = sources(SRC);
    for (const file of ["backup/control.ts", "doctor.ts", "control-entry.ts", "tailnet/localapi.ts"]) {
      expect(scan(new Map([[file, tree.get(file) as string]])), file).toEqual([]);
    }
    // The Convex probe's exception is that function only.
    const doctor = `${tree.get("doctor.ts")}\nexport async function probe(url: string) {\n  return fetch(url);\n}\n`;
    expect(scan(new Map([["doctor.ts", doctor]]))).toMatchObject([{ function: "probe" }]);
  });
});
