// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import {
  BaselineError,
  MAX_LISTED_PER_FILE,
  ScanEngine,
  baselineEntriesOf,
  formatBaseline,
  formatScanHuman,
  parseBaseline,
  parseSize,
  scanExitCode,
  scanNotices,
  type ScanReport,
  type ScanSecret,
} from "../src/scan.js";

/**
 * The scan engine (ADR-0038 Decision 14), on in-memory content: findings,
 * locations, complete matches only, bounds, allow markers, and the baseline.
 */

const API_KEY: ScanSecret = { item: "API_KEY", versionId: "ver_api", retiring: false, value: "tok-api-aaaabbbbccccdddd" };
const DB_PASS: ScanSecret = { item: "DB_PASS", versionId: "ver_db", retiring: false, value: "hunter2-hunter2-hunter2" };
// A PEM-shaped multi-line value, assembled at runtime so that no source line
// is a key header, with a low-entropy body.
const PEM_LABEL = ["PRIVATE", "KEY"].join(" ");
const PEM_VALUE = [
  `-----BEGIN ${PEM_LABEL}-----`,
  "FAKEKEYDATA0FAKEKEYDATA1FAKEKEYDATA2FAKEKEYDATA3FAKE",
  "FAKEKEYDATA4FAKEKEYDATA5FAKEKEYDATA6FAKEKEYDATA7FAKE",
  `-----END ${PEM_LABEL}-----`,
].join("\n");
const TLS_KEY: ScanSecret = { item: "TLS_KEY", versionId: "ver_tls", retiring: false, value: PEM_VALUE };

/** Scan files given as strings or bytes, each split into the given chunk size. */
function scanFiles(
  secrets: ScanSecret[],
  files: Record<string, string | Uint8Array>,
  opts: { chunk?: number; engine?: ScanEngine } = {},
): ScanReport {
  const engine = opts.engine ?? new ScanEngine(secrets);
  for (const [path, content] of Object.entries(files)) {
    const data = typeof content === "string" ? Buffer.from(content) : Buffer.from(content);
    if (!engine.admit(path, data.length)) continue;
    const file = engine.begin(path);
    const size = opts.chunk ?? data.length;
    let ok = true;
    for (let at = 0; at < data.length && ok; at += Math.max(1, size)) ok = file.push(data.subarray(at, at + Math.max(1, size)));
    if (ok) file.end();
    else file.fail("grew past the per-file bound while being read");
  }
  return engine.result();
}

/** Every chunk size gives the same report. */
function everyChunking(secrets: ScanSecret[], files: Record<string, string>): ScanReport {
  const whole = scanFiles(secrets, files);
  const longest = Math.max(...Object.values(files).map((f) => Buffer.byteLength(f)));
  for (let chunk = 1; chunk <= Math.min(longest, 97); chunk++) {
    expect(scanFiles(secrets, files, { chunk }), `chunk ${chunk}`).toEqual(whole);
  }
  return whole;
}

function allValues(): string[] {
  return [API_KEY, DB_PASS, TLS_KEY].map((s) => s.value);
}

describe("findings and their locations", () => {
  it("maps an occurrence to its line and byte column", () => {
    const report = everyChunking([API_KEY], {
      "src/config.ts": `// config\nexport const key =\n  "${API_KEY.value}";\n`,
    });
    expect(report.findings).toEqual([
      { path: "src/config.ts", line: 3, column: 4, offset: 32, item: "API_KEY", versionId: "ver_api", retiring: false, form: "raw" },
    ]);
    expect(scanExitCode(report)).toBe(1);
  });

  it("counts the column in bytes, after multi-byte characters", () => {
    const report = everyChunking([API_KEY], { "a.txt": `é ✓ ${API_KEY.value}` });
    // "é" is 2 bytes, "✓" is 3, plus two spaces: the value starts at byte 8.
    expect(report.findings[0]).toMatchObject({ line: 1, column: 8 });
  });

  it("finds a multi-line PEM value and reports the line it starts on (A-S2)", () => {
    const file = `# fixtures\nkey: |\n${PEM_VALUE}\nnext: 1\n`;
    const report = everyChunking([TLS_KEY], { "deploy/values.yaml": file });
    const raw = report.findings.filter((f) => f.form === "raw");
    expect(raw).toEqual([expect.objectContaining({ path: "deploy/values.yaml", line: 3, column: 1, item: "TLS_KEY" })]);
  });

  it("finds a PEM value in JSON, where its newlines are escaped", () => {
    const file = `{\n  "tls": ${JSON.stringify(PEM_VALUE)}\n}\n`;
    const report = everyChunking([TLS_KEY], { "dist/config.json": file });
    expect(report.findings).toEqual([expect.objectContaining({ line: 2, column: 11, form: "json" })]);
  });

  it("reports two Secrets on one line, and the report holds nothing from that line (A-S3)", () => {
    const line = `CANARY_CONTEXT_LEFT ${API_KEY.value} CANARY_MIDDLE ${DB_PASS.value} CANARY_CONTEXT_RIGHT`;
    const report = everyChunking([API_KEY, DB_PASS], { ".env.production": `# top\n${line}\n` });
    expect(report.findings.map((f) => [f.item, f.line, f.column])).toEqual([
      ["API_KEY", 2, 21],
      ["DB_PASS", 2, 21 + API_KEY.value.length + " CANARY_MIDDLE ".length],
    ]);
    const human = formatScanHuman(report, { environment: "production", mode: "paths" }).join("\n");
    const json = JSON.stringify(report);
    for (const output of [human, json]) {
      for (const leaked of [...allValues(), "CANARY", API_KEY.value.slice(0, 8), DB_PASS.value.slice(-8)]) {
        expect(output).not.toContain(leaked);
      }
    }
    expect(human).toContain(".env.production:2:21: API_KEY (version ver_api), as written");
  });

  it("names the form and flags a retiring version", () => {
    const retiring: ScanSecret = { item: "API_KEY", versionId: "ver_old", retiring: true, value: "tok-api-OLDOLDOLDOLDOLD" };
    const encoded = Buffer.from(`user:${retiring.value}`).toString("base64");
    const report = everyChunking([API_KEY, retiring], {
      "log.txt": `a=${encodeURIComponent(API_KEY.value + "/")}\nAuthorization: Basic ${encoded}\n`,
    });
    expect(report.findings.map((f) => [f.versionId, f.retiring, f.form, f.line])).toEqual([
      ["ver_api", false, "raw", 1],
      ["ver_old", true, "base64", 2],
    ]);
    expect(formatScanHuman(report, { environment: "production", mode: "paths" })[1]).toContain(
      "API_KEY (version ver_old, retiring), base64",
    );
  });

  it("reports a Secret inside another Secret's value as two findings", () => {
    const url: ScanSecret = { item: "DATABASE_URL", versionId: "ver_url", retiring: false, value: `postgres://app:${DB_PASS.value}@db/app` };
    const report = everyChunking([url, DB_PASS], { "dist/server.js": `const u="${url.value}"` });
    // Listed in the order they start, although DB_PASS ends first.
    expect(report.findings.map((f) => [f.item, f.column])).toEqual([
      ["DATABASE_URL", 10],
      ["DB_PASS", 10 + "postgres://app:".length],
    ]);
  });

  it("checks a retiring value that equals the current one only once", () => {
    const same: ScanSecret = { ...API_KEY, versionId: "ver_prev", retiring: true };
    const report = scanFiles([API_KEY, same], { a: API_KEY.value });
    expect(report.findings).toHaveLength(1);
    expect(report.valuesChecked).toBe(1);
  });
});

describe("complete occurrences only", () => {
  it("a file ending with a long start of a Secret is not a finding, only counted", () => {
    const report = everyChunking([API_KEY], { "dist/app.js": `var x = "${API_KEY.value.slice(0, 20)}` });
    expect(report.findings).toEqual([]);
    expect(report.incompletePrefixes).toBe(1);
    expect(scanExitCode(report)).toBe(0);
    const notice = scanNotices(report).join("\n");
    expect(notice).toContain("1 file(s) end with the first 8 or more bytes of a Secret");
    expect(notice).not.toContain("dist/app.js");
  });

  it("a short trailing start is not even counted", () => {
    expect(scanFiles([API_KEY], { a: "abc tok-a" }).incompletePrefixes).toBe(0);
  });
});

describe("what is not scanned is never reported clean (A-S5)", () => {
  it("scans a NUL-containing binary file as bytes", () => {
    const binary = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 0, 0, 0xff]), Buffer.from(DB_PASS.value), Buffer.from([0, 1, 2])]);
    const report = scanFiles([DB_PASS], { "bin/server": binary });
    expect(report.findings).toEqual([expect.objectContaining({ path: "bin/server", offset: 8, line: 1, column: 9 })]);
  });

  it("a file over the per-file bound is not scanned, and the scan exits 2 when nothing else is found", () => {
    const engine = new ScanEngine([API_KEY], { limits: { maxFileSize: 100, maxTotalSize: 10_000 } });
    const report = scanFiles([API_KEY], { "big.bin": "x".repeat(101), "small.txt": "fine" }, { engine });
    expect(report.notScanned).toEqual([{ path: "big.bin", reason: "larger than the per-file bound (101 bytes > 100 bytes)" }]);
    expect(report.filesScanned).toBe(1);
    expect(scanExitCode(report)).toBe(2);
    expect(formatScanHuman(report, { environment: "dev", mode: "paths" }).join("\n")).toContain(
      "Not scanned (1), so not known to be clean:\n  big.bin: larger than the per-file bound",
    );
  });

  it("files past the total bound are not scanned; smaller ones that still fit are", () => {
    const engine = new ScanEngine([API_KEY], { limits: { maxFileSize: 100, maxTotalSize: 150 } });
    const report = scanFiles([API_KEY], { a: "a".repeat(100), b: "b".repeat(80), c: "c".repeat(40) }, { engine });
    expect(report.notScanned.map((n) => n.path)).toEqual(["b"]);
    expect(report.notScanned[0]!.reason).toContain("over the total size bound");
    expect(report.bytesScanned).toBe(140);
  });

  it("a file that grows past the bound while read keeps its findings and is reported not scanned", () => {
    const engine = new ScanEngine([API_KEY], { limits: { maxFileSize: 64, maxTotalSize: 10_000 } });
    const file = engine.begin("growing.log");
    expect(file.push(Buffer.from(`${API_KEY.value}\n`))).toBe(true);
    expect(file.push(Buffer.alloc(64))).toBe(false);
    file.fail("grew past the per-file bound while being read");
    const report = engine.result();
    expect(report.findings).toHaveLength(1);
    expect(report.notScanned).toEqual([{ path: "growing.log", reason: "grew past the per-file bound while being read" }]);
    expect(scanExitCode(report)).toBe(1);
  });

  it("names the values too short to check, and the report holds none of them", () => {
    const pin: ScanSecret = { item: "PIN", versionId: "ver_pin", retiring: false, value: "1234567" };
    const report = scanFiles([pin, API_KEY], { a: "pin=1234567" });
    expect(report.skippedItems).toEqual(["PIN"]);
    expect(report.findings).toEqual([]);
    expect(scanNotices(report)).toEqual(["varlatch scan: values shorter than 8 bytes are not checked: PIN"]);
    expect(JSON.stringify(report)).not.toContain("1234567");
  });
});

describe("inline allow markers", () => {
  it("allow only the named item, on a line the occurrence touches", () => {
    const report = everyChunking([API_KEY, DB_PASS], {
      "test/fixture.ts": [
        `const a = "${API_KEY.value}"; // varlatch:allow API_KEY`,
        `const b = "${DB_PASS.value}"; // varlatch:allow API_KEY`,
        `// varlatch:allow DB_PASS`,
        `const c = "${DB_PASS.value}";`,
        `const d = "${API_KEY.value}"; // varlatch:allow  API_KEYS`,
        `const e = "${API_KEY.value}"; // varlatch:allowAPI_KEY`,
      ].join("\n"),
    });
    expect(report.allowed.map((f) => [f.item, f.line, f.allowedBy])).toEqual([["API_KEY", 1, "marker"]]);
    expect(report.findings.map((f) => [f.item, f.line])).toEqual([
      ["DB_PASS", 2],
      ["DB_PASS", 4],
      ["API_KEY", 5],
      ["API_KEY", 6],
    ]);
  });

  it("allow a multi-line value from its first or last line", () => {
    const first = everyChunking([TLS_KEY], { a: `k: | # varlatch:allow TLS_KEY\n${PEM_VALUE}\n` });
    // The marker is on line 1; the value starts on line 2, so it does not apply.
    expect(first.findings).toHaveLength(1);
    const onLast = everyChunking([TLS_KEY], { a: `k: "${PEM_VALUE}" # varlatch:allow TLS_KEY\n` });
    expect(onLast.findings).toEqual([]);
    expect(onLast.allowed).toHaveLength(1);
    const onStart = everyChunking([TLS_KEY], { a: `# varlatch:allow TLS_KEY ${PEM_VALUE}\n` });
    expect(onStart.findings).toEqual([]);
  });
});

describe("the baseline", () => {
  it("allows a finding by path, item, and version only; a new version is found again", () => {
    const baseline = [{ path: "test/key.pem", item: "TLS_KEY", versionId: "ver_tls" }];
    const engine = new ScanEngine([TLS_KEY, API_KEY], { baseline });
    const report = scanFiles([], { "test/key.pem": PEM_VALUE, "other.pem": PEM_VALUE, "test/k2": API_KEY.value }, { engine });
    expect(report.allowed.map((f) => [f.path, f.allowedBy])).toEqual([["test/key.pem", "baseline"]]);
    expect(report.findings.map((f) => f.path)).toEqual(["other.pem", "test/k2"]);
    const rotated = new ScanEngine([{ ...TLS_KEY, versionId: "ver_tls2" }], { baseline });
    expect(scanFiles([], { "test/key.pem": PEM_VALUE }, { engine: rotated }).findings).toHaveLength(1);
  });

  it("holds exactly path, item, and version ID, and refuses anything else (no value-derived data)", () => {
    const report = scanFiles([API_KEY, DB_PASS], { "a.txt": `${API_KEY.value} ${DB_PASS.value}`, "b.txt": API_KEY.value });
    const text = formatBaseline(baselineEntriesOf(report));
    const parsed = JSON.parse(text);
    expect(parsed).toEqual({
      version: 1,
      entries: [
        { path: "a.txt", item: "API_KEY", versionId: "ver_api" },
        { path: "a.txt", item: "DB_PASS", versionId: "ver_db" },
        { path: "b.txt", item: "API_KEY", versionId: "ver_api" },
      ],
    });
    for (const value of allValues()) expect(text).not.toContain(value);
    expect(parseBaseline(text)).toEqual(parsed.entries);
    const bad = [
      "{",
      "[]",
      JSON.stringify({ version: 2, entries: [] }),
      JSON.stringify({ version: 1 }),
      JSON.stringify({ version: 1, entries: [], note: "x" }),
      JSON.stringify({ version: 1, entries: [{ path: "a", item: "B", versionId: "v", sha256: "ab12" }] }),
      JSON.stringify({ version: 1, entries: [{ path: "a", item: "B" }] }),
      JSON.stringify({ version: 1, entries: [{ path: "", item: "B", versionId: "v" }] }),
      JSON.stringify({ version: 1, entries: [{ path: "a", item: "B", versionId: 3 }] }),
    ];
    for (const b of bad) expect(() => parseBaseline(b), b).toThrow(BaselineError);
  });
});

describe("listing limits", () => {
  it("lists at most a bounded number of findings per file and counts the rest, still as findings", () => {
    const content = `${API_KEY.value}\n`.repeat(MAX_LISTED_PER_FILE + 5);
    const report = scanFiles([API_KEY], { "many.txt": content }, { chunk: 4096 });
    expect(report.findings).toHaveLength(MAX_LISTED_PER_FILE);
    expect(report.unlisted).toEqual([{ path: "many.txt", item: "API_KEY", versionId: "ver_api", retiring: false, count: 5 }]);
    expect(scanExitCode(report)).toBe(1);
    const human = formatScanHuman(report, { environment: "dev", mode: "paths" });
    expect(human.join("\n")).toContain(`${MAX_LISTED_PER_FILE + 5} finding(s) in 1 file(s)`);
  });
});

describe("sizes", () => {
  it("parses byte sizes with binary suffixes", () => {
    expect(parseSize("64M")).toBe(64 * 2 ** 20);
    expect(parseSize("1G")).toBe(2 ** 30);
    expect(parseSize("512k")).toBe(512 * 1024);
    expect(parseSize("2MiB")).toBe(2 * 2 ** 20);
    expect(parseSize("1000")).toBe(1000);
    for (const bad of ["", "0", "-1", "1.5M", "M", "10T"]) expect(parseSize(bad), bad).toBeNull();
  });
});
