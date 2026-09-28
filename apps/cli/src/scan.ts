// SPDX-License-Identifier: Apache-2.0
import { MIN_LENGTH, StreamScanner, type FormName } from "@varlatch/matcher";

/**
 * Local secret scanning: the engine behind `varlatch scan` (ADR-0038
 * Decision 14).
 *
 * - Content is streamed through the shared matcher (`@varlatch/matcher`),
 *   one file at a time, as bytes: binary files are scanned like text, and a
 *   value that spans lines (a PEM key) is found because matching runs across
 *   the whole file. Offsets are mapped back to a line and a byte column
 *   while streaming, keeping only the newline positions a later occurrence
 *   can still need.
 * - Only complete occurrences are findings. A file that ends with the start
 *   of a Secret is counted, without a location, and is not a finding.
 * - A finding names the file, line, column, item, version, and form. It
 *   never carries the value, a fragment of it, or anything else from the
 *   matched line, so a second Secret on that line cannot leak through it.
 * - A file that is skipped or cannot be read is reported as not scanned,
 *   never as clean.
 * - False positives: an inline `varlatch:allow NAME` marker on a line the
 *   occurrence touches, or a baseline entry (path, item, version). Neither
 *   holds anything derived from the value.
 */

/** One value to look for: a Secret's current or retiring version. */
export interface ScanSecret {
  item: string;
  versionId: string;
  retiring: boolean;
  value: string;
}

export interface Finding {
  /** Relative to the directory holding varlatch.toml, with `/` separators. */
  path: string;
  line: number;
  /** 1-based, counted in bytes from the start of the line. */
  column: number;
  /** Byte offset from the start of the file. */
  offset: number;
  item: string;
  versionId: string;
  retiring: boolean;
  form: FormName;
}

export interface AllowedFinding extends Finding {
  allowedBy: "marker" | "baseline";
}

export interface NotScanned {
  path: string;
  reason: string;
}

/** Occurrences beyond the per-file listing limit: counted by item and version, not located. */
export interface Unlisted {
  path: string;
  item: string;
  versionId: string;
  retiring: boolean;
  count: number;
}

export interface BaselineEntry {
  path: string;
  item: string;
  versionId: string;
}

export interface ScanReport {
  findings: Finding[];
  unlisted: Unlisted[];
  allowed: AllowedFinding[];
  notScanned: NotScanned[];
  /** Items with a value shorter than the matcher's minimum length; not checked. */
  skippedItems: string[];
  /** Secret versions checked (a rotating item counts twice). */
  valuesChecked: number;
  filesScanned: number;
  bytesScanned: number;
  /** Files that end with at least MIN_LENGTH bytes of a Secret's start and hold no complete occurrence of it there. */
  incompletePrefixes: number;
}

export interface ScanLimits {
  maxFileSize: number;
  maxTotalSize: number;
}

export const DEFAULT_LIMITS: ScanLimits = { maxFileSize: 64 * 2 ** 20, maxTotalSize: 2 ** 30 };

/** Detailed findings kept per file; further occurrences are counted per item and version. */
export const MAX_LISTED_PER_FILE = 1000;
/** Allow markers kept per file; further markers are ignored, which can only add findings. */
const MAX_MARKERS_PER_FILE = 10_000;

const MARKER = Buffer.from("varlatch:allow", "latin1");
const MAX_GAP = 16;
const MAX_NAME = 256;
/** Bytes a partly seen marker can span: the marker, its gap, a name, and the byte after it. */
const MARKER_SPAN = MARKER.length + MAX_GAP + MAX_NAME + 1;

function isUpper(b: number): boolean {
  return b >= 0x41 && b <= 0x5a;
}
function isNameByte(b: number): boolean {
  return isUpper(b) || (b >= 0x30 && b <= 0x39) || b === 0x5f;
}
function isWordByte(b: number): boolean {
  return isNameByte(b) || (b >= 0x61 && b <= 0x7a);
}

/**
 * Newline positions near the end of the stream, enough to locate any
 * offset at or after `keepFrom`.
 */
class LineIndex {
  private newlines: number[] = [];
  private head = 0;
  private before = 0;
  private lastPruned = -1;

  feed(chunk: Uint8Array, base: number): void {
    const buf = Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    for (let i = buf.indexOf(10); i >= 0; i = buf.indexOf(10, i + 1)) this.newlines.push(base + i);
  }

  prune(keepFrom: number): void {
    while (this.head < this.newlines.length && this.newlines[this.head]! < keepFrom) {
      this.lastPruned = this.newlines[this.head]!;
      this.before++;
      this.head++;
    }
    if (this.head > 4096 && this.head * 2 > this.newlines.length) {
      this.newlines = this.newlines.slice(this.head);
      this.head = 0;
    }
  }

  /** 1-based line and byte column of `offset`. */
  locate(offset: number): { line: number; column: number } {
    let lo = this.head;
    let hi = this.newlines.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (this.newlines[mid]! < offset) lo = mid + 1;
      else hi = mid;
    }
    const previous = lo > this.head ? this.newlines[lo - 1]! : this.lastPruned;
    return { line: this.before + (lo - this.head) + 1, column: offset - previous };
  }
}

/** Finds `varlatch:allow NAME` markers in a byte stream, including across chunks. */
class MarkerFinder {
  private carry: Buffer = Buffer.alloc(0);

  /** Markers completed in this chunk, by offset and name. */
  feed(chunk: Uint8Array, base: number, final: boolean): { offset: number; name: string }[] {
    const data = this.carry.length > 0 ? Buffer.concat([this.carry, chunk]) : Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    const dataBase = base - this.carry.length;
    const found: { offset: number; name: string }[] = [];
    let from = 0;
    let resume = -1;
    for (let at = data.indexOf(MARKER, from); at >= 0; at = data.indexOf(MARKER, from)) {
      const gapStart = at + MARKER.length;
      let gapEnd = gapStart;
      while (gapEnd < data.length && gapEnd - gapStart <= MAX_GAP && (data[gapEnd] === 0x20 || data[gapEnd] === 0x09)) gapEnd++;
      if (gapEnd === data.length && !final) {
        resume = at;
        break;
      }
      let nameEnd = gapEnd;
      if (gapEnd > gapStart && gapEnd - gapStart <= MAX_GAP && gapEnd < data.length && isUpper(data[gapEnd]!)) {
        while (nameEnd < data.length && nameEnd - gapEnd <= MAX_NAME && isNameByte(data[nameEnd]!)) nameEnd++;
        if (nameEnd === data.length && !final) {
          resume = at;
          break;
        }
        const bounded = nameEnd - gapEnd <= MAX_NAME;
        const terminated = nameEnd === data.length || !isWordByte(data[nameEnd]!);
        if (bounded && terminated) {
          found.push({ offset: dataBase + at, name: data.toString("latin1", gapEnd, nameEnd) });
          from = nameEnd;
          continue;
        }
      }
      from = at + 1;
    }
    if (final) this.carry = Buffer.alloc(0);
    else if (resume >= 0) this.carry = Buffer.from(data.subarray(resume));
    else this.carry = Buffer.from(data.subarray(Math.max(0, data.length - (MARKER.length - 1))));
    return found;
  }
}

interface Occ {
  entry: number;
  form: FormName;
  start: number;
  line: number;
  column: number;
  endLine: number;
}

/** One file being scanned. Created by `ScanEngine.begin`. */
export class FileScan {
  private readonly lines = new LineIndex();
  private readonly markers = new MarkerFinder();
  private readonly allow = new Map<number, Set<string>>();
  private markerCount = 0;
  private readonly occurrences: Occ[] = [];
  private readonly unlisted = new Map<number, number>();
  private bytes = 0;
  private done = false;

  constructor(
    private readonly engine: ScanEngine,
    private readonly scanner: StreamScanner,
    readonly path: string,
    private readonly window: number,
  ) {}

  /** Feed the next chunk. False when the file went over the per-file bound: stop reading and call `fail`. */
  push(chunk: Uint8Array): boolean {
    if (this.done) throw new Error("file scan already finished");
    if (this.bytes + chunk.length > this.engine.limits.maxFileSize) return false;
    const base = this.bytes;
    this.bytes += chunk.length;
    this.lines.feed(chunk, base);
    this.collectMarkers(this.markers.feed(chunk, base, false));
    for (const o of this.scanner.push(chunk)) {
      const listed = this.occurrences.length < MAX_LISTED_PER_FILE;
      if (!listed) {
        this.unlisted.set(o.entry, (this.unlisted.get(o.entry) ?? 0) + 1);
        continue;
      }
      const at = this.lines.locate(o.start);
      const endLine = this.lines.locate(o.end - 1).line;
      this.occurrences.push({ entry: o.entry, form: o.form, start: o.start, line: at.line, column: at.column, endLine });
    }
    // Any later occurrence or marker starts after this point.
    this.lines.prune(this.bytes - this.window);
    return true;
  }

  /** The file ended cleanly. */
  end(): void {
    if (this.done) throw new Error("file scan already finished");
    this.done = true;
    this.collectMarkers(this.markers.feed(new Uint8Array(0), this.bytes, true));
    const end = this.scanner.end();
    const prefix = end.incompletePrefix;
    this.engine.finish(this, this.bytes, prefix !== null && prefix.length >= MIN_LENGTH);
  }

  /**
   * The file could not be read to its end. What was found so far is still
   * reported, and the file is reported as not scanned.
   */
  fail(reason: string): void {
    if (this.done) throw new Error("file scan already finished");
    this.done = true;
    this.engine.finish(this, this.bytes, false, reason);
  }

  /** @internal */
  results(): { occurrences: Occ[]; unlisted: Map<number, number>; allowedBy: (o: Occ, item: string) => boolean } {
    return {
      occurrences: this.occurrences,
      unlisted: this.unlisted,
      allowedBy: (o, item) => {
        for (let line = o.line; line <= o.endLine; line++) {
          if (this.allow.get(line)?.has(item)) return true;
        }
        return false;
      },
    };
  }

  private collectMarkers(found: { offset: number; name: string }[]): void {
    for (const { offset, name } of found) {
      if (this.markerCount >= MAX_MARKERS_PER_FILE) return;
      this.markerCount++;
      const line = this.lines.locate(offset).line;
      let names = this.allow.get(line);
      if (!names) this.allow.set(line, (names = new Set()));
      names.add(name);
    }
  }
}

export class ScanEngine {
  readonly limits: ScanLimits;
  /** Item, version, and phase per registered entry; the values live only in the matcher. */
  private readonly secrets: Omit<ScanSecret, "value">[];
  private readonly scanner: StreamScanner;
  private readonly baseline: Set<string>;
  private open: FileScan | null = null;
  private readonly report: ScanReport;
  private readonly window: number;

  constructor(secrets: ScanSecret[], opts: { limits?: ScanLimits; baseline?: BaselineEntry[] } = {}) {
    this.limits = opts.limits ?? DEFAULT_LIMITS;
    // A retiring value equal to the current one is the same bytes: check it once.
    const seen = new Set<string>();
    const unique = secrets.filter((s) => {
      const key = `${s.item}\u0000${s.value}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    this.scanner = new StreamScanner(unique.map((s) => ({ item: s.item, value: s.value })));
    this.secrets = unique.map(({ item, versionId, retiring }) => ({ item, versionId, retiring }));
    this.window = Math.max(this.scanner.maxLength, MARKER_SPAN) + 1;
    this.baseline = new Set((opts.baseline ?? []).map(baselineKey));
    this.report = {
      findings: [],
      unlisted: [],
      allowed: [],
      notScanned: [],
      skippedItems: [...new Set(this.scanner.skipped)].sort(),
      valuesChecked: this.secrets.length - this.scanner.skippedEntries.length,
      filesScanned: 0,
      bytesScanned: 0,
      incompletePrefixes: 0,
    };
  }

  /** Whether any value is registered at all; if not, reading files cannot find anything. */
  get checksAnything(): boolean {
    return this.report.valuesChecked > 0;
  }

  /**
   * Decide whether a file of `size` bytes is read. A file over the per-file
   * bound, or one that no longer fits in the total bound, is recorded as
   * not scanned and false is returned.
   */
  admit(path: string, size: number): boolean {
    if (size > this.limits.maxFileSize) {
      this.notScanned(path, `larger than the per-file bound (${formatBytes(size)} > ${formatBytes(this.limits.maxFileSize)})`);
      return false;
    }
    if (this.report.bytesScanned + size > this.limits.maxTotalSize) {
      this.notScanned(path, `over the total size bound of ${formatBytes(this.limits.maxTotalSize)}`);
      return false;
    }
    return true;
  }

  notScanned(path: string, reason: string): void {
    this.report.notScanned.push({ path, reason });
  }

  /** Start reading a file. Only one file is open at a time. */
  begin(path: string): FileScan {
    if (this.open) throw new Error(`still scanning ${this.open.path}`);
    this.scanner.reset();
    this.open = new FileScan(this, this.scanner, path, this.window);
    return this.open;
  }

  /** @internal Called by FileScan. */
  finish(file: FileScan, bytes: number, incompletePrefix: boolean, failure?: string): void {
    if (this.open !== file) throw new Error("not the open file");
    this.open = null;
    this.report.bytesScanned += bytes;
    if (failure !== undefined) this.notScanned(file.path, failure);
    else this.report.filesScanned++;
    if (incompletePrefix) this.report.incompletePrefixes++;
    const { occurrences, unlisted, allowedBy } = file.results();
    // Found in the order they end; listed in the order they start.
    const ordered = [...occurrences].sort((a, b) => a.start - b.start || a.entry - b.entry);
    for (const o of ordered) {
      const secret = this.secrets[o.entry]!;
      const finding: Finding = {
        path: file.path,
        line: o.line,
        column: o.column,
        offset: o.start,
        item: secret.item,
        versionId: secret.versionId,
        retiring: secret.retiring,
        form: o.form,
      };
      if (allowedBy(o, secret.item)) this.report.allowed.push({ ...finding, allowedBy: "marker" });
      else if (this.baseline.has(baselineKey(finding))) this.report.allowed.push({ ...finding, allowedBy: "baseline" });
      else this.report.findings.push(finding);
    }
    for (const [entry, count] of unlisted) {
      const secret = this.secrets[entry]!;
      const u = { path: file.path, item: secret.item, versionId: secret.versionId, retiring: secret.retiring, count };
      // Unlisted occurrences have no location, so only the baseline can allow them.
      if (!this.baseline.has(baselineKey(u))) this.report.unlisted.push(u);
    }
  }

  result(): ScanReport {
    if (this.open) throw new Error(`still scanning ${this.open.path}`);
    return this.report;
  }
}

function baselineKey(e: { path: string; item: string; versionId: string }): string {
  return JSON.stringify([e.path, e.item, e.versionId]);
}

export function formatBytes(n: number): string {
  for (const [unit, size] of [
    ["GiB", 2 ** 30],
    ["MiB", 2 ** 20],
    ["KiB", 2 ** 10],
  ] as const) {
    if (n >= size && n % size === 0) return `${n / size} ${unit}`;
  }
  return n >= 2 ** 20 ? `${(n / 2 ** 20).toFixed(1)} MiB` : `${n} bytes`;
}

/** `64M`, `1G`, `512K`, or a plain number of bytes. */
export function parseSize(text: string): number | null {
  const m = /^(\d+)([KMG]?)(i?B)?$/i.exec(text.trim());
  if (!m) return null;
  const unit = { "": 1, K: 2 ** 10, M: 2 ** 20, G: 2 ** 30 }[m[2]!.toUpperCase() as "" | "K" | "M" | "G"];
  const n = Number(m[1]) * unit;
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

// ---- Baseline ----------------------------------------------------------------

export const BASELINE_FILE = "varlatch-scan-baseline.json";

export class BaselineError extends Error {
  override name = "BaselineError";
}

/**
 * Parse a baseline file. It holds path, item name, and version ID per entry
 * and nothing else: any other field is refused, so nothing derived from a
 * value can be kept in it.
 */
export function parseBaseline(text: string): BaselineEntry[] {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (err) {
    throw new BaselineError(`not valid JSON (${err instanceof Error ? err.message : String(err)})`);
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) throw new BaselineError("expected an object");
  const keys = Object.keys(doc).sort();
  if (keys.join(",") !== "entries,version") throw new BaselineError('expected exactly the fields "version" and "entries"');
  const { version, entries } = doc as { version: unknown; entries: unknown };
  if (version !== 1) throw new BaselineError(`unsupported version ${JSON.stringify(version)}; this CLI reads version 1`);
  if (!Array.isArray(entries)) throw new BaselineError('"entries" must be an array');
  return entries.map((entry, i) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new BaselineError(`entry ${i + 1} must be an object`);
    const fields = Object.keys(entry).sort();
    if (fields.join(",") !== "item,path,versionId") {
      throw new BaselineError(`entry ${i + 1} must have exactly "path", "item", and "versionId"`);
    }
    const { path, item, versionId } = entry as Record<string, unknown>;
    if (typeof path !== "string" || path === "" || typeof item !== "string" || item === "" || typeof versionId !== "string" || versionId === "") {
      throw new BaselineError(`entry ${i + 1}: "path", "item", and "versionId" must be non-empty strings`);
    }
    return { path, item, versionId };
  });
}

/** The baseline file's text: entries deduplicated and sorted. */
export function formatBaseline(entries: BaselineEntry[]): string {
  const unique = new Map(entries.map((e) => [baselineKey(e), { path: e.path, item: e.item, versionId: e.versionId }]));
  const sorted = [...unique.values()].sort(
    (a, b) => cmp(a.path, b.path) || cmp(a.item, b.item) || cmp(a.versionId, b.versionId),
  );
  return `${JSON.stringify({ version: 1, entries: sorted }, null, 2)}\n`;
}

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Baseline entries for everything a report found (listed or not). */
export function baselineEntriesOf(report: ScanReport): BaselineEntry[] {
  return [
    ...report.findings.map((f) => ({ path: f.path, item: f.item, versionId: f.versionId })),
    ...report.unlisted.map((u) => ({ path: u.path, item: u.item, versionId: u.versionId })),
  ];
}

// ---- Report ------------------------------------------------------------------

export const SCAN_REPORT_VERSION = 1;

/** 0 clean; 1 findings; 2 no findings, but not everything was scanned. */
export function scanExitCode(report: ScanReport): number {
  if (report.findings.length > 0 || report.unlisted.length > 0) return 1;
  return report.notScanned.length > 0 ? 2 : 0;
}

/** A path as shown on a terminal: control characters escaped, never interpreted. */
export function displayPath(path: string): string {
  // eslint-disable-next-line no-control-regex
  return /[\u0000-\u001f\u007f-\u009f]/.test(path) ? JSON.stringify(path) : path;
}

const FORM_TEXT: Record<FormName, string> = {
  raw: "as written",
  json: "JSON-escaped",
  percent: "percent-encoded",
  base64: "base64",
  base64url: "base64url",
};

/** The human report for stdout. Names, versions, and locations only. */
export function formatScanHuman(report: ScanReport, opts: { environment: string; mode: "staged" | "paths" }): string[] {
  const lines: string[] = [];
  const count = report.findings.length + report.unlisted.reduce((n, u) => n + u.count, 0);
  const files = new Set([...report.findings.map((f) => f.path), ...report.unlisted.map((u) => u.path)]);
  for (const f of report.findings) {
    lines.push(
      `${displayPath(f.path)}:${f.line}:${f.column}: ${f.item} (version ${f.versionId}${f.retiring ? ", retiring" : ""}), ${FORM_TEXT[f.form]}`,
    );
  }
  for (const u of report.unlisted) {
    lines.push(
      `${displayPath(u.path)}: ${u.count} more occurrence(s) of ${u.item} (version ${u.versionId}${u.retiring ? ", retiring" : ""}), not listed`,
    );
  }
  if (report.notScanned.length > 0) {
    if (lines.length > 0) lines.push("");
    lines.push(`Not scanned (${report.notScanned.length}), so not known to be clean:`);
    for (const n of report.notScanned) lines.push(`  ${displayPath(n.path)}: ${n.reason}`);
  }
  if (lines.length > 0) lines.push("");
  const what = opts.mode === "staged" ? "staged file" : "file";
  lines.push(
    `varlatch scan: ${report.filesScanned} ${what}(s) checked against ${report.valuesChecked} Secret value(s) of ${opts.environment}: ` +
      (count > 0 ? `${count} finding(s) in ${files.size} file(s).` : "no findings.") +
      (report.notScanned.length > 0 ? ` ${report.notScanned.length} not scanned.` : "") +
      (report.allowed.length > 0 ? ` ${report.allowed.length} allowed by a marker or the baseline.` : ""),
  );
  if (count > 0) lines.push("Values and line contents are never shown. Rotate a Secret that was committed or published.");
  return lines;
}

/** Notices for stderr: what was not checked, by name only. */
export function scanNotices(report: ScanReport): string[] {
  const notices: string[] = [];
  if (report.skippedItems.length > 0) {
    notices.push(
      `varlatch scan: values shorter than ${MIN_LENGTH} bytes are not checked: ${report.skippedItems.join(", ")}`,
    );
  }
  if (report.incompletePrefixes > 0) {
    notices.push(
      `varlatch scan: ${report.incompletePrefixes} file(s) end with the first ${MIN_LENGTH} or more bytes of a Secret ` +
        "but hold no complete occurrence there; that is not a finding",
    );
  }
  return notices;
}
