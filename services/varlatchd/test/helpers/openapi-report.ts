// SPDX-License-Identifier: AGPL-3.0-or-later
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import type { TestProject } from "vitest/node";
import { openApiCheckMode, specOperations, type Mismatch } from "./openapi-check.js";

/**
 * Vitest global setup for the OpenAPI check (openapi-check.ts). Each test
 * file's worker appends the /v1 exchanges it saw and any mismatches to a
 * file in a directory this setup provides; at the end of the run they are
 * summed up:
 *
 * - mismatches by kind and operation (in collect mode the only place they
 *   show; in enforce mode the failing tests show them too);
 * - the spec operations no test exercised, and those exercised only with
 *   errors, which nothing here checked a success body for. Only a run of
 *   the whole suite (CI) makes that list meaningful.
 *
 * VARLATCH_OPENAPI_REPORT=<file> also writes the full report as JSON.
 */
export default async function setup(project: TestProject): Promise<() => Promise<void>> {
  if (openApiCheckMode() === "off") {
    project.provide("openApiReportDir", "");
    return async () => {};
  }
  const dir = await mkdtemp(join(tmpdir(), "varlatch-openapi-"));
  project.provide("openApiReportDir", dir);
  return async () => {
    try {
      await report(dir);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  };
}

type Line =
  | { type: "exchange"; operation: string; status: number }
  | ({ type: "mismatch"; file: string; test: string } & Mismatch);

async function report(dir: string): Promise<void> {
  const lines: Line[] = [];
  for (const name of await readdir(dir)) {
    for (const raw of (await readFile(join(dir, name), "utf8")).split("\n")) {
      if (raw) lines.push(JSON.parse(raw) as Line);
    }
  }
  if (lines.length === 0) return;
  const statuses = new Map<string, Set<number>>();
  const mismatches = new Map<string, { kind: string; operation: string; status: number; detail: string; count: number; tests: Set<string> }>();
  for (const line of lines) {
    if (line.type === "exchange") {
      let set = statuses.get(line.operation);
      if (!set) statuses.set(line.operation, (set = new Set()));
      set.add(line.status);
    } else {
      const key = `${line.kind}|${line.operation}|${line.status}|${line.detail}`;
      let m = mismatches.get(key);
      if (!m) mismatches.set(key, (m = { kind: line.kind, operation: line.operation, status: line.status, detail: line.detail, count: 0, tests: new Set() }));
      m.count++;
      m.tests.add(`${relative(process.cwd(), line.file)} > ${line.test}`);
    }
  }
  const all = specOperations();
  const never = all.filter((op) => !statuses.has(op)).sort();
  const errorsOnly = all.filter((op) => {
    const s = statuses.get(op);
    return s && ![...s].some((x) => x >= 200 && x < 300);
  }).sort();
  const byKind = new Map<string, number>();
  for (const m of mismatches.values()) byKind.set(m.kind, (byKind.get(m.kind) ?? 0) + 1);

  const out: string[] = [];
  out.push(
    `OpenAPI check (${openApiCheckMode()}): ${lines.filter((l) => l.type === "exchange").length} /v1 exchanges, ` +
      `${all.length - never.length} of ${all.length} operations exercised, ${errorsOnly.length} only with errors; ` +
      `${mismatches.size} distinct mismatches` +
      (byKind.size ? ` (${[...byKind].map(([k, n]) => `${k} ${n}`).join(", ")})` : ""),
  );
  for (const m of [...mismatches.values()].sort((a, b) => a.kind.localeCompare(b.kind) || a.operation.localeCompare(b.operation))) {
    out.push(`  ${m.kind}: ${m.operation} ${m.status} x${m.count}: ${m.detail}`);
  }
  if (process.env.CI || process.env.VARLATCH_OPENAPI_REPORT) {
    out.push(`Operations no test exercised (${never.length}):`, ...never.map((op) => `  ${op}`));
    out.push(`Operations exercised only with errors (${errorsOnly.length}):`, ...errorsOnly.map((op) => `  ${op} ${[...statuses.get(op)!].sort().join(",")}`));
  }
  console.log(out.join("\n"));
  const file = process.env.VARLATCH_OPENAPI_REPORT;
  if (file) {
    await writeFile(
      file,
      JSON.stringify(
        {
          mode: openApiCheckMode(),
          operations: all.length,
          exercised: Object.fromEntries([...statuses].sort().map(([op, s]) => [op, [...s].sort()])),
          neverExercised: never,
          errorsOnly,
          mismatches: [...mismatches.values()].map((m) => ({ ...m, tests: [...m.tests].sort() })),
        },
        null,
        2,
      ) + "\n",
    );
  }
}

declare module "vitest" {
  export interface ProvidedContext {
    openApiReportDir: string;
  }
}
