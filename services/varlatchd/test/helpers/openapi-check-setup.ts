// SPDX-License-Identifier: AGPL-3.0-or-later
import { appendFileSync } from "node:fs";
import { join } from "node:path";
import { threadId } from "node:worker_threads";
import { afterAll, afterEach, expect, inject, vi } from "vitest";
import { inspect, openApiCheckMode, type Exchange, type Mismatch } from "./openapi-check.js";

/**
 * Every app a test builds checks its /v1 traffic against openapi.yaml
 * (openapi-check.ts). buildApp() is wrapped here, in the test runner only:
 * the server code has no hook for it. The wrapper replaces the app's fetch,
 * which app.request() and real listeners both call.
 *
 * VARLATCH_OPENAPI_CHECK=enforce (the default) fails a test whose traffic
 * did not match the spec; collect records without failing; off skips the
 * check. Either way the run's exchanges and mismatches are written for the
 * report that openapi-report.ts prints at the end of the run.
 */

const mode = openApiCheckMode();
let pending: Mismatch[] = [];
const exchanges: Exchange[] = [];
const recorded: (Mismatch & { test: string })[] = [];

vi.mock(import("../../src/http/app.js"), async (importOriginal) => {
  const original = await importOriginal();
  if (openApiCheckMode() === "off") return original;
  return {
    ...original,
    buildApp: ((...args: Parameters<typeof original.buildApp>) => {
      const app = original.buildApp(...args);
      const fetch = app.fetch;
      app.fetch = (async (request: Request, ...rest: unknown[]) => {
        const pathname = new URL(request.url).pathname;
        const checked = pathname === "/v1" || pathname.startsWith("/v1/");
        const requestText = checked && request.body !== null ? await request.clone().text() : null;
        const response = await (fetch as (r: Request, ...x: unknown[]) => Response | Promise<Response>)(request, ...rest);
        if (checked) {
          const { exchange, mismatches } = await inspect(request, requestText, response);
          if (exchange) exchanges.push(exchange);
          const test = expect.getState().currentTestName ?? "(outside a test)";
          for (const m of mismatches) recorded.push({ ...m, test });
          pending.push(...mismatches);
        }
        return response;
      }) as typeof app.fetch;
      return app;
    }) as typeof original.buildApp,
  };
});

afterEach(() => {
  const found = pending;
  pending = [];
  if (mode !== "enforce") return;
  expect(
    found.map((m) => `${m.kind}: ${m.operation} ${m.status}: ${m.detail}`),
    "/v1 traffic that does not match packages/protocol/openapi.yaml (test/helpers/openapi-check.ts)",
  ).toEqual([]);
});

afterAll(() => {
  if (mode === "off") return;
  const dir = inject("openApiReportDir");
  if (!dir) return;
  const file = join(dir, `${process.pid}-${threadId}.jsonl`);
  const testFile = expect.getState().testPath ?? "";
  const lines = [
    ...exchanges.map((e) => JSON.stringify({ type: "exchange", ...e })),
    ...recorded.map((m) => JSON.stringify({ type: "mismatch", file: testFile, ...m })),
  ];
  if (lines.length) appendFileSync(file, lines.join("\n") + "\n");
});
