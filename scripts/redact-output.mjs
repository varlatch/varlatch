#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copies stdin to stdout line by line, with every Varlatch token masked
// (redact-tokens.mjs). scripts/ci-shell.sh puts it after the end-to-end
// suites in CI, whose logs are public.
import { createInterface } from "node:readline";
import { redactTokens } from "./redact-tokens.mjs";

for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  process.stdout.write(`${redactTokens(line)}\n`);
}
