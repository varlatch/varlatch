// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Minimal backup-control client: `node dist/control-entry.js <command>` with
 * the JSON input on stdin, output identical to `varlatchd admin
 * backup-control <command>`. The full CLI loads the whole daemon's module
 * graph first — about 0.8 s of CPU per call, measured on a 1-CPU budget,
 * taken from the running daemon's requests during every backup (ADR-0036
 * measurements). This file imports only Node built-ins.
 *
 * `prepare-restore` runs offline before the daemon starts and stays on the
 * full CLI.
 */
import { request } from "node:http";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const command = process.argv[2] ?? "";
const dir = process.env.VARLATCH_STATE_DIR ?? "/var/lib/varlatch";
const input = JSON.parse(readFileSync(0, "utf8") || "{}") as Record<string, unknown>;

function fail(message: string): void {
  console.log(JSON.stringify({ error: message }));
  process.exitCode = 1;
}

if (!command || command === "prepare-restore") {
  fail("Use `varlatchd admin backup-control` for this command");
} else {
  const req = request({ socketPath: join(dir, "backup.sock"), path: "/", method: "POST" }, (res) => {
    let text = "";
    res.on("data", (chunk) => { text += String(chunk); });
    res.on("end", () => {
      try {
        const value = JSON.parse(text) as { error?: string };
        if (res.statusCode !== 200) fail(value.error ?? "Backup control failed");
        else console.log(JSON.stringify(value));
      } catch { fail("Invalid backup control response"); }
    });
  });
  req.on("error", () => fail("Backup supervisor is not running"));
  req.end(JSON.stringify({ ...input, command }));
}
