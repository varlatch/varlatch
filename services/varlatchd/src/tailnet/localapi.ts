// SPDX-License-Identifier: AGPL-3.0-or-later
import http from "node:http";

/**
 * One GET against the tailscaled LocalAPI on its unix socket. Rejects on a
 * socket error or after `timeoutMs`; any HTTP status resolves.
 */
export function localApiGet(socketPath: string, path: string, timeoutMs = 3000): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        socketPath,
        path,
        method: "GET",
        // LocalAPI requires this literal host; no DNS lookup happens.
        headers: { Host: "local-tailscaled.sock" },
        timeout: timeoutMs,
      },
      (res) => {
        let body = "";
        res.on("data", (chunk: Buffer) => (body += chunk.toString("utf8")));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
      },
    );
    req.on("timeout", () => req.destroy(new Error("LocalAPI timeout")));
    req.on("error", reject);
    req.end();
  });
}
