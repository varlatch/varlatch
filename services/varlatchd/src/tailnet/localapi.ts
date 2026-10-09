// SPDX-License-Identifier: AGPL-3.0-or-later
import http from "node:http";

/**
 * One GET against the tailscaled LocalAPI on its unix socket. Any HTTP
 * status resolves with the whole body. Rejects on a socket error, on an
 * answer that ends before its body does, and once `timeoutMs` has passed
 * since the call, whatever arrived by then: it always settles.
 */
export function localApiGet(socketPath: string, path: string, timeoutMs = 3000): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request({
      socketPath,
      path,
      method: "GET",
      // LocalAPI requires this literal host; no DNS lookup happens.
      headers: { Host: "local-tailscaled.sock" },
    });
    let late = false;
    const deadline = setTimeout(() => {
      late = true;
      req.destroy(new Error("LocalAPI timeout"));
    }, timeoutMs);
    const fail = (err: Error) => {
      clearTimeout(deadline);
      reject(err);
    };
    req.on("error", fail);
    req.on("response", (res) => {
      let body = "";
      res.on("data", (chunk: Buffer) => (body += chunk.toString("utf8")));
      const cut = () => fail(new Error(late ? "LocalAPI timeout" : "LocalAPI answer ended early"));
      res.on("error", cut);
      res.on("end", () => {
        clearTimeout(deadline);
        resolve({ status: res.statusCode ?? 0, body });
      });
      res.on("close", () => {
        if (!res.complete) cut();
      });
    });
    req.end();
  });
}
