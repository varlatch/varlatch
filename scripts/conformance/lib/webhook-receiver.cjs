// SPDX-License-Identifier: Apache-2.0
/**
 * The webhooks suite's receiver (the webhook-receiver capability): a local
 * HTTP endpoint on 127.0.0.1 that records every request and answers it.
 * Standard library only, CommonJS, so it runs as a file or as `node -e`
 * inside the TypeScript server's container.
 *
 *   node webhook-receiver.cjs [<dir>] <port>
 *
 * The port is the last argument. A path with a segment fail-<n> answers
 * 500 to its first n requests, then 200; any other path, 200.
 * GET /_received answers every request recorded so far, oldest first:
 * { at, method, target, contentType, signature, body, status }.
 * With <dir>, it exits once <dir> is gone (its installation was removed),
 * and after two hours in any case.
 */
const http = require("node:http");
const fs = require("node:fs");

const args = process.argv.slice(1);
const port = Number(args[args.length - 1]);
const dir = args.length >= 2 && !args[args.length - 2].endsWith(".cjs") ? args[args.length - 2] : null;
const got = [];
const seen = new Map();

const server = http.createServer((req, res) => {
  const chunks = [];
  let size = 0;
  req.on("data", (c) => {
    size += c.length;
    if (size <= 4 * 1024 * 1024) chunks.push(c);
  });
  req.on("end", () => {
    if (req.method === "GET" && req.url === "/_received") {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify(got));
      return;
    }
    const path = req.url.split("?")[0];
    const n = (seen.get(path) ?? 0) + 1;
    seen.set(path, n);
    const fail = /\/fail-(\d+)(?:\/|$)/.exec(path);
    const status = fail && n <= Number(fail[1]) ? 500 : 200;
    got.push({
      at: Date.now(),
      method: req.method,
      target: req.url,
      contentType: req.headers["content-type"] ?? null,
      signature: req.headers["x-varlatch-signature"] ?? null,
      body: Buffer.concat(chunks).toString("utf8"),
      status,
    });
    res.statusCode = status;
    res.end();
  });
});
// Its log (the harness keeps it beside the installation) says whether it
// listened, or why not: a port taken by another socket, for one.
server.on("error", (err) => {
  process.stderr.write(`webhook-receiver: cannot listen on 127.0.0.1:${port}: ${err.code || err.message}\n`);
  process.exit(1);
});
server.on("listening", () => process.stdout.write(`webhook-receiver: listening on 127.0.0.1:${port} at ${new Date().toISOString()}\n`));
server.listen(port, "127.0.0.1");

const started = Date.now();
setInterval(() => {
  if ((dir && !fs.existsSync(dir)) || Date.now() - started > 2 * 60 * 60 * 1000) process.exit(0);
}, 5000).unref();
// The interval does not hold the process; the server does.
