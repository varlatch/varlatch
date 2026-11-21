// SPDX-License-Identifier: Apache-2.0
/**
 * The oidc suite's issuer (the oidc-issuer capability): a local OIDC
 * issuer over https on 127.0.0.1, with a certificate the target's server
 * trusts. Standard library only, CommonJS, so it runs as a file or as
 * `node -e` inside the TypeScript server's container.
 *
 *   node oidc-issuer.cjs serve [<dir>] <cert dir> <port>
 *   node oidc-issuer.cjs control <cert file> <port> <method> <path> [<body>]
 *
 * serve: the issuer is https://127.0.0.1:<port>, with the key and
 * certificate in <cert dir> (key.pem, cert.pem). It answers
 *   GET /.well-known/openid-configuration  { issuer, jwks_uri }
 *   GET /jwks                              { keys } (none until set)
 *   PUT /_conformance/jwks                 sets the keys: { keys }
 *   GET /_conformance/counts               { discovery, jwks } fetched so far
 * With <dir>, it exits once <dir> is gone (its installation was removed),
 * and after two hours in any case.
 *
 * control: one request to a running issuer, trusting <cert file>; prints
 * the answer's body, exits 1 on a status other than 2xx.
 */
const https = require("node:https");
const fs = require("node:fs");
const path = require("node:path");

const args = process.argv.slice(1).filter((a) => !a.endsWith("oidc-issuer.cjs"));
const mode = args[0];

if (mode === "serve") {
  const rest = args.slice(1);
  const port = Number(rest[rest.length - 1]);
  const certDir = rest[rest.length - 2];
  const dir = rest.length >= 3 ? rest[rest.length - 3] : null;
  const issuer = `https://127.0.0.1:${port}`;
  const counts = { discovery: 0, jwks: 0 };
  let keys = [];
  const json = (res, status, body) => {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(body));
  };
  const server = https.createServer(
    { key: fs.readFileSync(path.join(certDir, "key.pem")), cert: fs.readFileSync(path.join(certDir, "cert.pem")) },
    (req, res) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        const url = req.url.split("?")[0];
        if (req.method === "GET" && url === "/.well-known/openid-configuration") {
          counts.discovery++;
          return json(res, 200, { issuer, jwks_uri: `${issuer}/jwks` });
        }
        if (req.method === "GET" && url === "/jwks") {
          counts.jwks++;
          return json(res, 200, { keys });
        }
        if (req.method === "PUT" && url === "/_conformance/jwks") {
          try {
            keys = JSON.parse(Buffer.concat(chunks).toString("utf8")).keys;
          } catch {
            return json(res, 400, { error: "not JSON" });
          }
          return json(res, 200, { keys: keys.length });
        }
        if (req.method === "GET" && url === "/_conformance/counts") return json(res, 200, counts);
        return json(res, 404, { error: "not found" });
      });
    },
  );
  // Its log (the harness keeps it beside the installation) says whether it
  // listened, or why not: a port taken by another socket, for one.
  server.on("error", (err) => {
    process.stderr.write(`oidc-issuer: cannot listen on 127.0.0.1:${port}: ${err.code || err.message}\n`);
    process.exit(1);
  });
  server.on("listening", () => process.stdout.write(`oidc-issuer: listening on 127.0.0.1:${port} at ${new Date().toISOString()}\n`));
  server.listen(port, "127.0.0.1");
  if (dir) {
    setInterval(() => {
      if (!fs.existsSync(dir)) process.exit(0);
    }, 5000).unref();
  }
  setTimeout(() => process.exit(0), 2 * 3600 * 1000).unref();
} else if (mode === "control") {
  const [, certFile, port, method, target, body] = args;
  const req = https.request(
    { host: "127.0.0.1", port: Number(port), method, path: target, ca: fs.readFileSync(certFile), headers: { "Content-Type": "application/json" }, timeout: 10_000 },
    (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        process.stdout.write(Buffer.concat(chunks).toString("utf8"));
        process.exit(res.statusCode >= 200 && res.statusCode < 300 ? 0 : 1);
      });
    },
  );
  req.on("error", (err) => {
    process.stderr.write(String(err));
    process.exit(2);
  });
  req.on("timeout", () => req.destroy(new Error("timed out")));
  if (body) req.write(body);
  req.end();
} else {
  process.stderr.write("Usage: oidc-issuer.cjs serve [<dir>] <cert dir> <port> | control <cert file> <port> <method> <path> [<body>]\n");
  process.exit(64);
}
