// SPDX-License-Identifier: Apache-2.0
// ADR-0033: shared gate enforcement outside Convex's replaceable database.
// The pinned backend image includes Node. No Docker socket/admin key is exposed.
const fs = require('node:fs');
const http = require('node:http');
const { spawn } = require('node:child_process');
const state = process.env.VARLATCH_STATE_DIR || '/var/lib/varlatch';
if ((process.env.DATA_DIR && process.env.DATA_DIR !== '/convex/data') ||
    (process.env.STORAGE_DIR && process.env.STORAGE_DIR !== '/convex/data/storage') ||
    Object.keys(process.env).some(name => name.startsWith('S3_STORAGE_') && process.env[name])) {
  throw Error('Installation backup requires the canonical Convex local storage layout');
}
// Per-service secret files (#28): on Coolify every environment variable
// reaches every service, so the instance secret and database password may
// arrive as files mounted only here. A set variable wins; an empty file (the
// unconfigured default) changes nothing.
function secretFile(name) {
  try { return fs.readFileSync(`/run/secrets/${name}`, 'utf8').replace(/\r?\n$/, ''); } catch { return ''; }
}
const childEnv = { ...process.env };
if (!childEnv.INSTANCE_SECRET) childEnv.INSTANCE_SECRET = secretFile('convex-instance-secret');
if (childEnv.POSTGRES_URL) {
  const url = new URL(childEnv.POSTGRES_URL);
  const password = secretFile('convex-db-password');
  if (!url.password && password) { url.password = encodeURIComponent(password); childEnv.POSTGRES_URL = url.toString(); }
}
// Without one, Convex's own startup would invent a random secret and
// silently invalidate every admin key: refuse instead.
if (!childEnv.INSTANCE_SECRET) throw Error('No Convex instance secret: set CONVEX_INSTANCE_SECRET or provide the convex-instance-secret file');
let child = null, stopping = false, shuttingDown = false;
const sockets = new Set();
function gate() {
  try {
    const g = JSON.parse(fs.readFileSync(`${state}/maintenance.json`, 'utf8'));
    if (!g.id || !['capture', 'restore'].includes(g.kind)) throw Error('invalid gate');
    if (g.kind === 'capture' && Number.isFinite(g.expiresAt) && g.expiresAt <= Date.now()) return null;
    return g;
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    return { id: 'invalid', kind: 'restore', phase: 'paused' }; // fail closed
  }
}
function privateScript() {
  const original = fs.readFileSync('/convex/run_backend.sh', 'utf8');
  if (!original.includes('--port 3210') || !original.includes('--site-proxy-port 3211')) throw Error('Unsupported Convex entrypoint');
  const script = original.replace('--port 3210', '--port 3220').replace('--site-proxy-port 3211', '--site-proxy-port 3221');
  fs.writeFileSync('/tmp/varlatch-convex-backend.sh', script, { mode: 0o700 });
}
function tick() {
  const g = gate();
  const paused = g && g.phase !== 'draining' && g.phase !== 'reconciling';
  if (paused || shuttingDown) {
    if (child && !stopping) {
      for (const socket of sockets) socket.destroy();
      stopping = true;
      const current = child;
      current.kill('SIGTERM');
      const kill = setTimeout(() => current.kill('SIGKILL'), 10_000);
      current.once('exit', () => clearTimeout(kill));
    }
    if (!child && g) {
      const temp = `${state}/convex-ack.tmp`;
      fs.writeFileSync(temp, JSON.stringify({ id: g.id, stopped: true }));
      fs.renameSync(temp, `${state}/convex-ack.json`);
    }
  } else if (!child && !stopping) {
    child = spawn('bash', ['/tmp/varlatch-convex-backend.sh'], { cwd: '/convex', stdio: 'inherit', env: childEnv });
    child.once('error', () => { child = null; stopping = false; });
    child.once('exit', () => { child = null; stopping = false; if (shuttingDown) process.exit(0); });
  }
}
function proxy(port, backendPort) {
  const server = http.createServer((req, res) => {
    const g = gate();
    // During drain/reconciliation only the signed, narrow mirror publisher may mutate.
    // Convex validates the JWT and mirror role; the proxy merely limits routes/payloads.
    if (g && (g.phase === 'draining' || g.phase === 'reconciling') && port === 3210 && req.url === '/version') {
      return forward(req, res, backendPort);
    }
    if (g && (g.phase === 'draining' || g.phase === 'reconciling') && port === 3210 && req.url === '/api/mutation' && req.method === 'POST') {
      let body = '';
      req.on('error', () => res.destroy());
      req.on('data', c => { body += c; if (body.length > 1024 * 1024) req.destroy(); });
      req.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          if (!['mirror:upsert', 'mirror:remove'].includes(parsed.path)) throw Error();
          forward(req, res, backendPort, body);
        } catch { res.writeHead(503); res.end('Installation maintenance'); }
      });
      return;
    }
    if (g) { res.writeHead(503, { 'Retry-After': '5' }); res.end('Installation maintenance'); return; }
    forward(req, res, backendPort);
  });
  server.on('connection', s => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
  server.on('upgrade', (req, socket, head) => {
    // After 'upgrade' the http server no longer handles this socket's errors:
    // a client reset (tab closed, network drop, a one-shot CLI exiting) must
    // close this connection, never crash the supervisor (unhandled ECONNRESET
    // restarted convex-backend and dropped every dashboard's live connection).
    socket.on('error', () => socket.destroy());
    if (gate()) { socket.destroy(); return; }
    const upstream = http.request({ hostname: '127.0.0.1', port: backendPort, path: req.url, headers: req.headers });
    upstream.on('upgrade', (response, remote, remoteHead) => {
      socket.write(`HTTP/1.1 ${response.statusCode} ${response.statusMessage}\r\n${Object.entries(response.headers).map(([k,v]) => `${k}: ${v}\r\n`).join('')}\r\n`);
      if (head.length) remote.write(head); if (remoteHead.length) socket.write(remoteHead);
      remote.pipe(socket); socket.pipe(remote);
      socket.on('close', () => remote.destroy()); remote.on('error', () => socket.destroy());
    });
    upstream.on('error', () => socket.destroy()); upstream.end();
  });
  server.listen(port, '0.0.0.0');
}
function forward(req, res, port, body) {
  const upstream = http.request({ hostname: '127.0.0.1', port, method: req.method, path: req.url, headers: req.headers }, response => {
    res.writeHead(response.statusCode, response.headers); response.pipe(res);
  });
  upstream.on('error', () => { if (!res.headersSent) res.writeHead(503); res.end(); });
  req.on('aborted', () => upstream.destroy());
  req.on('error', () => upstream.destroy());
  res.on('error', () => upstream.destroy());
  if (body !== undefined) upstream.end(body); else req.pipe(upstream);
}
privateScript(); proxy(3210, 3220); proxy(3211, 3221); tick();
setInterval(tick, 100);
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => { shuttingDown = true; tick(); if (!child) process.exit(0); });
