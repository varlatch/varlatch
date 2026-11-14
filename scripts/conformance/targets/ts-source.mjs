// SPDX-License-Identifier: Apache-2.0
/**
 * Target `ts-source`: the TypeScript stack built from this checkout, as a
 * disposable Compose project (canonical infra/compose files, temporary
 * credentials, free loopback ports, its own volumes), removed on `down`.
 * The suites reach it through the dashboard's nginx, the one public origin
 * (ADR-0035 D5).
 *
 * Every operation runs `docker compose` against that project. The state an
 * operation needs (directory, project name, ports) is the JSON that `up`
 * returns; scripts/conformance/target-op.mjs reads it back for the suites.
 */
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { requestsFromNginxLog } from "./nginx-log.mjs";

export const name = "ts-source";

export const capabilities = [
  "probe:audit-event-count",
  "probe:device-sign-in-addresses",
  "probe:expire-pending-device-sign-ins",
  "probe:proxy-addresses",
  "maintenance",
  "serve-cli",
  "ts-stack",
];

const BUILT_FROM_SOURCE = ["varlatchd", "varlatch-migrate", "varlatch-web", "convex-deploy"];
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** `docker compose` against the project; output captured unless `inherit`. */
function compose(state, args, { input = "", inherit = false, env = {} } = {}) {
  const r = spawnSync(
    "docker",
    [
      "compose",
      "--project-name", state.project,
      "--env-file", join(state.dir, ".env"),
      "-f", join(state.dir, "docker-compose.yml"),
      "-f", join(state.dir, "build.json"),
      ...args,
    ],
    {
      cwd: state.dir,
      env: { ...process.env, ...state.env, ...env },
      input,
      encoding: "utf8",
      stdio: inherit ? ["ignore", "inherit", "inherit"] : "pipe",
      maxBuffer: 256 * 1024 * 1024,
    },
  );
  return { status: r.status ?? 1, stdout: r.stdout ?? "", stderr: r.stderr ?? (r.error ? String(r.error) : "") };
}

function mustCompose(state, args, options) {
  const r = compose(state, args, options);
  if (r.status !== 0) throw new Error(`docker compose ${args.join(" ")} failed (exit ${r.status}): ${r.stderr.trim().slice(-500)}`);
  return r.stdout;
}

/** The varlatchd admin CLI inside the container, as an operator runs it. */
const admin = (state, args, input = "") => mustCompose(state, ["exec", "-T", "varlatchd", "node", "dist/cli.js", "admin", ...args], { input });

const psql = (state, sql) => mustCompose(state, ["exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "varlatch", "-Atqc", sql]).trim();

/** Ask the kernel for `count` unused loopback ports. */
async function freePorts(count) {
  const servers = await Promise.all(
    Array.from({ length: count }, () => new Promise((resolve, reject) => {
      const server = createServer();
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => resolve(server));
    })),
  );
  const ports = servers.map((s) => s.address().port);
  await Promise.all(servers.map((s) => new Promise((resolve) => s.close(resolve))));
  return ports;
}

async function status(url) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
    return { code: res.status, body: await res.text() };
  } catch {
    return { code: 0, body: "" };
  }
}

/** Builds and starts a fresh installation; returns the state every other operation takes. */
export async function up({ repoRoot }) {
  const dir = mkdtempSync(join(tmpdir(), "varlatch-conformance-"));
  const state = { target: name, dir, project: `varlatch-e2e-${dir.split("-").pop().toLowerCase().replace(/[^a-z0-9]/g, "")}`, env: {} };
  try {
    cpSync(join(repoRoot, "infra/compose/docker-compose.yml"), join(dir, "docker-compose.yml"));
    cpSync(join(repoRoot, "infra/compose/convex-supervisor.cjs"), join(dir, "convex-supervisor.cjs"));
    cpSync(join(repoRoot, "infra/compose/postgres-init"), join(dir, "postgres-init"), { recursive: true });
    // Build contexts resolve against the checkout; every runtime file,
    // secret, network and volume belongs to the disposable project.
    writeFileSync(join(dir, "build.json"), JSON.stringify({ services: Object.fromEntries(BUILT_FROM_SOURCE.map((s) => [s, { build: { context: repoRoot } }])) }));
    const [webPort, varlatchdPort, convexPort] = await freePorts(3);
    const origin = `http://localhost:${webPort}`;
    state.origin = origin;
    state.env = {
      VARLATCH_WEB_PORT: String(webPort),
      VARLATCHD_PORT: String(varlatchdPort),
      CONVEX_PORT: String(convexPort),
      WEB_ORIGIN: origin,
      // One public origin (ADR-0035 D5): the browser reaches Convex through
      // the dashboard at /convex, exercising the same-origin proxy.
      CONVEX_CLOUD_ORIGIN: `${origin}/convex`,
      BIND_ADDRESS: "127.0.0.1",
      VARLATCH_KEK_HOST_PATH: join(dir, "secrets", "varlatch-kek"),
    };
    const hex = (bytes) => randomBytes(bytes).toString("hex");
    writeFileSync(join(dir, ".env"), [
      `POSTGRES_SUPERUSER_PASSWORD=${hex(24)}`,
      `VARLATCH_MIGRATE_PASSWORD=${hex(24)}`,
      `VARLATCH_RUNTIME_PASSWORD=${hex(24)}`,
      `CONVEX_DB_PASSWORD=${hex(24)}`,
      `CONVEX_INSTANCE_SECRET=${hex(32)}`,
      `VARLATCH_PUBLIC_URL=${origin}`,
      "VARLATCH_JWKS_URL=http://varlatchd:8686/.well-known/jwks.json",
      "VARLATCH_CONVEX_URL=http://convex-backend:3210",
      "",
    ].join("\n"));
    mkdirSync(join(dir, "secrets"));
    writeFileSync(join(dir, "secrets", "varlatch-kek"), `${hex(32)}\n`);

    mustCompose(state, ["up", "-d", "--build"], { inherit: true });
    console.log("--- waiting for readiness");
    for (let i = 0; i < 60; i++) {
      if ((await status(`${origin}/v1/meta`)).code === 200) break;
      await sleep(3000);
    }
    const ready = await status(`http://localhost:${varlatchdPort}/readyz`);
    if (ready.code !== 200 || !ready.body.includes('"ready":true')) throw new Error(`varlatchd is not ready: ${ready.code} ${ready.body.slice(0, 200)}`);
    return state;
  } catch (err) {
    err.state = state;
    throw err;
  }
}

/** Removes the installation: containers, volumes, networks and the project directory. */
export async function down(state) {
  compose(state, ["down", "-v", "--remove-orphans"]);
  rmSync(state.dir, { recursive: true, force: true });
}

/** What a failed run prints to help: the last lines of every service's log. */
export async function diagnostics(state) {
  return compose(state, ["logs", "--tail", "50"]).stdout;
}

export const origin = (state) => state.origin;

/** The first enrollment URL, as `varlatchd admin bootstrap` prints it. */
export async function bootstrap(state) {
  return admin(state, ["bootstrap"]);
}

/** A recovery enrollment URL, or with `cliCredential` a CLI token on the last line, as the admin CLI prints them. */
export async function recover(state, identity, { cliCredential = false } = {}) {
  return admin(state, ["recover", "--identity", identity, ...(cliCredential ? ["--cli-credential"] : [])]);
}

async function waitForMeta(state) {
  for (let i = 0; i < 60; i++) {
    if ((await status(`${state.origin}/v1/meta`)).code === 200) return;
    await sleep(2000);
  }
  throw new Error("the server did not answer /v1/meta after restarting");
}

/** Restarts the server with its data kept. */
export async function restart(state) {
  mustCompose(state, ["restart", "varlatchd"]);
  await waitForMeta(state);
}

/** The server's logs. */
export async function logs(state) {
  return mustCompose(state, ["logs", "varlatchd"]);
}

/** One record per request varlatchd answered, from the dashboard's nginx access log. */
export async function requestLog(state) {
  return requestsFromNginxLog(compose(state, ["logs", "--no-log-prefix", "varlatch-web"]).stdout);
}

/** Brings derived read models up to date before the dashboard suites: the Convex audit mirror. */
export async function settle(state) {
  admin(state, ["mirror-sync"]);
}

const PROBES = {
  "audit-event-count": (state) => Number(psql(state, "SELECT count(*) FROM audit_events")),
  "expire-pending-device-sign-ins": (state) => {
    psql(state, "UPDATE device_sign_ins SET expires_at = clock_timestamp() - interval '1 second' WHERE status = 'pending'");
    return true;
  },
  "device-sign-in-addresses": (state, requestedName) => {
    // Names come from the suites; only plain ones reach SQL.
    if (!/^[a-z0-9-]{1,64}$/.test(requestedName ?? "")) throw new Error("device-sign-in-addresses: name must be lower-case letters, digits and dashes");
    return JSON.parse(psql(state, `SELECT coalesce(json_agg(json_build_object('requesterIp', requester_ip)), '[]') FROM device_sign_ins WHERE requested_name = '${requestedName}'`));
  },
  "proxy-addresses": (state) => {
    const id = mustCompose(state, ["ps", "-q", "varlatch-web"]).trim();
    const r = spawnSync("docker", ["inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", id], { encoding: "utf8" });
    if (r.status !== 0) throw new Error(`docker inspect failed: ${r.stderr}`);
    return r.stdout.trim().split(/\s+/).filter(Boolean);
  },
};

/** A fixed, named read of server state where /v1 does not show it; returns JSON-able data. */
export async function probe(state, probeName, ...args) {
  const run = PROBES[probeName];
  if (!run) throw new Error(`unknown probe ${probeName}`);
  return run(state, ...args);
}

/** Opens a maintenance window for `ttlMs`: the same `503 MAINTENANCE` admission a restore uses. */
export async function maintenance(state, ttlMs) {
  admin(state, ["backup-control", "capture-begin"], JSON.stringify({ ttlMs: Number(ttlMs) }));
}

/** Recreates the server with CLI serving on or off (ADR-0058 Decision 3); waiting for it is the caller's. */
export async function serveCli(state, on) {
  mustCompose(state, ["up", "-d", "varlatchd"], { env: { VARLATCH_SERVE_CLI: on ? "on" : "off" } });
}

/**
 * Compose control for the ts-stack checks: `compose <args...>` runs docker
 * compose against the project; `compose-env` gives what the host CLI needs
 * to find the project the way plain `docker compose` does (doctor --dir).
 */
export async function tsStack(state, action, ...args) {
  if (action === "compose") return compose(state, args);
  if (action === "compose-env") {
    return {
      status: 0,
      stdout: JSON.stringify({
        dir: state.dir,
        env: {
          ...state.env,
          COMPOSE_PROJECT_NAME: state.project,
          COMPOSE_FILE: `${join(state.dir, "docker-compose.yml")}:${join(state.dir, "build.json")}`,
          COMPOSE_ENV_FILES: join(state.dir, ".env"),
        },
      }),
      stderr: "",
    };
  }
  throw new Error(`unknown ts-stack action ${action}`);
}
