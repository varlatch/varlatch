// SPDX-License-Identifier: Apache-2.0
/**
 * The TypeScript stack as a disposable Compose project: what the
 * `ts-source` and `ts-release` targets share. They differ only in where the
 * Compose files and images come from (this checkout, built; or a verified
 * release bundle, pulled by digest); every operation of the target contract
 * is the same, and runs `docker compose` against the project.
 *
 * The state an operation needs is the JSON `up` returns:
 *   target        the target's specification (`ts-source`, `ts-release:0.22.0`)
 *   root          the directory `down` removes
 *   dir           the Compose project directory (.env, secrets/, the files)
 *   composeFiles  the Compose files, relative to `dir`, in order
 *   project       the Compose project name
 *   env           the variables every `docker compose` call gets (ports, origin)
 *   origin        the dashboard origin
 *
 * The suites reach the stack through the dashboard's nginx, the one public
 * origin (ADR-0035 D5). scripts/conformance/target-op.mjs reads the state
 * back for the suites.
 */
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { join } from "node:path";
import { requestsFromNginxLog } from "./nginx-log.mjs";


const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** A Compose project name for a new temporary directory. */
export const projectName = (dir) => `varlatch-e2e-${dir.split("-").pop().toLowerCase().replace(/[^a-z0-9]/g, "")}`;

/** `docker compose` against the project; output captured unless `inherit`. */
export function compose(state, args, { input = "", inherit = false, env = {} } = {}) {
  const r = spawnSync(
    "docker",
    [
      "compose",
      "--project-name", state.project,
      "--env-file", join(state.dir, ".env"),
      ...state.composeFiles.flatMap((f) => ["-f", join(state.dir, f)]),
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

export function mustCompose(state, args, options) {
  const r = compose(state, args, options);
  if (r.status !== 0) throw new Error(`docker compose ${args.join(" ")} failed (exit ${r.status}): ${r.stderr.trim().slice(-500)}`);
  return r.stdout;
}

/** The varlatchd admin CLI inside the container, as an operator runs it. */
const admin = (state, args, input = "") => mustCompose(state, ["exec", "-T", "varlatchd", "node", "dist/cli.js", "admin", ...args], { input });

/**
 * The host-admin capability: one `varlatchd admin` host command whose
 * refusal a suite checks (`audit-export ...` only), inside the container.
 * Its exit status and output, whatever the status.
 */
export async function hostAdmin(state, ...args) {
  if (args[0] !== "audit-export") throw new Error(`host-admin: unknown command ${args[0]}`);
  return compose(state, ["exec", "-T", "varlatchd", "node", "dist/cli.js", "admin", ...args]);
}

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

/**
 * Gives the project its free loopback ports, temporary credentials and its
 * own key file; writes `.env` and `secrets/` into `state.dir`.
 */
export async function configure(state) {
  const [webPort, varlatchdPort, convexPort] = await freePorts(3);
  const origin = `http://localhost:${webPort}`;
  state.origin = origin;
  state.varlatchdPort = varlatchdPort;
  state.env = {
    VARLATCH_WEB_PORT: String(webPort),
    VARLATCHD_PORT: String(varlatchdPort),
    CONVEX_PORT: String(convexPort),
    WEB_ORIGIN: origin,
    // One public origin (ADR-0035 D5): the browser reaches Convex through
    // the dashboard at /convex, exercising the same-origin proxy.
    CONVEX_CLOUD_ORIGIN: `${origin}/convex`,
    BIND_ADDRESS: "127.0.0.1",
    VARLATCH_KEK_HOST_PATH: join(state.dir, "secrets", "varlatch-kek"),
    // The webhooks suite's receiver, on varlatchd's own loopback inside its
    // container: the one private destination the outbound policy allows.
    // and the audit-export suite's object store, on the project's network.
    // And the oidc suite's issuer, on varlatchd's loopback too.
    // And the sync suite's fake platforms, on its loopback port 443.
    VARLATCH_OUTBOUND_ALLOW: `127.0.0.1/32:${WEBHOOK_RECEIVER_PORT},${OBJECT_STORE_ALIAS}:9000,127.0.0.1/32:${OIDC_ISSUER_PORT},127.0.0.1/32:443`,
  };
  // The oidc suite's issuer certificate and the sync suite's fake
  // platforms' certificate, which varlatchd trusts from its start
  // (NODE_EXTRA_CA_CERTS), mounted with their keys for the issuer and the
  // fakes. The fakes run in varlatchd's container on its loopback, and the
  // platforms' host names lead there (extra_hosts).
  issuerCertificate(join(state.dir, "oidc"));
  platformFakesCertificate(join(state.dir, "oidc"));
  writeFileSync(join(state.dir, "oidc", "roots.pem"), `${readFileSync(join(state.dir, "oidc", "cert.pem"), "utf8")}${readFileSync(join(state.dir, "oidc", "fakes-cert.pem"), "utf8")}`);
  chmodSync(join(state.dir, "oidc", "roots.pem"), 0o644);
  writeFileSync(join(state.dir, OIDC_OVERRIDE), [
    "# Written by scripts/conformance/targets/compose-stack.mjs: the oidc suite's issuer certificate,",
    "# the sync suite's fake platforms' certificate, and their host names.",
    "services:",
    "  varlatchd:",
    "    environment:",
    `      NODE_EXTRA_CA_CERTS: ${OIDC_MOUNT}/roots.pem`,
    "    extra_hosts:",
    ...PLATFORM_FAKE_HOSTS.map((h) => `      - "${h}:127.0.0.1"`),
    "    volumes:",
    `      - ./oidc:${OIDC_MOUNT}:ro`,
    "",
  ].join("\n"));
  if (!state.composeFiles.includes(OIDC_OVERRIDE)) state.composeFiles.push(OIDC_OVERRIDE);
  const hex = (bytes) => randomBytes(bytes).toString("hex");
  writeFileSync(join(state.dir, ".env"), [
    `POSTGRES_SUPERUSER_PASSWORD=${hex(24)}`,
    `VARLATCH_MIGRATE_PASSWORD=${hex(24)}`,
    `VARLATCH_RUNTIME_PASSWORD=${hex(24)}`,
    `CONVEX_DB_PASSWORD=${hex(24)}`,
    `CONVEX_INSTANCE_SECRET=${hex(32)}`,
    `VARLATCH_PUBLIC_URL=${origin}`,
    "VARLATCH_JWKS_URL=http://varlatchd:8686/.well-known/jwks.json",
    "VARLATCH_CONVEX_URL=http://convex-backend:3210",
    "",
  ].join("\n"), { mode: 0o600 });
  mkdirSync(join(state.dir, "secrets"));
  writeFileSync(join(state.dir, "secrets", "varlatch-kek"), `${hex(32)}\n`, { mode: 0o644 });
}

/** Starts the configured project (`upArgs` after `up -d`) and waits until varlatchd is ready. */
export async function start(state, upArgs) {
  mustCompose(state, ["up", "-d", ...upArgs], { inherit: true });
  console.log("--- waiting for readiness");
  for (let i = 0; i < 60; i++) {
    if ((await status(`${state.origin}/v1/meta`)).code === 200) break;
    await sleep(3000);
  }
  const ready = await status(`http://localhost:${state.varlatchdPort}/readyz`);
  if (ready.code !== 200 || !ready.body.includes('"ready":true')) throw new Error(`varlatchd is not ready: ${ready.code} ${ready.body.slice(0, 200)}`);
}

/** Removes the installation: containers, volumes, networks and the project directory. */
export async function down(state) {
  // The object store sits on the project's network: removed first, by its name.
  if (state.project) spawnSync("docker", ["rm", "-fv", objectStoreName(state)], { stdio: "ignore" });
  if (state.composeFiles?.length) compose(state, ["down", "-v", "--remove-orphans"]);
  rmSync(state.root ?? state.dir, { recursive: true, force: true });
}

/**
 * The image each service of the project runs, by image ID (content
 * address), from its containers: what the stack actually ran, for the
 * target's implementation fingerprint.
 */
export function imageIds(state) {
  const ids = mustCompose(state, ["ps", "-a", "-q"]).split("\n").map((l) => l.trim()).filter(Boolean);
  if (ids.length === 0) throw new Error("the project has no containers to fingerprint");
  const r = spawnSync("docker", ["inspect", "-f", '{{ index .Config.Labels "com.docker.compose.service" }} {{ .Image }}', ...ids], { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`docker inspect failed: ${r.stderr}`);
  const images = {};
  for (const line of r.stdout.split("\n").filter(Boolean)) {
    const [service, image] = line.trim().split(/\s+/);
    if (images[service] && images[service] !== image) throw new Error(`service ${service} runs two images: ${images[service]}, ${image}`);
    images[service] = image;
  }
  return Object.fromEntries(Object.entries(images).sort(([a], [b]) => a.localeCompare(b)));
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
  return requestsFromNginxLog(mustCompose(state, ["logs", "--no-log-prefix", "varlatch-web"]));
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
  "deletion-due": (state, deletionId) => {
    // An Organization's open deletion request (ADR-0051), made due now: as
    // if scheduled 40 days ago and due a second ago. Only an id reaches SQL.
    if (!/^odl_[a-z2-7]{26}$/.test(deletionId ?? "")) throw new Error("deletion-due: a deletion request id (odl_...)");
    psql(state, `UPDATE organization_deletions SET scheduled_at = scheduled_at - interval '40 days', run_after = clock_timestamp() - interval '1 second'
      WHERE id = '${deletionId}' AND cancelled_at IS NULL AND completed_at IS NULL`);
    return true;
  },
  // Where the converge engine's trigger scan stands: a change reaches the
  // engine once the scan's cursor passes its audit event.
  "sync-trigger-position": (state) => JSON.parse(psql(state, `SELECT json_build_object(
      'cursor', COALESCE((SELECT cursor_order FROM sync_cursor), 0),
      'latest', COALESCE((SELECT max(event_order) FROM audit_events WHERE substr(event_type, 1, 5) <> 'sync.'), 0))`)),
  // The sync suite's repair pass: the Target's last repair hours ago, as
  // six hours later, and nothing else changed, so that only the periodic
  // schedule can make it due. Answers what would also have made it due,
  // for the suite to see the Target was settled.
  "sync-repair-due": (state, targetId) => {
    if (!/^snt_[a-z0-9]{26}$/.test(targetId ?? "")) throw new Error("sync-repair-due: a Sync Target id");
    const got = psql(state, `UPDATE sync_targets SET last_repair_at = clock_timestamp() - interval '7 hours' WHERE id = '${targetId}'
      RETURNING json_build_object('needsSync', needs_sync, 'nextAttemptAt', next_attempt_at)`);
    if (!got) throw new Error(`sync-repair-due: no Sync Target ${targetId}`);
    return JSON.parse(got);
  },
  "deletion-teardown": (state, organizationId) => {
    if (!/^org_[a-z0-9]{26}$/.test(organizationId ?? "")) throw new Error("deletion-teardown: an Organization id (org_...)");
    const list = (table) => `COALESCE((SELECT json_agg(json_build_object('id', id, 'revoked', revoked_at IS NOT NULL) ORDER BY id) FROM ${table} WHERE organization_id = '${organizationId}'), '[]'::json)`;
    return JSON.parse(psql(state, `SELECT json_build_object('targets', ${list("sync_targets")}, 'connections', ${list("platform_connections")}, 'webhooks', ${list("webhooks")},
      'githubApps', COALESCE((SELECT json_agg(json_build_object('id', id, 'removed', removed_at IS NOT NULL, 'keyKept', key_envelope IS NOT NULL) ORDER BY id)
        FROM github_apps WHERE organization_id = '${organizationId}'), '[]'::json))`));
  },
  "audit-export-drain-due": (state, organizationId) => {
    if (!/^org_[a-z0-9]{26}$/.test(organizationId ?? "")) throw new Error("audit-export-drain-due: an Organization id (org_...)");
    const got = psql(state, `UPDATE audit_exports SET drain_deadline = clock_timestamp() - interval '1 second'
      WHERE organization_id = '${organizationId}' AND state = 'draining' RETURNING 'true'`);
    if (!/\btrue\b/.test(got ?? "")) throw new Error(`audit-export-drain-due: no draining audit export of ${organizationId}`);
    return true;
  },
  "github-app-pending-expired": (state, registrationId) => {
    if (!/^ghr_[a-z0-9]{26}$/.test(registrationId ?? "")) throw new Error("github-app-pending-expired: a GitHub App registration id (ghr_...)");
    // The pending conversion's material is written once, by a trigger; this
    // one update runs with triggers off (the superuser's replica role), in
    // its own transaction.
    const got = psql(state, `BEGIN; SET LOCAL session_replication_role = replica;
      UPDATE github_app_registrations SET converted_at = clock_timestamp() - interval '2 hours', pending_expires_at = clock_timestamp() - interval '1 second'
      WHERE id = '${registrationId}' AND converted_at IS NOT NULL AND ended_at IS NULL RETURNING 'true'; COMMIT;`);
    if (!/\btrue\b/.test(got ?? "")) throw new Error(`github-app-pending-expired: no pending GitHub App conversion ${registrationId}`);
    return true;
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

/**
 * Recreates the server with CLI serving on or off (ADR-0058 Decision 3);
 * waiting for it is the caller's. `--no-build`: the images the stack
 * started with, never a rebuild.
 */
export async function serveCli(state, on) {
  mustCompose(state, ["up", "-d", "--no-build", "varlatchd"], { env: { VARLATCH_SERVE_CLI: on ? "on" : "off" } });
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
          COMPOSE_FILE: state.composeFiles.map((f) => join(state.dir, f)).join(":"),
          COMPOSE_ENV_FILES: join(state.dir, ".env"),
        },
      }),
      stderr: "",
    };
  }
  throw new Error(`unknown ts-stack action ${action}`);
}

/** The webhook receiver's port, inside varlatchd's container. */
export const WEBHOOK_RECEIVER_PORT = 18787;

const RECEIVER_SOURCE = new URL("../lib/webhook-receiver.cjs", import.meta.url);

/** What the receiver recorded, read inside the container; null when it does not answer. */
function receiverRequests(state) {
  const read = `fetch("http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/_received").then((r) => r.text()).then((t) => process.stdout.write(t), () => process.exit(1))`;
  const r = compose(state, ["exec", "-T", "varlatchd", "node", "-e", read]);
  if (r.status !== 0) return null;
  return JSON.parse(r.stdout);
}

/**
 * The webhook-receiver capability: `url` starts the receiver
 * (lib/webhook-receiver.cjs) inside varlatchd's container when it is not
 * running, and answers the URL varlatchd reaches it at; `requests` what it
 * recorded. It lives as long as the container: a restart of varlatchd ends
 * it, and the next `url` starts it again, with nothing recorded.
 */
export async function webhookReceiver(state, action) {
  if (action === "requests") {
    const got = receiverRequests(state);
    if (!got) throw new Error("the webhook receiver is not running: ask for its url first");
    return got;
  }
  if (action !== "url") throw new Error(`unknown webhook-receiver action ${action}`);
  if (!receiverRequests(state)) {
    mustCompose(state, ["exec", "-d", "-T", "varlatchd", "node", "-e", readFileSync(RECEIVER_SOURCE, "utf8"), String(WEBHOOK_RECEIVER_PORT)]);
    for (let i = 0; i < 50 && !receiverRequests(state); i++) await sleep(200);
    if (!receiverRequests(state)) throw new Error("the webhook receiver did not start in varlatchd's container");
  }
  return { url: `http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}` };
}

/** The sync suite's fake platforms' host names (lib/platform-fakes.cjs). */
export const PLATFORM_FAKE_HOSTS = ["api.github.com", "coolify.conformance.test", "convex.conformance.test"];

/**
 * A self-signed certificate for the fake platforms' host names and its key,
 * in dir (fakes-cert.pem, fakes-key.pem; readable by the server's user):
 * the targets trust it for this run only.
 */
export function platformFakesCertificate(dir) {
  mkdirSync(dir, { recursive: true });
  const r = spawnSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2",
    "-subj", "/CN=conformance-platform-fakes", "-addext", `subjectAltName=${PLATFORM_FAKE_HOSTS.map((h) => `DNS:${h}`).join(",")}`,
    "-keyout", join(dir, "fakes-key.pem"), "-out", join(dir, "fakes-cert.pem")], { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`openssl could not make the fake platforms' certificate: ${(r.stderr || r.error || "").toString().trim().slice(-300)}`);
  chmodSync(dir, 0o755);
  chmodSync(join(dir, "fakes-key.pem"), 0o644);
  chmodSync(join(dir, "fakes-cert.pem"), 0o644);
}

/** The fake platforms' control port, inside varlatchd's container. */
const PLATFORM_FAKES_CONTROL = 18788;
const PLATFORM_FAKES_SOURCE = new URL("../lib/platform-fakes.cjs", import.meta.url);

/** A control request to the fake platforms, made inside the container; null when they do not answer. */
function platformFakesControl(state, method, path, body) {
  const call = `fetch("http://127.0.0.1:${PLATFORM_FAKES_CONTROL}${path}", { method: ${JSON.stringify(method)}, ${body ? `body: ${JSON.stringify(body)}, ` : ""}}).then((r) => r.ok ? r.text() : Promise.reject(r.status)).then((t) => process.stdout.write(t), () => process.exit(1))`;
  const r = compose(state, ["exec", "-T", "varlatchd", "node", "-e", call]);
  return r.status === 0 ? JSON.parse(r.stdout) : null;
}

/**
 * The platform-fakes capability: `start` runs the fake platforms
 * (lib/platform-fakes.cjs) in varlatchd's container, on its loopback port
 * 443 (which the platforms' host names lead to) when they are not running;
 * `state` what they hold and every request they saw; `drift <resource>
 * <key> <value>` changes a Coolify value behind Varlatch's back; `github
 * <json>` sets up the fake GitHub's App side (lib/platform-fakes.cjs,
 * POST /_github). They live as long as the container.
 */
export async function platformFakes(state, action, ...args) {
  if (action === "state") {
    const got = platformFakesControl(state, "GET", "/_state");
    if (!got) throw new Error("the fake platforms are not running: start them first");
    return got;
  }
  if (action === "drift") {
    const [resource, key, value] = args;
    const got = platformFakesControl(state, "POST", "/_drift", JSON.stringify({ resource, key, value }));
    if (!got) throw new Error(`the fake platforms could not drift ${resource} ${key}`);
    return got;
  }
  if (action === "github") {
    const got = platformFakesControl(state, "POST", "/_github", args[0]);
    if (!got) throw new Error(`the fake GitHub refused ${args[0]?.slice(0, 80)}`);
    return got;
  }
  if (action !== "start") throw new Error(`unknown platform-fakes action ${action}`);
  if (!platformFakesControl(state, "GET", "/_state")) {
    mustCompose(state, ["exec", "-d", "-T", "varlatchd", "node", "-e", readFileSync(PLATFORM_FAKES_SOURCE, "utf8"),
      "443", String(PLATFORM_FAKES_CONTROL), `${OIDC_MOUNT}/fakes-cert.pem`, `${OIDC_MOUNT}/fakes-key.pem`]);
    for (let i = 0; i < 50 && !platformFakesControl(state, "GET", "/_state"); i++) await sleep(200);
    if (!platformFakesControl(state, "GET", "/_state")) throw new Error("the fake platforms did not start in varlatchd's container");
  }
  return { coolify: "https://coolify.conformance.test", convex: "https://convex.conformance.test", github: "acme" };
}

/** The oidc suite's issuer: its port on varlatchd's loopback, its Compose override and mount. */
export const OIDC_ISSUER_PORT = 7443;
const OIDC_OVERRIDE = "conformance-oidc.yml";
const OIDC_MOUNT = "/conformance-oidc";
export const ISSUER_SOURCE = new URL("../lib/oidc-issuer.cjs", import.meta.url);

/**
 * A self-signed certificate for https://127.0.0.1 and its key, in dir
 * (cert.pem, key.pem; readable by the server's user), for the oidc suite's
 * issuer.
 */
export function issuerCertificate(dir) {
  mkdirSync(dir, { recursive: true });
  const r = spawnSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2",
    "-subj", "/CN=conformance-oidc", "-addext", "subjectAltName=IP:127.0.0.1",
    "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem")], { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`openssl could not make the issuer certificate: ${(r.stderr || r.error || "").toString().trim().slice(-300)}`);
  chmodSync(dir, 0o755);
  chmodSync(join(dir, "key.pem"), 0o644);
  chmodSync(join(dir, "cert.pem"), 0o644);
}

/**
 * The oidc-issuer capability: `start` runs the issuer (lib/oidc-issuer.cjs)
 * in varlatchd's container, on its loopback port the allow list opens,
 * when it is not running, and answers its URL; `keys <json>` sets its
 * JWKS; `counts` what it was fetched. A control request runs in the
 * container too.
 */
export async function oidcIssuer(state, action, ...args) {
  const control = (method, path, body) => compose(state, ["exec", "-T", "varlatchd", "node", "-e", readFileSync(ISSUER_SOURCE, "utf8"),
    "control", `${OIDC_MOUNT}/cert.pem`, String(OIDC_ISSUER_PORT), method, path, ...(body ? [body] : [])]);
  const running = () => control("GET", "/_conformance/counts").status === 0;
  if (action === "start") {
    if (!running()) {
      mustCompose(state, ["exec", "-d", "-T", "varlatchd", "node", "-e", readFileSync(ISSUER_SOURCE, "utf8"), "serve", OIDC_MOUNT, String(OIDC_ISSUER_PORT)]);
      for (let i = 0; i < 50 && !running(); i++) await sleep(200);
      if (!running()) throw new Error("the oidc issuer did not start in varlatchd's container");
    }
    return { issuer: `https://127.0.0.1:${OIDC_ISSUER_PORT}` };
  }
  const r = action === "keys" ? control("PUT", "/_conformance/jwks", args[0]) : action === "counts" ? control("GET", "/_conformance/counts") : null;
  if (!r) throw new Error(`unknown oidc-issuer action ${action}`);
  if (r.status !== 0) throw new Error(`oidc-issuer ${action}: ${(r.stderr || r.stdout).trim().slice(0, 300)}`);
  return JSON.parse(r.stdout);
}

/** The object store's network alias, and the image the tests pin (MinIO withdrew its own images). */
export const OBJECT_STORE_ALIAS = "conformance-s3";
export const OBJECT_STORE_IMAGE = "cgr.dev/chainguard/minio@sha256:6a1d0b45c8669726bba580ced0bfa4cb9fdeed1ed636dfabd81d1577beb6937b";

const objectStoreName = (state) => `${state.project}-object-store`;

/** The object store's keys: derived from the installation, so every operation names the same ones. */
export function objectStoreKeys(seed) {
  const h = createHash("sha256").update(`object-store:${seed}`).digest("hex");
  return { accessKeyId: `conformance${h.slice(0, 8)}`, secretAccessKey: h.slice(8, 48) };
}

/** Waits until MinIO at hostEndpoint answers ready. */
export async function objectStoreReady(hostEndpoint) {
  for (let i = 0; i < 100; i++) {
    const ok = await fetch(`${hostEndpoint}/minio/health/ready`, { signal: AbortSignal.timeout(2000) }).then((r) => r.ok, () => false);
    if (ok) return;
    await sleep(300);
  }
  throw new Error("the object store did not become ready");
}

/**
 * The object-store capability: `start` runs MinIO (pinned by digest) on
 * the project's network, under an alias the outbound allow list opens,
 * with its port published on loopback for the suite; again, it answers
 * the running one. JSON: the endpoint varlatchd reaches it at, the one
 * the suite reaches it at, the region and the keys. `down` removes it.
 */
export async function objectStore(state, action) {
  if (action !== "start") throw new Error(`unknown object-store action ${action}`);
  const name = objectStoreName(state);
  const keys = objectStoreKeys(state.dir);
  const running = spawnSync("docker", ["inspect", "-f", "{{.State.Running}}", name], { encoding: "utf8" });
  if (running.status !== 0 || running.stdout.trim() !== "true") {
    spawnSync("docker", ["rm", "-fv", name], { stdio: "ignore" });
    const r = spawnSync("docker", ["run", "-d", "--name", name, "--network", `${state.project}_default`, "--network-alias", OBJECT_STORE_ALIAS,
      "-p", "127.0.0.1::9000", "-e", `MINIO_ROOT_USER=${keys.accessKeyId}`, "-e", `MINIO_ROOT_PASSWORD=${keys.secretAccessKey}`,
      OBJECT_STORE_IMAGE, "server", "/data"], { encoding: "utf8" });
    if (r.status !== 0) throw new Error(`docker run ${name} failed: ${r.stderr.trim().slice(-300)}`);
  }
  const port = spawnSync("docker", ["port", name, "9000/tcp"], { encoding: "utf8" }).stdout.trim().split("\n")[0].split(":").pop();
  const hostEndpoint = `http://127.0.0.1:${port}`;
  await objectStoreReady(hostEndpoint);
  return { endpoint: `http://${OBJECT_STORE_ALIAS}:9000`, hostEndpoint, region: "us-east-1", ...keys };
}
