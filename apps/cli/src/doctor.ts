// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { EMBEDDED_RELEASE } from "@varlatch/backup";
import { compareVersions, parseManifest, type ReleaseManifest } from "./upgrade.js";

/**
 * `varlatch doctor` (ADR-0035 Decision 8): read-only Installation Health for
 * the Compose installation in --dir. Host authority, like `admin backup`: it
 * needs Docker access, no Varlatch login. It only runs `docker compose version`,
 * `ps`, `config` and read-only `exec`s and reads files: no restarts, repairs,
 * locks, or writes (not even a diagnostics log). The resolved configuration
 * holds secret values; they stay in memory and no check reports one.
 *
 * Results are pass/fail/unknown; findings are mandatory or advisory. Exit
 * code 1 when any mandatory check fails. Unknown is shown as unknown — the
 * upgrade gate (`--gate`, D11), not doctor, decides what an unknown blocks.
 */

export type CheckStatus = "pass" | "fail" | "unknown";
export type CheckClass = "mandatory" | "advisory";
export interface Check {
  id: string;
  title: string;
  status: CheckStatus;
  class: CheckClass;
  detail?: string;
  remedy?: string;
}
interface ServerFacts {
  serverVersion: string;
  releaseVersion: string;
  migrationVersion: number;
  publicUrl: string | null;
  convexConfigured: boolean;
  installationId: string | null;
  /** The tailnet browser endpoint varlatchd serves (ADR-0046); absent from older servers, null when off. */
  tailnetBrowserEndpoint?: string | null;
}
export interface DoctorReport {
  dir: string;
  facts: ServerFacts | null;
  checks: Check[];
}

export type Runner = (args: string[], timeoutMs?: number) => Promise<{ code: number; stdout: string }>;

/** docker in `dir`; stdout captured (bounded), stderr discarded — it can carry connection strings. */
export function dockerRunner(dir: string): Runner {
  return (args, timeoutMs = 60_000) =>
    new Promise((resolveRun) => {
      const child = spawn("docker", args, { cwd: dir, stdio: ["ignore", "pipe", "ignore"] });
      let stdout = "";
      const timer = setTimeout(() => child.kill("SIGTERM"), timeoutMs);
      child.stdout.on("data", (chunk: Buffer) => {
        if (stdout.length < 1024 * 1024) stdout += chunk.toString();
      });
      child.once("error", () => { clearTimeout(timer); resolveRun({ code: 127, stdout: "" }); });
      child.once("close", (code) => { clearTimeout(timer); resolveRun({ code: code ?? 1, stdout: stdout.trim() }); });
    });
}

export interface ServiceState {
  ID?: string;
  Service: string;
  State: string;
  Health?: string;
  ExitCode?: number;
  Image?: string;
}

/** `docker compose ps --format json` prints a JSON array (older) or NDJSON (newer). */
export function parseComposePs(stdout: string): ServiceState[] {
  const text = stdout.trim();
  if (!text) return [];
  if (text.startsWith("[")) return JSON.parse(text) as ServiceState[];
  return text.split("\n").filter(Boolean).map((line) => JSON.parse(line) as ServiceState);
}

const LONG_RUNNING = ["postgres", "varlatchd", "varlatch-web", "convex-backend"];

export function checkServices(services: ServiceState[]): Check[] {
  const byName = new Map(services.map((s) => [s.Service, s]));
  const problems: string[] = [];
  for (const name of [...LONG_RUNNING, ...(byName.has("tailscale") ? ["tailscale"] : [])]) {
    const s = byName.get(name);
    if (!s) problems.push(`${name}: not created`);
    else if (s.State !== "running") problems.push(`${name}: ${s.State}`);
    else if (s.Health && s.Health !== "healthy") problems.push(`${name}: ${s.Health}`);
  }
  const migrate = byName.get("varlatch-migrate");
  if (migrate && migrate.State === "exited" && migrate.ExitCode !== 0) {
    problems.push(`varlatch-migrate: exited ${migrate.ExitCode}`);
  }
  const checks: Check[] = [{
    id: "services.running",
    title: "Services running and healthy",
    class: "mandatory",
    status: problems.length ? "fail" : "pass",
    ...(problems.length
      ? { detail: problems.join("; "), remedy: "Inspect with `docker compose ps` and `docker compose logs <service>`" }
      : { detail: LONG_RUNNING.join(", ") }),
  }];
  const deploy = byName.get("convex-deploy");
  if (deploy && deploy.State === "exited") {
    checks.push({
      id: "application-plane.deploy",
      title: "Last Application Plane function deploy",
      class: "mandatory",
      status: deploy.ExitCode === 0 ? "pass" : "fail",
      ...(deploy.ExitCode === 0
        ? { detail: "convex-deploy exited 0" }
        : { detail: `convex-deploy exited ${deploy.ExitCode}`, remedy: "Check `docker compose logs convex-deploy`" }),
    });
  }
  return checks;
}

const IMAGE_FOR_SERVICE: Record<string, string> = {
  varlatchd: "varlatchd",
  "varlatch-migrate": "varlatchd",
  "varlatch-web": "varlatch-web",
  "convex-backend": "convex-backend",
  postgres: "postgres",
  // Ingress overlays (pinned by release manifests from 0.10.0 on).
  caddy: "caddy",
  tailscale: "tailscale",
};

export function checkRelease(
  manifest: ReleaseManifest | null,
  pending: ReleaseManifest | null,
  services: ServiceState[],
  facts: ServerFacts | null,
): Check[] {
  const checks: Check[] = [];
  checks.push(pending
    ? {
        id: "release.pending-upgrade", title: "Upgrade completion", class: "mandatory", status: "fail",
        detail: `an upgrade to ${pending.version} was started and not completed`,
        remedy: `Rerun \`varlatch upgrade ${pending.version}\` to finish it`,
      }
    : { id: "release.pending-upgrade", title: "Upgrade completion", class: "mandatory", status: "pass", detail: "no upgrade in progress" });

  const base = { id: "release.consistency", title: "Running images match the release", class: "mandatory" as const };
  // During an upgrade the pending release is the one that should be running.
  const pinned = pending ?? manifest;
  if (!pinned) {
    checks.push({ ...base, status: "unknown", detail: "no varlatch-release.json here (source-built or platform-managed deployment); image pinning not checked" });
    return checks;
  }
  const problems: string[] = [];
  if (facts && facts.serverVersion !== pinned.version) {
    problems.push(`varlatchd reports ${facts.serverVersion}, manifest pins ${pinned.version}`);
  }
  for (const s of services) {
    const key = IMAGE_FOR_SERVICE[s.Service];
    const digest = key ? pinned.images[key]?.digest : null;
    if (!digest || !s.Image) continue;
    const sha = digest.slice(digest.indexOf("@") + 1);
    if (!s.Image.includes(sha)) problems.push(`${s.Service} runs ${s.Image}, manifest pins ${sha.slice(0, 19)}…`);
  }
  checks.push(problems.length
    ? { ...base, status: "fail", detail: problems.join("; "), remedy: "Re-apply the release: `docker compose pull && docker compose up -d`" }
    : { ...base, status: "pass", detail: `release ${pinned.version}${pending ? " (pending)" : ""}` });
  return checks;
}

/**
 * convex-backend runs the supervisor from a bind-mounted file whose image
 * never changes across releases, so a new file takes effect only when the
 * container restarts. A supervisor that records the hash of what it loaded is
 * judged by content: the host file may be rewritten, unchanged, after the
 * container started (Coolify does that on every deploy). Without that hash (a
 * supervisor from before it was recorded), a container started before the
 * file's last change still runs the previous supervisor. Not applicable
 * without the file or the container.
 */
export function checkSupervisor(
  fileModifiedMs: number | null,
  startedAt: string | null,
  hashes?: { file: string; loaded: string | null },
): Check | null {
  if (fileModifiedMs === null || !startedAt) return null;
  const started = Date.parse(startedAt);
  if (Number.isNaN(started)) return null;
  const base = { id: "application-plane.supervisor", title: "Convex supervisor runs the installed file", class: "mandatory" as const };
  if (hashes?.loaded) {
    return hashes.loaded === hashes.file
      ? { ...base, status: "pass", detail: "convex-backend runs the installed supervisor file (same content)" }
      : {
          ...base, status: "fail",
          detail: "convex-backend runs a different supervisor than the installed file",
          remedy: "docker compose up -d --no-deps --force-recreate convex-backend",
        };
  }
  return started >= fileModifiedMs
    ? { ...base, status: "pass", detail: "convex-backend started after the supervisor file last changed" }
    : {
        ...base, status: "fail",
        detail: `convex-backend started ${new Date(started).toISOString()}, before the supervisor file changed (${new Date(fileModifiedMs).toISOString()}): it still runs the previous supervisor`,
        remedy: "docker compose up -d --no-deps --force-recreate convex-backend",
      };
}

export function checkCliVersion(facts: ServerFacts | null, cliVersion = EMBEDDED_RELEASE.version): Check {
  const base = { id: "cli.version", title: "Host CLI matches the installation", class: "advisory" as const };
  if (!facts) return { ...base, status: "unknown", detail: `CLI ${cliVersion}; server version unavailable` };
  return compareVersions(cliVersion, facts.serverVersion) === 0
    ? { ...base, status: "pass", detail: cliVersion }
    : {
        ...base, status: "fail",
        detail: `CLI ${cliVersion}, installation ${facts.serverVersion}`,
        remedy: "Replace the host CLI with the installation's release (docs/operations/backup.md, Install the operator CLI)",
      };
}

/**
 * The oldest Docker Compose this release supports, for every ingress: the
 * Tailscale overlay uses `!reset`, which Compose 2.24 introduced.
 */
export const COMPOSE_MINIMUM = "2.24";

/**
 * The version in `docker compose version --short` output ("2.29.7",
 * "v2.24.0", "2.29.7-desktop.1", "5.5.1"). Only the numbers count: a suffix
 * such as Docker Desktop's "-desktop.1" does not make it a prerelease.
 */
export function parseComposeVersion(output: string): string | null {
  return output.match(/(?<![\w.])v?(\d+\.\d+(?:\.\d+)?)/)?.[1] ?? null;
}

/**
 * Docker Compose against the floor; `output` is `docker compose version
 * --short`, null when that did not run. `varlatch setup` refuses to start
 * unless this passes. Here it is advisory and outside the upgrade gate, like
 * the host CLI's version: it describes the host's tooling, not the
 * installation, and an upgrade neither changes it nor can fix it.
 */
export function checkComposeVersion(output: string | null): Check {
  const base = { id: "compose.version", title: `Docker Compose ${COMPOSE_MINIMUM} or newer`, class: "advisory" as const };
  if (output === null) {
    return {
      ...base, status: "fail",
      detail: "`docker compose version` did not run, so Docker or its Compose plugin is missing",
      remedy: `Install Docker with its Compose plugin, ${COMPOSE_MINIMUM} or newer`,
    };
  }
  const version = parseComposeVersion(output);
  if (!version) {
    return {
      ...base, status: "unknown",
      detail: output.trim() ? `found "${(output.trim().split("\n")[0] ?? "").slice(0, 60)}", not a version number` : "`docker compose version --short` printed no version",
      remedy: `Install a released Docker Compose, ${COMPOSE_MINIMUM} or newer`,
    };
  }
  return compareVersions(version, COMPOSE_MINIMUM) >= 0
    ? { ...base, status: "pass", detail: version }
    : { ...base, status: "fail", detail: `found ${version}`, remedy: `Update Docker Compose to ${COMPOSE_MINIMUM} or newer` };
}

const isLoopback = (host: string) => ["localhost", "127.0.0.1", "[::1]"].includes(host);

/**
 * The ports a Tailscale Serve configuration, as `tailscale serve status
 * --json` prints it, claims: TCP handlers and Web host:port handlers, at the
 * top level and in foreground sessions. Null when the output is not such a
 * configuration: then nothing can be concluded.
 */
export function servePorts(statusJson: string): Set<string> | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(statusJson);
  } catch {
    return null;
  }
  const isMap = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
  if (!isMap(parsed)) return null;
  // Absent or null (Go's empty map) is no foreground session; anything else
  // that is not a map of sessions is a shape this check does not know.
  const foreground = parsed.Foreground;
  if (foreground !== undefined && foreground !== null && !isMap(foreground)) return null;
  const configs = [parsed, ...(isMap(foreground) ? Object.values(foreground) : [])];
  const ports = new Set<string>();
  for (const config of configs) {
    if (!isMap(config)) return null;
    for (const [key, field] of [["TCP", "port"], ["Web", "host:port"]] as const) {
      const handlers = config[key];
      if (handlers === undefined || handlers === null) continue;
      if (!isMap(handlers)) return null;
      for (const k of Object.keys(handlers)) ports.add(field === "port" ? k : (k.split(":").pop() ?? k));
    }
  }
  return ports;
}

/**
 * The tailnet browser endpoint from the host's side (ADR-0046): the
 * dashboard's Content-Security-Policy must let browsers connect to it
 * (otherwise Connect fails with "not reachable from this browser"), and no
 * Tailscale Serve handler may sit on its port, where it would take the
 * connection and its device identity away from varlatchd. `serveStatus` is
 * the sidecar's applied Serve configuration (`tailscale serve status
 * --json`), null when it could not be read: never a pass then.
 */
export function checkTailnetBrowser(
  endpoint: string | null | undefined,
  cspConf: string | null,
  webEndpoint: string | null,
  serveStatus: string | null,
): Check[] {
  const checks: Check[] = [];
  const policy = { id: "tailnet.browser-policy", title: "Dashboard allows the tailnet browser endpoint", class: "advisory" as const };
  const connect = cspConf?.match(/connect-src ([^;"]*)/)?.[1]?.split(/\s+/) ?? null;
  if (endpoint) {
    checks.push(
      cspConf === null
        ? { ...policy, status: "unknown", detail: "could not read the dashboard's security policy (a varlatch-web image older than this check?)" }
        : connect?.includes(endpoint)
          ? { ...policy, status: "pass", detail: `connect-src allows ${endpoint}` }
          : {
              ...policy,
              status: "fail",
              detail: `varlatchd serves ${endpoint}, but the dashboard's connect-src allows only ${connect?.join(" ") ?? "nothing"}: browsers cannot reach the endpoint`,
              remedy: "Run `varlatch setup --tailnet-endpoint` again: it sets VARLATCH_TAILNET_ENDPOINT for varlatch-web",
            },
    );
    const port = new URL(endpoint).port;
    const direct = { id: "tailnet.browser-direct", title: "Tailnet browser endpoint reached directly", class: "mandatory" as const };
    const ports = serveStatus === null ? null : servePorts(serveStatus);
    checks.push(
      ports === null
        ? {
            ...direct, status: "unknown",
            detail: serveStatus === null
              ? "could not read Tailscale Serve's applied configuration from the tailscale container"
              : "Tailscale Serve's applied configuration is not in a form this check reads",
            remedy: "Check `docker compose exec tailscale tailscale serve status --json`",
          }
        : ports.has(port)
          ? {
              ...direct, status: "fail",
              detail: `Tailscale Serve handles port ${port}: it would take those connections, and with them the device's identity`,
              remedy: `Remove port ${port} from the Serve configuration (tailscale-serve.json, or \`tailscale serve\` in the container); nothing may proxy the browser endpoint`,
            }
          : { ...direct, status: "pass", detail: `the applied Serve configuration has no handler on port ${port}` },
    );
  } else if (webEndpoint) {
    checks.push({
      ...policy, status: "fail",
      detail: `varlatch-web allows ${webEndpoint} (VARLATCH_TAILNET_ENDPOINT), but varlatchd serves no tailnet browser endpoint`,
      remedy: "Run `varlatch setup` again (or `--tailnet-endpoint` to serve one)",
    });
  }
  return checks;
}

export function checkWebConfig(configJs: string | null, publicUrl: string | null): Check[] {
  const convexUrl = configJs?.match(/convexUrl:\s*"([^"]*)"/)?.[1] ?? "";
  const configured: Check = convexUrl
    ? { id: "web.live-updates", title: "Dashboard live-update endpoint", class: "advisory", status: "pass", detail: convexUrl }
    : {
        id: "web.live-updates", title: "Dashboard live-update endpoint", class: "advisory", status: "fail",
        detail: "varlatch-web serves no Convex URL; the dashboard runs without live updates",
        remedy: "Set CONVEX_CLOUD_ORIGIN and apply it with `docker compose up -d` (a restart keeps the old value)",
      };
  const checks = [configured];
  if (convexUrl && publicUrl) {
    let problem: string | null = null;
    try {
      const pub = new URL(publicUrl), cvx = new URL(convexUrl);
      if (!isLoopback(pub.hostname) && isLoopback(cvx.hostname)) {
        problem = `the dashboard at ${pub.origin} tells browsers to reach Convex at ${cvx.origin}, which is only reachable on this host`;
      } else if (pub.protocol === "https:" && cvx.protocol !== "https:" && !isLoopback(cvx.hostname)) {
        problem = `an HTTPS dashboard cannot open the insecure Convex endpoint ${cvx.origin} (mixed content)`;
      }
    } catch {
      problem = `unparseable Convex URL ${convexUrl}`;
    }
    checks.push(problem
      ? { id: "web.live-updates-reachable", title: "Live-update endpoint usable by browsers", class: "mandatory", status: "fail", detail: problem, remedy: "Set CONVEX_CLOUD_ORIGIN to the public HTTPS Convex origin and apply it with `docker compose up -d`" }
      : { id: "web.live-updates-reachable", title: "Live-update endpoint usable by browsers", class: "mandatory", status: "pass", detail: "consistent with the public URL" });
  }
  return checks;
}

function readManifest(path: string): ReleaseManifest | null {
  if (!existsSync(path)) return null;
  try { return parseManifest(readFileSync(path, "utf8"), path); } catch { return null; }
}

export async function runDoctor(opts: { dir: string; waitSeconds?: number; run?: Runner }): Promise<DoctorReport> {
  const dir = resolve(opts.dir);
  const run = opts.run ?? dockerRunner(dir);
  const checks: Check[] = [];

  // First, so a missing or old Compose is named even when listing the project fails.
  const compose = await run(["compose", "version", "--short"]);
  checks.push(checkComposeVersion(compose.code === 0 ? compose.stdout : null));

  const ps = await run(["compose", "ps", "--all", "--format", "json"]);
  let services: ServiceState[] = [];
  try {
    if (ps.code !== 0) throw new Error();
    services = parseComposePs(ps.stdout);
  } catch {
    checks.push({
      id: "docker.compose", title: "Docker Compose project", class: "mandatory", status: "fail",
      detail: `could not list the Compose project in ${dir}`,
      remedy: "Run from the Compose directory (or pass --dir) as a user with Docker access",
    });
    return { dir, facts: null, checks };
  }
  checks.push(...checkServices(services));

  let facts: ServerFacts | null = null;
  const wait = String(opts.waitSeconds ?? 15);
  const server = await run(["compose", "exec", "-T", "varlatchd", "node", "dist/cli.js", "admin", "doctor", "--wait", wait], (Number(wait) + 60) * 1000);
  try {
    if (server.code !== 0) throw new Error();
    const report = JSON.parse(server.stdout.split("\n").pop() ?? "") as { facts: ServerFacts; checks: Check[] };
    facts = report.facts;
    checks.push(...report.checks);
  } catch {
    checks.push({
      id: "secret-plane.ready", title: "Secret Plane ready", class: "mandatory", status: "unknown",
      detail: "could not query varlatchd (not running, or an image older than this check)",
      remedy: "Check `docker compose ps varlatchd` and `docker compose logs varlatchd`",
    });
  }

  checks.push(...checkRelease(
    readManifest(join(dir, "varlatch-release.json")),
    readManifest(join(dir, "varlatch-release.json.pending")),
    services,
    facts,
  ));
  checks.push(checkCliVersion(facts));

  const web = await run(["compose", "exec", "-T", "varlatch-web", "cat", "/usr/share/nginx/html/varlatch-config.js"]);
  checks.push(...checkWebConfig(web.code === 0 ? web.stdout : null, facts?.publicUrl ?? null));
  const csp = await run(["compose", "exec", "-T", "varlatch-web", "cat", "/etc/nginx/varlatch/csp.conf"]);
  const webEndpoint = await run(["compose", "exec", "-T", "varlatch-web", "printenv", "VARLATCH_TAILNET_ENDPOINT"]);
  // What Serve actually applies in the sidecar, not a file on the host.
  const serve = facts?.tailnetBrowserEndpoint ? await run(["compose", "exec", "-T", "tailscale", "tailscale", "serve", "status", "--json"]) : null;
  checks.push(
    ...checkTailnetBrowser(
      facts?.tailnetBrowserEndpoint,
      csp.code === 0 ? csp.stdout : null,
      webEndpoint.code === 0 ? webEndpoint.stdout.trim() || null : null,
      serve && serve.code === 0 ? serve.stdout : null,
    ),
  );
  const resolved = await run(["compose", "--profile", "deploy", "config", "--format", "json"]);
  let config: import("./adopt.js").ComposeConfig | null = null;
  try { config = resolved.code === 0 ? JSON.parse(resolved.stdout) : null; } catch { /* unknown below */ }
  const { checkAdoption } = await import("./adopt.js");
  checks.push(checkAdoption(config, dir));
  const { checkComposeOverride } = await import("./setup.js");
  const override = checkComposeOverride(dir);
  if (override) checks.push(override);
  const supervisor = await supervisorCheck(config, services, run);
  if (supervisor) checks.push(supervisor);
  checks.push({
    id: "realtime.browser", title: "Browser live-update connection", class: "mandatory", status: "unknown",
    detail: "only measurable from a browser; open the dashboard and check for a reconnecting indicator",
  });

  return { dir, facts, checks };
}

async function supervisorCheck(config: import("./adopt.js").ComposeConfig | null, services: ServiceState[], run: Runner): Promise<Check | null> {
  const volumes = (config?.services["convex-backend"] as { volumes?: { source?: string; target?: string }[] } | undefined)?.volumes ?? [];
  const source = volumes.find((v) => v.target === "/convex/varlatch-supervisor.cjs")?.source;
  const id = services.find((s) => s.Service === "convex-backend" && s.State === "running")?.ID;
  if (!source || !existsSync(source) || !id) return null;
  const inspected = await run(["inspect", "--format", "{{.State.StartedAt}}", id]);
  const loaded = await run(["exec", id, "cat", "/tmp/varlatch-supervisor.sha256"]);
  const file = createHash("sha256").update(readFileSync(source)).digest("hex");
  return checkSupervisor(statSync(source).mtimeMs, inspected.code === 0 ? inspected.stdout : null, {
    file,
    loaded: loaded.code === 0 && /^[0-9a-f]{64}$/.test(loaded.stdout.trim()) ? loaded.stdout.trim() : null,
  });
}

/**
 * The upgrade gate (ADR-0035 D11): the mandatory checks the upgrade workflow
 * can always run from the host. Each must PASS — unknown blocks like fail; a
 * required check that is missing counts as unknown. Conditional checks gate
 * where they apply (a leftover convex-deploy container, the supervisor file,
 * a configured live-update endpoint). Browser realtime is measured by the
 * browser, not here, and the pending-upgrade check is what the gate clears.
 */
export const UPGRADE_GATE = {
  required: ["services.running", "secret-plane.ready", "release.consistency", "config.public-url", "mirror.catch-up", "application-plane.functions"],
  conditional: ["application-plane.deploy", "application-plane.supervisor", "web.live-updates-reachable"],
} as const;

export interface GateVerdict {
  pass: boolean;
  /** Gate checks that did not pass (or were not reported). */
  blocking: Check[];
  /** Advisory findings and unknowns: shown, never blocking. */
  advisory: Check[];
  /** Mandatory checks outside the gate that did not pass, e.g. browser realtime. */
  outsideGate: Check[];
}

export function evaluateGate(report: DoctorReport): GateVerdict {
  const byId = new Map(report.checks.map((c) => [c.id, c]));
  const blocking: Check[] = [];
  for (const id of UPGRADE_GATE.required) {
    const c = byId.get(id);
    if (!c) blocking.push({ id, title: id, class: "mandatory", status: "unknown", detail: "not reported: doctor could not run this check" });
    else if (c.status !== "pass") blocking.push(c);
  }
  for (const id of UPGRADE_GATE.conditional) {
    const c = byId.get(id);
    if (c && c.status !== "pass") blocking.push(c);
  }
  const gated = new Set<string>([...UPGRADE_GATE.required, ...UPGRADE_GATE.conditional, "release.pending-upgrade"]);
  return {
    pass: blocking.length === 0,
    blocking,
    advisory: report.checks.filter((c) => c.class === "advisory" && c.status !== "pass"),
    outsideGate: report.checks.filter((c) => c.class === "mandatory" && !gated.has(c.id) && c.status !== "pass"),
  };
}

export function formatGate(verdict: GateVerdict): string {
  const line = (c: Check) => [`  ${c.status === "unknown" ? "?" : "✗"} ${c.title}: ${c.detail ?? c.status}`, ...(c.remedy ? [`      → ${c.remedy}`] : [])];
  const lines = verdict.pass
    ? ["Upgrade gate: PASS — every gate check passed."]
    : ["Upgrade gate: BLOCKED — these must pass (unknown blocks like fail):", ...verdict.blocking.flatMap(line)];
  if (verdict.outsideGate.length) lines.push("Not measurable from this host (check after the upgrade):", ...verdict.outsideGate.map((c) => `  ? ${c.title}: ${c.detail ?? c.status}`));
  if (verdict.advisory.length) lines.push("Advisory (never blocks):", ...verdict.advisory.map((c) => `  ! ${c.title}: ${c.detail ?? c.status}`));
  return lines.join("\n");
}

export function doctorExitCode(report: DoctorReport): number {
  return report.checks.some((c) => c.class === "mandatory" && c.status === "fail") ? 1 : 0;
}

export function formatDoctor(report: DoctorReport): string {
  const lines = [
    `Varlatch doctor — ${report.dir}${report.facts ? ` (server ${report.facts.serverVersion})` : ""}`,
    "",
  ];
  const mark = (c: Check) => (c.status === "pass" ? "✓" : c.status === "unknown" ? "?" : c.class === "mandatory" ? "✗" : "!");
  const order = (c: Check) =>
    c.status === "fail" && c.class === "mandatory" ? 0 : c.status === "fail" ? 1 : c.status === "unknown" ? 2 : 3;
  for (const c of [...report.checks].sort((a, b) => order(a) - order(b))) {
    const tag = c.status === "pass" ? "" : `  [${c.class}${c.status === "unknown" ? ", unknown" : ""}]`;
    lines.push(`${mark(c)} ${c.title}${tag}`);
    if (c.detail) lines.push(`    ${c.detail}`);
    if (c.remedy && c.status !== "pass") lines.push(`    → ${c.remedy}`);
  }
  const failed = report.checks.filter((c) => c.status === "fail" && c.class === "mandatory").length;
  const advisory = report.checks.filter((c) => c.status === "fail" && c.class === "advisory").length;
  const unknown = report.checks.filter((c) => c.status === "unknown").length;
  lines.push("", `${failed} mandatory failure(s), ${advisory} advisory finding(s), ${unknown} unknown. Read-only: nothing was changed.`);
  return lines.join("\n");
}
