// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from "node:fs";
import { z } from "zod";
import { parseTrustedProxies } from "./http/client-address.js";

/**
 * varlatchd runtime configuration. The root KEK is canonically supplied via a
 * mounted file (VARLATCH_KEK_FILE); the environment-variable form exists as a
 * documented fallback with extra persistence/exposure implications (ADR-0011).
 */
/** Compose passes optional vars as empty strings; treat those as unset. */
const optional = <T extends z.ZodTypeAny>(schema: T) =>
  z.preprocess((v) => (v === "" ? undefined : v), schema.optional());

const envSchema = z.object({
  VARLATCH_DATABASE_URL: z.string().min(1),
  // Per-service secret file (#28): fills the URL's password when the URL
  // carries none. On Coolify every environment variable reaches every
  // service, so a password that must stay in one service comes from a file.
  VARLATCH_DATABASE_PASSWORD_FILE: optional(z.string().min(1)),
  VARLATCH_KEK_FILE: optional(z.string().min(1)),
  VARLATCH_KEK: optional(z.string().min(1)),
  VARLATCH_PORT: z.coerce.number().int().min(1).max(65535).default(8686),
  VARLATCH_PUBLIC_URL: optional(z.string().url()),
  VARLATCH_CONVEX_URL: optional(z.string().url()),
  // Optional Tailscale integration (ADR-0014): all three must be set to
  // enable the dedicated tailnet listener.
  VARLATCH_TAILSCALE_SOCKET: optional(z.string().min(1)),
  VARLATCH_TAILSCALE_TAILNET: optional(z.string().min(1)),
  VARLATCH_TAILNET_PORT: optional(z.coerce.number().int().min(1).max(65535)),
  VARLATCH_TAILNET_BIND: optional(z.string().min(1)),
  // The tailnet browser endpoint (ADR-0046): HTTPS on this port, off unless
  // set. Needs the node's machine name for its certificate, and serves the
  // dashboard's origin plus any listed here (exact origins, comma-separated).
  VARLATCH_TAILNET_HTTPS_PORT: optional(z.coerce.number().int().min(1).max(65535)),
  VARLATCH_TAILNET_MACHINE: optional(z.string().min(1)),
  VARLATCH_TAILNET_BROWSER_ORIGINS: optional(z.string()),
  // Outbound sync installation switch (ADR-0031 §9): default on; "on" only
  // means authorized users MAY configure integrations. An Infrastructure
  // Operator sets "off" for locked-down networks/stricter postures; the UI
  // then points at the CLI mode.
  VARLATCH_SYNC: optional(z.enum(["on", "off"])),
  // Optional adapter allowlist narrowing (comma-separated platform names).
  VARLATCH_SYNC_ADAPTERS: optional(z.string().min(1)),
  // Proxies whose X-Forwarded-For the ordinary listener believes
  // (http/client-address.ts): comma-separated IPs, CIDR ranges, and host
  // names, such as the compose service varlatch-web. Unset: none.
  VARLATCH_TRUSTED_PROXIES: optional(z.string()),
});

export interface VarlatchdConfig {
  databaseUrl: string;
  port: number;
  publicUrl: string | undefined;
  /** The issuer of the tokens varlatchd signs: publicUrl, else localhost:port. */
  issuer: string;
  convexUrl: string | undefined;
  tailscale:
    | {
        socketPath: string;
        expectedTailnet: string;
        port: number;
        bind: string;
        /** The browser endpoint (ADR-0046); null when off, the default. */
        browser: { host: string; port: number; origins: string[] } | null;
      }
    | null;
  /** Outbound sync (ADR-0031): null when disabled on this Installation. */
  sync: { adapters: string[] | null } | null;
  /** VARLATCH_TRUSTED_PROXIES, validated; null when no proxy is trusted. */
  trustedProxies: string | null;
  /** Loads and validates the raw 32-byte root KEK. Never log its value. */
  loadRootKek: () => Buffer;
}

export class ConfigError extends Error {
  override name = "ConfigError";
}

function parseKekMaterial(raw: string, source: string): Buffer {
  const trimmed = raw.trim();
  let key: Buffer;
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    key = Buffer.from(trimmed, "hex");
  } else {
    try {
      key = Buffer.from(trimmed, "base64");
    } catch {
      throw new ConfigError(`Root KEK from ${source} is neither hex nor base64`);
    }
  }
  if (key.length !== 32) {
    throw new ConfigError(
      `Root KEK from ${source} must be 32 bytes (got ${key.length}); ` +
        "generate one with: openssl rand -hex 32",
    );
  }
  return key;
}

/**
 * Applies a database password file (#28). An empty or missing file changes
 * nothing, and a password already in the URL wins — existing installations
 * that pass it through the environment behave exactly as before.
 */
export function withPasswordFile(databaseUrl: string, passwordFile: string | undefined): string {
  if (!passwordFile) return databaseUrl;
  let password = "";
  try {
    password = readFileSync(passwordFile, "utf8").replace(/\r?\n$/, "");
  } catch {
    return databaseUrl;
  }
  if (!password) return databaseUrl;
  let url: URL;
  try {
    url = new URL(databaseUrl);
  } catch {
    throw new ConfigError("VARLATCH_DATABASE_URL is not a valid URL");
  }
  if (url.password) return databaseUrl;
  url.password = encodeURIComponent(password);
  return url.toString();
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);
/** A DNS name or IPv4 address (lowercase, as the URL parser leaves it), or a bracketed IPv6 address. */
const ORIGIN_HOST = /^(\[[0-9a-f:.]+\]|[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*)$/;

/**
 * An origin the browser endpoint lets read cross-origin, exactly as a
 * browser sends it: scheme, host and port, nothing else. HTTPS, or plain
 * HTTP on loopback for local development. Never `null` or a wildcard.
 */
function browserOrigin(raw: string, source: string): string {
  if (raw === "*" || raw === "null") throw new ConfigError(`${source}: "${raw}" is never allowed; list exact origins`);
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ConfigError(`${source}: "${raw}" is not an origin such as https://varlatch.example.com`);
  }
  if (!(url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK.has(url.hostname)))) {
    throw new ConfigError(`${source}: "${raw}" must use https (plain http only on localhost)`);
  }
  if (url.origin !== raw) throw new ConfigError(`${source}: "${raw}" must be exactly an origin, written ${url.origin}`);
  // The URL parser accepts characters no browser origin carries, "*" among them.
  if (!ORIGIN_HOST.test(url.hostname)) throw new ConfigError(`${source}: "${raw}" must name one host; wildcards are never allowed`);
  return raw;
}

/** The node's machine name: one lowercase DNS label, as Tailscale names machines. */
const MACHINE_NAME = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

function tailnetBrowser(
  cfg: z.infer<typeof envSchema>,
  tailnet: string | undefined,
): { host: string; port: number; origins: string[] } | null {
  const port = cfg.VARLATCH_TAILNET_HTTPS_PORT;
  if (port === undefined) return null;
  if (!tailnet || !cfg.VARLATCH_TAILNET_PORT) {
    throw new ConfigError("VARLATCH_TAILNET_HTTPS_PORT needs the tailnet listener: set VARLATCH_TAILSCALE_SOCKET, VARLATCH_TAILSCALE_TAILNET, and VARLATCH_TAILNET_PORT.");
  }
  if (port === cfg.VARLATCH_TAILNET_PORT || port === cfg.VARLATCH_PORT) {
    throw new ConfigError("VARLATCH_TAILNET_HTTPS_PORT must differ from VARLATCH_PORT and VARLATCH_TAILNET_PORT.");
  }
  const machine = cfg.VARLATCH_TAILNET_MACHINE;
  if (!machine || !MACHINE_NAME.test(machine)) {
    throw new ConfigError(
      "VARLATCH_TAILNET_HTTPS_PORT needs VARLATCH_TAILNET_MACHINE, the node's machine name in lowercase " +
        `(its certificate is for <machine>.${tailnet}).`,
    );
  }
  // The dashboard's own origin by default, but only over HTTPS: a page
  // served in plain text could be altered on the way to an approved device.
  const origins = new Set<string>();
  if (cfg.VARLATCH_PUBLIC_URL) {
    const dashboard = new URL(cfg.VARLATCH_PUBLIC_URL);
    if (dashboard.protocol === "https:" || LOOPBACK.has(dashboard.hostname)) origins.add(dashboard.origin);
  }
  for (const raw of (cfg.VARLATCH_TAILNET_BROWSER_ORIGINS ?? "").split(",")) {
    const entry = raw.trim();
    if (entry) origins.add(browserOrigin(entry, "VARLATCH_TAILNET_BROWSER_ORIGINS"));
  }
  if (origins.size === 0) {
    throw new ConfigError(
      "VARLATCH_TAILNET_HTTPS_PORT needs a dashboard origin it may serve: an https VARLATCH_PUBLIC_URL, " +
        "or exact origins in VARLATCH_TAILNET_BROWSER_ORIGINS.",
    );
  }
  return { host: `${machine}.${tailnet}`.toLowerCase(), port, origins: [...origins] };
}

export function loadConfig(
  env: NodeJS.ProcessEnv = process.env,
  opts: { requireKek?: boolean } = {},
): VarlatchdConfig {
  const parsed = envSchema.safeParse(env);
  if (!parsed.success) {
    throw new ConfigError(
      `Invalid configuration: ${parsed.error.issues
        .map((i) => `${i.path.join(".")}: ${i.message}`)
        .join("; ")}`,
    );
  }
  const cfg = parsed.data;
  // The migrate entrypoint runs under the elevated DB role and never touches
  // key material (ADR-0019); it may run without a KEK configured.
  if ((opts.requireKek ?? true) && !cfg.VARLATCH_KEK_FILE && !cfg.VARLATCH_KEK) {
    throw new ConfigError(
      "No root KEK configured. Set VARLATCH_KEK_FILE (recommended: a mounted " +
        "secret file such as /run/secrets/varlatch-kek) or VARLATCH_KEK.",
    );
  }
  const tailscaleVars = [
    cfg.VARLATCH_TAILSCALE_SOCKET,
    cfg.VARLATCH_TAILSCALE_TAILNET,
    cfg.VARLATCH_TAILNET_PORT,
  ];
  if (tailscaleVars.some(Boolean) && !tailscaleVars.every(Boolean)) {
    throw new ConfigError(
      "Partial Tailscale configuration: set all of VARLATCH_TAILSCALE_SOCKET, " +
        "VARLATCH_TAILSCALE_TAILNET, and VARLATCH_TAILNET_PORT, or none.",
    );
  }
  const browser = tailnetBrowser(cfg, cfg.VARLATCH_TAILSCALE_TAILNET);
  const trustedProxies = cfg.VARLATCH_TRUSTED_PROXIES?.trim() || null;
  if (trustedProxies) {
    try {
      parseTrustedProxies(trustedProxies);
    } catch (err) {
      throw new ConfigError(err instanceof Error ? err.message : String(err));
    }
  }
  return {
    trustedProxies,
    databaseUrl: withPasswordFile(cfg.VARLATCH_DATABASE_URL, cfg.VARLATCH_DATABASE_PASSWORD_FILE),
    port: cfg.VARLATCH_PORT,
    publicUrl: cfg.VARLATCH_PUBLIC_URL,
    // The one token issuer (#110): the server, the Mirror publisher, and
    // `admin mirror-sync` must agree, and Convex trusts exactly this value.
    // Compose refuses to start without VARLATCH_PUBLIC_URL; the localhost
    // fallback serves a bare `node dist/cli.js` run only.
    issuer: cfg.VARLATCH_PUBLIC_URL ?? `http://localhost:${cfg.VARLATCH_PORT}`,
    convexUrl: cfg.VARLATCH_CONVEX_URL,
    sync:
      cfg.VARLATCH_SYNC === "off"
        ? null
        : {
            adapters: cfg.VARLATCH_SYNC_ADAPTERS
              ? cfg.VARLATCH_SYNC_ADAPTERS.split(",").map((a) => a.trim()).filter(Boolean)
              : null,
          },
    tailscale:
      cfg.VARLATCH_TAILSCALE_SOCKET && cfg.VARLATCH_TAILSCALE_TAILNET && cfg.VARLATCH_TAILNET_PORT
        ? {
            socketPath: cfg.VARLATCH_TAILSCALE_SOCKET,
            expectedTailnet: cfg.VARLATCH_TAILSCALE_TAILNET,
            port: cfg.VARLATCH_TAILNET_PORT,
            bind: cfg.VARLATCH_TAILNET_BIND ?? "0.0.0.0",
            browser,
          }
        : null,
    loadRootKek: () => {
      if (cfg.VARLATCH_KEK_FILE) {
        let raw: string;
        try {
          raw = readFileSync(cfg.VARLATCH_KEK_FILE, "utf8");
        } catch (err) {
          throw new ConfigError(
            `Cannot read root KEK file ${cfg.VARLATCH_KEK_FILE}: ${
              err instanceof Error ? err.message : String(err)
            }`,
          );
        }
        return parseKekMaterial(raw, `file ${cfg.VARLATCH_KEK_FILE}`);
      }
      return parseKekMaterial(cfg.VARLATCH_KEK as string, "environment variable");
    },
  };
}
