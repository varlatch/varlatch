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
  convexUrl: string | undefined;
  tailscale:
    | { socketPath: string; expectedTailnet: string; port: number; bind: string }
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
