// SPDX-License-Identifier: Apache-2.0
import type {
  CredentialLifetimeConfig,
  SecurityControl,
  SecurityControlChange,
  SecurityControlChangeInput,
  SecurityControlList,
  SecurityControlMode,
  SecurityControlName,
  VarlatchClient,
} from "@varlatch/sdk";

/**
 * `varlatch security controls` and `varlatch security set` (ADR-0054
 * Decisions 1 and 2, capability security.controls): the Organization's
 * Security Controls, and changing one. Tightening applies at once;
 * loosening (a mode towards off, a longer lifetime, cleared settings) needs
 * the person's approval with a trusted passkey, which the shared step-up
 * handling asks for (approvals.ts). `enforce` is not offered yet.
 */

export const SECURITY_CONTROLS_CAPABILITY = "security.controls";

export const CONTROL_NAMES: readonly SecurityControlName[] = [
  "requirement-protection",
  "admin-step-up",
  "passkey-verification",
  "credential-lifetime",
];
export const CONTROL_MODES: readonly SecurityControlMode[] = ["off", "report", "enforce"];

export const SECURITY_CONTROLS_USAGE = "Usage: varlatch security controls [--json] [--org <organization>] [--server <url>]";
export const SECURITY_SET_USAGE =
  "Usage: varlatch security set <control> <off|report|enforce> [--default-ttl <seconds>] [--max-ttl <seconds>] [--clear-config] " +
  "[--approval <id>] [--json] [--org <organization>] [--server <url>]";

/** A command line that cannot be right: exit 64. */
export class SecurityUsageError extends Error {
  override name = "SecurityUsageError";
}

/** The server cannot do it: it lacks the capability, or the mode. Exit 1. */
export class SecurityControlsError extends Error {
  override name = "SecurityControlsError";
}

export interface SetRequest {
  control: SecurityControlName;
  mode: SecurityControlMode;
  defaultTtlSeconds?: number | undefined;
  maxTtlSeconds?: number | undefined;
  clearConfig: boolean;
}

function seconds(flag: string, raw: string | undefined): number | undefined {
  if (raw === undefined) return undefined;
  if (!/^[1-9]\d{0,9}$/.test(raw)) throw new SecurityUsageError(`${flag} takes a whole number of seconds, more than 0: ${raw}`);
  return Number(raw);
}

/** Check `security set`'s arguments before any request. */
export function parseSetRequest(
  positionals: readonly string[],
  values: ReadonlyMap<string, string>,
  booleans: ReadonlySet<string>,
): SetRequest {
  const [control, mode] = positionals;
  if (!control || !mode) throw new SecurityUsageError("give the control and the mode");
  if (!(CONTROL_NAMES as readonly string[]).includes(control)) {
    throw new SecurityUsageError(`no control ${control}; the controls are ${CONTROL_NAMES.join(", ")}`);
  }
  if (!(CONTROL_MODES as readonly string[]).includes(mode)) {
    throw new SecurityUsageError(`no mode ${mode}; the modes are ${CONTROL_MODES.join(", ")}`);
  }
  const defaultTtlSeconds = seconds("--default-ttl", values.get("--default-ttl"));
  const maxTtlSeconds = seconds("--max-ttl", values.get("--max-ttl"));
  const clearConfig = booleans.has("--clear-config");
  const configures = defaultTtlSeconds !== undefined || maxTtlSeconds !== undefined || clearConfig;
  if (configures && control !== "credential-lifetime") {
    throw new SecurityUsageError("--default-ttl, --max-ttl and --clear-config go with credential-lifetime only");
  }
  if (clearConfig && (defaultTtlSeconds !== undefined || maxTtlSeconds !== undefined)) {
    throw new SecurityUsageError("--clear-config cannot be combined with --default-ttl or --max-ttl");
  }
  if (defaultTtlSeconds !== undefined && maxTtlSeconds !== undefined && defaultTtlSeconds > maxTtlSeconds) {
    throw new SecurityUsageError("--default-ttl cannot be more than --max-ttl");
  }
  return { control: control as SecurityControlName, mode: mode as SecurityControlMode, defaultTtlSeconds, maxTtlSeconds, clearConfig };
}

export type SecurityApi = Pick<VarlatchClient, "meta" | "listSecurityControls" | "changeSecurityControl">;

async function requireCapability(api: SecurityApi, command: string): Promise<void> {
  const meta = await api.meta();
  if (!meta.capabilities.includes(SECURITY_CONTROLS_CAPABILITY)) {
    throw new SecurityControlsError(
      `varlatch ${command}: this server (${meta.serverVersion}) has no security controls ` +
        `(it lacks the ${SECURITY_CONTROLS_CAPABILITY} capability); upgrade the server.`,
    );
  }
}

/**
 * The modes the server accepts for this control: its own list where the
 * server gives one (enforce only where that control can enforce), the
 * modes every control accepts on an older server.
 */
export function modesOf(list: Pick<SecurityControlList, "availableModes">, control: Pick<SecurityControl, "availableModes">): SecurityControlMode[] {
  return control.availableModes ?? list.availableModes;
}

/** The controls this server can enforce. */
export function enforceable(list: SecurityControlList): SecurityControl["control"][] {
  return list.items.filter((c) => modesOf(list, c).includes("enforce")).map((c) => c.control);
}

export async function fetchControls(api: SecurityApi, organization: string): Promise<SecurityControlList> {
  await requireCapability(api, "security controls");
  return api.listSecurityControls(organization);
}

/** The body of the change: the requested mode, and the configuration it sets, keeps or clears. */
export function changeInput(request: SetRequest, current: SecurityControl): SecurityControlChangeInput {
  const input: SecurityControlChangeInput = { mode: request.mode, expectedVersion: current.version };
  if (request.clearConfig) {
    input.config = null;
  } else if (request.defaultTtlSeconds !== undefined || request.maxTtlSeconds !== undefined) {
    const defaultTtlSeconds = request.defaultTtlSeconds ?? current.config?.defaultTtlSeconds;
    const maxTtlSeconds = request.maxTtlSeconds ?? current.config?.maxTtlSeconds;
    if (defaultTtlSeconds === undefined || maxTtlSeconds === undefined) {
      throw new SecurityUsageError("credential-lifetime has no lifetimes yet: give both --default-ttl and --max-ttl");
    }
    if (defaultTtlSeconds > maxTtlSeconds) {
      throw new SecurityUsageError(`the default lifetime (${defaultTtlSeconds} s) cannot be more than the maximum (${maxTtlSeconds} s)`);
    }
    input.config = { defaultTtlSeconds, maxTtlSeconds };
  }
  return input;
}

/**
 * Change one control: read its current version (and lifetimes), refuse a
 * mode this server does not offer, then send the change. Loosening goes
 * through the client's step-up handling.
 */
export async function setControl(
  api: SecurityApi,
  organization: string,
  request: SetRequest,
): Promise<{ before: SecurityControl; change: SecurityControlChange }> {
  await requireCapability(api, "security set");
  const list = await api.listSecurityControls(organization);
  const current = list.items.find((c) => c.control === request.control);
  if (!current) throw new SecurityControlsError(`varlatch security set: this server has no control ${request.control}. Nothing was changed.`);
  const offered = modesOf(list, current);
  if (!offered.includes(request.mode)) {
    throw new SecurityControlsError(
      `varlatch security set: this server does not offer the mode ${request.mode} for ${request.control} yet ` +
        `(it offers ${offered.join(", ")}). Nothing was changed.`,
    );
  }
  const change = await api.changeSecurityControl(organization, request.control, changeInput(request, current));
  return { before: current, change };
}

/** A lifetime as people read it: "12 hours", "30 days", "90 seconds". */
export function lifetime(totalSeconds: number): string {
  const unit = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;
  if (totalSeconds % 86400 === 0) return unit(totalSeconds / 86400, "day");
  if (totalSeconds % 3600 === 0) return unit(totalSeconds / 3600, "hour");
  if (totalSeconds % 60 === 0) return unit(totalSeconds / 60, "minute");
  return unit(totalSeconds, "second");
}

function configWords(config: CredentialLifetimeConfig | null): string {
  return config ? `default ${lifetime(config.defaultTtlSeconds)}, at most ${lifetime(config.maxTtlSeconds)}` : "";
}

function changedWords(c: SecurityControl): string {
  if (c.version === 0 || !c.changedAt) return "never changed";
  return `changed ${c.changedAt}${c.changedBy ? ` by ${c.changedBy.name ?? c.changedBy.id}` : " by the host operator"}`;
}

/** The human format of `security controls`. */
export function controlsLines(organization: string, list: SecurityControlList): string[] {
  const width = Math.max(...list.items.map((c) => c.control.length));
  const lines = [`Security controls for ${organization}:`];
  for (const c of list.items) {
    const config = configWords(c.config);
    lines.push(`  ${c.control.padEnd(width)}  ${c.mode.padEnd(7)}${config ? `  ${config}` : ""}  (version ${c.version}, ${changedWords(c)})`);
  }
  const enforcing = enforceable(list);
  lines.push(
    "",
    `Modes this server offers: ${list.availableModes.join(", ")}` +
      (enforcing.length > 0 ? `, and enforce for ${enforcing.join(", ")}.` : ". enforce is not available yet."),
    "Loosening a control (a mode towards off, a longer lifetime, cleared settings) needs your approval with a trusted passkey.",
  );
  return lines;
}

/** The human format of `security set`'s result. */
export function setLines(organization: string, before: SecurityControlMode | null, change: SecurityControlChange): string[] {
  const c = change.control;
  if (!change.changed) return [`${c.control} in ${organization} is already ${c.mode}${c.config ? ` (${configWords(c.config)})` : ""}. Nothing was changed.`];
  const lines = [
    `${c.control} in ${organization}: ${before && before !== c.mode ? `${before} -> ` : ""}${c.mode}` +
      `${c.config ? ` (${configWords(c.config)})` : ""}, version ${c.version}.`,
  ];
  if (change.loosened) lines.push("This loosened the control; your approval was used.");
  if (c.control === "passkey-verification" && c.mode === "enforce" && before !== "enforce") {
    lines.push(
      `From now on ${organization} refuses a person's sign-in that was not made with a trusted passkey that verified them (PIN, fingerprint or face),`,
      "admins included, until they sign in again with one. Machine credentials are not affected.",
      "Someone whose passkeys cannot verify them gets back in only through the host operator: varlatch admin security reset.",
    );
  }
  return lines;
}
