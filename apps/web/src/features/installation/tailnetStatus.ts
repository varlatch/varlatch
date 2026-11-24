// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ObservedCheck, ObservedNode, TailnetListenerReport } from "@varlatch/protocol";
import { CONTAINER, hostCommand, type Deployment } from "./deployment";

/**
 * The Installation page's Tailnet tab (GET /v1/installation/listeners):
 * what varlatchd checks itself, at start and every 60 seconds. None of it
 * says whether a device reaches a listener. That depends on the tailnet
 * policy, and only the device can find out (Connect to tailnet).
 */

/** Older than this, a report says nothing about now. The server's doctor uses the same limit. */
export const LISTENERS_STALE_MS = 10 * 60_000;

/** The browser endpoint's port, as setup chooses it. */
export const ENDPOINT_PORT = 8688;

/** For when the report names no usable node (an older server, or a failed read). */
export const NODE_PLACEHOLDER = "<this node's tag or Tailscale address>";

export const DOCS_TAILSCALE_URL = "https://docs.varlatch.com/self-hosting/configuration/#tailscale";
export const DOCS_ENDPOINT_URL = "https://docs.varlatch.com/self-hosting/configuration/#tailnet-browser-endpoint";

export type ListenerReason = NonNullable<ObservedCheck["reason"]>;

/** Each reason in words. */
export const REASON_TEXT: Record<ListenerReason, string> = {
  NOT_CHECKED: "Not checked yet",
  NOT_LISTENING: "A tailnet listener did not bind its port",
  NO_CERTIFICATE: "No valid certificate is loaded",
  LOCALAPI_UNAVAILABLE: "The tailnet node does not answer varlatchd",
  NOT_RUNNING: "The node is not connected to the tailnet",
  OTHER_TAILNET: "The node is on another tailnet than the configured one",
  NAME_CHANGED: "The node's name is no longer the browser endpoint's host",
  TAGS_DIFFER: "The node's tags are not tailnet_tags",
};

export type Tone = "ok" | "warn" | "error" | "muted";

export function checkTone(status: ObservedCheck["status"]): Tone {
  return status === "pass" ? "ok" : status === "fail" ? "error" : "muted";
}

export type CheckRow = {
  key: "listener" | "localApi" | "node" | "browserTls";
  label: string;
  /** What passing means, for this configuration. */
  passes: string;
  check: ObservedCheck;
};

/** The report's checks in display order; the certificate only with the browser endpoint. */
export function checkRows(report: TailnetListenerReport): CheckRow[] {
  const { configured, observed } = report;
  const endpoint = configured.browserEndpoint !== null;
  const rows: CheckRow[] = [
    {
      key: "listener",
      label: "Listeners",
      passes: endpoint
        ? `The tailnet listener (port ${configured.listenerPort}) and the browser endpoint are bound`
        : `The tailnet listener (port ${configured.listenerPort}) is bound`,
      check: observed.checks.listener,
    },
    { key: "localApi", label: "Node's answer", passes: "The tailnet node answers varlatchd", check: observed.checks.localApi },
    {
      key: "node",
      label: "Node",
      passes: endpoint ? `Connected to ${configured.tailnet}, under the endpoint's name` : `Connected to ${configured.tailnet}`,
      check: observed.checks.node,
    },
  ];
  if (observed.checks.browserTls) {
    rows.push({ key: "browserTls", label: "Endpoint certificate", passes: "A valid certificate for the endpoint is loaded", check: observed.checks.browserTls });
  }
  return rows;
}

export type TailnetSummary = {
  tone: Tone;
  headline: string;
  /** Older than LISTENERS_STALE_MS: the results may no longer hold. */
  stale: boolean;
};

/**
 * One line over all checks. `checkedAt` belongs to the whole report: every
 * check was made at that time, so there is one age, never one per check.
 */
export function tailnetSummary(report: TailnetListenerReport, now: number): TailnetSummary {
  const at = report.observed.checkedAt ? Date.parse(report.observed.checkedAt) : NaN;
  if (!Number.isFinite(at)) return { tone: "muted", headline: "Not checked yet", stale: false };
  if (now - at > LISTENERS_STALE_MS) return { tone: "warn", headline: "The last report is older than 10 minutes", stale: true };
  const statuses = checkRows(report).map((r) => r.check.status);
  const failing = statuses.filter((s) => s === "fail").length;
  if (failing) return { tone: "error", headline: `${failing} of ${statuses.length} checks fail`, stale: false };
  if (statuses.some((s) => s === "unknown")) return { tone: "muted", headline: "Not every check could be made yet", stale: false };
  return { tone: "ok", headline: "All server checks pass", stale: false };
}

/** The browser endpoint's port: the configured one, else the one setup would use. */
export function endpointPort(endpoint: string | null): string {
  return endpoint ? new URL(endpoint).port || "443" : String(ENDPOINT_PORT);
}

/**
 * What to change for a failing check; null when there is nothing to do but
 * wait. The browser endpoint's host is tailnet_hostname in the pinned
 * tailnet, both fixed when the node enrolled: the fix is to put the node
 * back, or, for a tailnet renamed on purpose, to re-pin it.
 */
export function remedy(reason: ListenerReason | undefined, deployment: Deployment, endpoint: string | null, node?: ObservedNode): string | null {
  switch (reason) {
    case undefined:
    case "NOT_CHECKED":
      return null;
    case "NOT_LISTENING":
    case "LOCALAPI_UNAVAILABLE":
    case "NOT_RUNNING":
      return deployment === "host" ? "Inspect: journalctl -u varlatchd" : `Inspect: docker logs ${CONTAINER}`;
    case "NO_CERTIFICATE":
      return "Enable HTTPS certificates for the tailnet, in its admin console; varlatchd fetches the node's certificate itself, when it starts and daily";
    case "OTHER_TAILNET":
      return (
        "Rejoin the node to the configured tailnet. " +
        `If ${node?.tailnet ? `the change to ${node.tailnet}` : "the change"} is intended, accept it on the host: ${hostCommand(deployment, "varlatch tailnet repin", true)}`
      );
    case "TAGS_DIFFER":
      // Only on a self-hosted control server, where the node's tags are its pre-auth key's.
      return "Give the node exactly tailnet_tags in Headscale (headscale nodes tag -i <node id> -t <tailnet_tags>), or enrol it again with a pre-auth key tagged with them; access reopens at the next check";
    case "NAME_CHANGED": {
      const name = endpoint ? new URL(endpoint).hostname.split(".")[0] : undefined;
      return `Rename the node back to ${name ?? "its tailnet_hostname"} in the tailnet's admin console${node?.name ? ` (it is ${node.name} now)` : ""}; access reopens at the next check`;
    }
  }
}

/** Where the access rule points: the node's tags, else its IPv4 address. */
export type RuleDestination = { dst: string[]; kind: "tags" | "address" | "placeholder" };

export function ruleDestination(node: ObservedNode | undefined): RuleDestination {
  if (node?.tags?.length) return { dst: [...node.tags], kind: "tags" };
  const ipv4 = node?.addresses?.find((a) => !a.includes(":"));
  if (ipv4) return { dst: [ipv4], kind: "address" };
  return { dst: [NODE_PLACEHOLDER], kind: "placeholder" };
}

/**
 * A grant for the browser endpoint, on the
 * configured endpoint's port. Its source is every member: narrow it to the
 * people, groups or devices that may read tailnet-protected values.
 */
export function endpointRule(endpoint: string | null, node?: ObservedNode): string {
  const rule = { src: ["autogroup:member"], dst: ruleDestination(node).dst, ip: [`tcp:${endpointPort(endpoint)}`] };
  // One line per field, as policy files are usually written.
  return `{\n${Object.entries(rule)
    .map(([key, value]) => `  ${JSON.stringify(key)}: ${JSON.stringify(value)}`)
    .join(",\n")}\n}`;
}

/** varlatchd.conf's lines for an installation without a tailnet node; its address stays. */
export function addTailnetLines(deployment: Deployment): string[] {
  return [
    "tailnet = on",
    "tailnet_hostname = varlatch",
    "tailnet_tags = tag:varlatch",
    "tailnet_port = 8687",
    `tailnet_auth_key_file = ${deployment === "host" ? "/etc/varlatch" : "/keys"}/tailnet-auth-key`,
    ...enableEndpointLines(),
  ];
}

/** Turns the browser endpoint on. */
export function enableEndpointLines(): string[] {
  return [`tailnet_https_port = ${ENDPOINT_PORT}`];
}
