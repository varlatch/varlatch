// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ObservedCheck, ObservedNode, TailnetListenerReport } from "@varlatch/protocol";

/**
 * The Installation page's Tailnet tab (GET /v1/installation/listeners):
 * what varlatchd checks itself, at start and every 60 seconds. None of it
 * says whether a device reaches a listener. That depends on the tailnet
 * policy, and only the device can find out (Connect to tailnet).
 */

/** Older than this, a report says nothing about now. The server's doctor uses the same limit. */
export const LISTENERS_STALE_MS = 10 * 60_000;

/** The browser endpoint's port when `varlatch setup --tailnet-endpoint` turns it on. */
export const ENDPOINT_PORT = 8688;

/** For when the report names no usable node (an older server, or a failed read). */
export const NODE_PLACEHOLDER = "<this node's tag or Tailscale address>";

export const DOCS_TAILSCALE_URL = "https://docs.varlatch.com/self-hosting/configuration/#tailscale";
export const DOCS_ENDPOINT_URL = "https://docs.varlatch.com/self-hosting/configuration/#tailnet-browser-endpoint";

export type ListenerReason = NonNullable<ObservedCheck["reason"]>;

/** Each reason in words, as the server's doctor puts them (services/varlatchd/src/doctor.ts). */
export const REASON_TEXT: Record<ListenerReason, string> = {
  NOT_CHECKED: "Not checked yet",
  NOT_LISTENING: "A tailnet listener did not bind its port",
  NO_CERTIFICATE: "No valid certificate is loaded",
  LOCALAPI_UNAVAILABLE: "tailscaled's LocalAPI does not answer",
  NOT_RUNNING: "The node is not connected to the tailnet",
  OTHER_TAILNET: "The node is on another tailnet than the configured one",
  NAME_CHANGED: "The node's name is no longer the browser endpoint's host",
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
    { key: "localApi", label: "Tailscale LocalAPI", passes: "tailscaled answers varlatchd", check: observed.checks.localApi },
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

/** The tailnet in the endpoint's host, <machine>.<tailnet>. */
function endpointTailnet(endpoint: string | null): string {
  const host = endpoint ? new URL(endpoint).hostname : "";
  return host.includes(".") ? host.slice(host.indexOf(".") + 1) : "<tailnet>";
}

/** How the operator runs this installation; the dashboard cannot tell, so they choose. */
export type Deployment = "setup" | "coolify";

/**
 * What to change for a failing check, per deployment; null when there is
 * nothing to do but wait. With the browser endpoint on, varlatchd derives
 * the endpoint's host from the machine and tailnet names, while the
 * dashboard's Content-Security-Policy allows VARLATCH_TAILNET_ENDPOINT:
 * a fix that changes one of them changes the endpoint URL with it, keeping
 * the configured endpoint's port and whatever else did not change.
 */
export function remedy(reason: ListenerReason | undefined, deployment: Deployment, endpoint: string | null, node?: ObservedNode): string | null {
  const logs =
    deployment === "setup"
      ? "Inspect: docker compose logs tailscale varlatchd"
      : "Inspect the logs of the tailscale and varlatchd services in Coolify";
  switch (reason) {
    case undefined:
    case "NOT_CHECKED":
      return null;
    case "NOT_LISTENING":
    case "LOCALAPI_UNAVAILABLE":
    case "NOT_RUNNING":
      return logs;
    case "NO_CERTIFICATE":
      return deployment === "setup"
        ? "The tailnet must have HTTPS certificates enabled, and the sidecar must let varlatchd's user fetch them: run varlatch setup --tailnet-endpoint again"
        : "The tailnet must have HTTPS certificates enabled, and VARLATCH_TAILNET_CERT_UID must be 999 so varlatchd's user may fetch them";
    case "OTHER_TAILNET": {
      if (deployment === "setup") return "Rerun varlatch setup: it stops and says what changed";
      // The node's own tailnet, when the server could read it; the name only with it.
      const theirs = node?.tailnet;
      const machine = theirs ? node?.name : undefined;
      return endpoint
        ? "Rejoin the node to the configured tailnet. To keep the node's tailnet instead, change these together, then redeploy: " +
            `VARLATCH_TAILNET_NAME to ${theirs ?? "the node's tailnet"}, ` +
            `VARLATCH_TAILNET_ENDPOINT to https://${machine ?? "<machine>"}.${theirs ?? "<that tailnet>"}:${endpointPort(endpoint)}, ` +
            `and VARLATCH_TAILNET_NODE ${machine ? `to ${machine}` : "confirmed as the node's machine name"}`
        : `Rejoin the node to the configured tailnet, or set VARLATCH_TAILNET_NAME to ${theirs ?? "the node's tailnet"}, then redeploy`;
    }
    case "NAME_CHANGED": {
      if (deployment === "setup") return "Rerun varlatch setup: it stops and says what changed";
      // NAME_CHANGED is judged only on the configured tailnet, so the node's name is its new name there.
      const renamed = node?.name;
      return `Set VARLATCH_TAILNET_NODE to ${renamed ?? "the node's new name"} and VARLATCH_TAILNET_ENDPOINT to https://${renamed ?? "<new name>"}.${endpointTailnet(endpoint)}:${endpointPort(endpoint)}, then redeploy`;
    }
  }
}

/** Where the access rule points: as `varlatch setup` chooses, the node's tags, else its IPv4 address. */
export type RuleDestination = { dst: string[]; kind: "tags" | "address" | "placeholder" };

export function ruleDestination(node: ObservedNode | undefined): RuleDestination {
  if (node?.tags?.length) return { dst: [...node.tags], kind: "tags" };
  const ipv4 = node?.addresses?.find((a) => !a.includes(":"));
  if (ipv4) return { dst: [ipv4], kind: "address" };
  return { dst: [NODE_PLACEHOLDER], kind: "placeholder" };
}

/**
 * The grant `varlatch setup` prints for the browser endpoint, on the
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

/** Adds the Tailscale sidecar to an installation without a tailnet listener; the address stays. */
export function addTailscaleLines(deployment: Deployment): string[] {
  return deployment === "setup"
    ? ["varlatch setup --dir /srv/varlatch --tailnet-endpoint \\", "  --tailscale-auth-key-file /secure/operator/tailscale-authkey"]
    : [
        "# Docker Compose Location: /infra/compose/docker-compose.coolify-tailscale.yml",
        "TS_AUTHKEY_HOST_PATH=/data/varlatch/secrets/tailscale-authkey",
        "VARLATCH_TAILNET_NAME=<your-tailnet>.ts.net",
        "VARLATCH_TAILNET_MACHINE=varlatch",
      ];
}

/** Turns the browser endpoint on where the node has joined. */
export function enableEndpointLines(deployment: Deployment, tailnet: string | null, node?: ObservedNode): string[] {
  if (deployment === "setup") return ["varlatch setup --dir /srv/varlatch --tailnet-endpoint"];
  // The node's name only when it is on the configured tailnet: anything else names a host that is not there.
  const machine = node?.name && tailnet && node.tailnet === tailnet.toLowerCase() ? node.name : "<machine>";
  const host = `${machine}.${tailnet ?? "<your-tailnet>.ts.net"}`;
  return [
    `VARLATCH_TAILNET_HTTPS_PORT=${ENDPOINT_PORT}`,
    `VARLATCH_TAILNET_NODE=${machine}`,
    `VARLATCH_TAILNET_ENDPOINT=https://${host}:${ENDPOINT_PORT}`,
    "VARLATCH_TAILNET_CERT_UID=999",
  ];
}
