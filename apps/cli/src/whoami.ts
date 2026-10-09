// SPDX-License-Identifier: Apache-2.0
import { ContextError, resolveContext } from "@varlatch/context";
import type { TailnetDevice, VarlatchClient, WhoAmI } from "@varlatch/sdk";

/**
 * `varlatch whoami` (capability identity.whoami): which identity, human or
 * machine, the credential this CLI would use belongs to, with that
 * identity's organization and the credential's own name, as GET /v1/me
 * answers. The credential is the one every other command uses: VARLATCH_TOKEN,
 * else the stored one for the server. `varlatch status`, which reads the
 * credential store only, never sees VARLATCH_TOKEN, and its human format is
 * frozen (ADR-0032 Decision 6), so this is its own command. Names and
 * identifiers only, never a token.
 */

export const WHOAMI_CAPABILITY = "identity.whoami";

/** The server cannot answer: it predates GET /v1/me. */
export class WhoamiUnsupportedError extends Error {
  override name = "WhoamiUnsupportedError";
}

export type WhoamiApi = Pick<VarlatchClient, "meta" | "whoami">;

/** Ask the server, after checking that it can answer (ADR-0018 §3: capabilities, not versions). */
export async function fetchWhoami(api: WhoamiApi): Promise<WhoAmI> {
  const meta = await api.meta();
  if (!meta.capabilities.includes(WHOAMI_CAPABILITY)) {
    throw new WhoamiUnsupportedError(
      `varlatch whoami: this server (${meta.serverVersion}) cannot say which identity a credential belongs to ` +
        `(it lacks the ${WHOAMI_CAPABILITY} capability); upgrade the server. ` +
        "varlatch status --probe still says whether a stored credential is valid.",
    );
  }
  return api.whoami();
}

/**
 * The server to ask: --server, VARLATCH_SERVER, the repository's server
 * (its local override included), else the only server with a stored
 * credential. Null when none of these names one.
 */
export function whoamiServer(input: {
  server: string | undefined;
  env: NodeJS.ProcessEnv;
  cwd: string;
  stored: readonly string[];
}): string | null {
  try {
    // The Environment plays no part; only the server is wanted.
    return resolveContext({ cwd: input.cwd, env: input.env, environment: "(unused)", ...(input.server ? { server: input.server } : {}) })
      .server;
  } catch (err) {
    if (!(err instanceof ContextError)) throw err;
  }
  const named = input.server ?? input.env.VARLATCH_SERVER;
  if (named) return named;
  return input.stored.length === 1 ? (input.stored[0] as string) : null;
}

function describeDevice(device: TailnetDevice): string {
  if (!device.recognized) return `not recognized (${device.reason ?? "unrecognized"})`;
  const node = device.nodeName ? `${device.nodeName} (${device.nodeId})` : `node ${device.nodeId}`;
  const who = device.tags?.length ? `tags ${device.tags.join(", ")}` : device.userLogin ? `user ${device.userLogin}` : "no tags";
  return `${node}, ${who}, on ${device.tailnet}`;
}

/** The human format: one labeled line per fact, as `varlatch context` prints. */
export function formatWhoamiHuman(server: string, caller: WhoAmI): string {
  const { identity, organization, credential } = caller;
  const org = organization
    ? `${organization.slug} (${organization.name}, ${organization.id})`
    : identity.kind === "human"
      ? "none: a person joins organizations as a member (varlatch org list)"
      : "none";
  const lines = [
    `Identity      ${identity.name} (${identity.kind}, ${identity.id})`,
    ...(identity.email ? [`Email         ${identity.email}`] : []),
    `Organization  ${org}`,
    `Credential    ${credential.name ?? "unnamed"} (${credential.kind}, ${credential.id}), ` +
      (credential.expiresAt ? `expires ${credential.expiresAt}` : "no expiry"),
    `Server        ${server} (${caller.listener} listener)`,
    ...(caller.tailnet ? [`Device        ${describeDevice(caller.tailnet)}`] : []),
  ];
  return lines.join("\n");
}
