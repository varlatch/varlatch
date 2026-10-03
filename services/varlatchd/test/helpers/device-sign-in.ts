// SPDX-License-Identifier: AGPL-3.0-or-later
import type { buildApp } from "../../src/http/app.js";
import type { AppCtx } from "../../src/domain/ctx.js";
import { issueCredential } from "../../src/auth/credentials.js";
import { newId } from "../../src/db/ids.js";
import { registerSoftPasskey, type SoftAuthenticator } from "./soft-authenticator.js";

/** Device sign-in test client: the CLI's and the dashboard's calls against one app. */
export const PUBLIC_URL = "https://varlatch.test";
export const RP = { rpId: "varlatch.test", origin: "https://varlatch.test" };

export interface Answer {
  status: number;
  body: any;
  headers: Headers;
}

export function deviceClient(app: () => ReturnType<typeof buildApp>) {
  const call = async (path: string, body: unknown, headers: Record<string, string> = {}): Promise<Answer> => {
    const res = await app().request(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json().catch(() => null), headers: res.headers };
  };
  const bearer = (token: string) => ({ Authorization: `Bearer ${token}` });
  return {
    start: (body: Record<string, unknown> = {}, userAgent = "varlatch-cli/0.14.0 (linux; x64)") =>
      call("/v1/auth/device", body, { "User-Agent": userAgent }),
    poll: (deviceCode: string) => call("/v1/auth/device/token", { deviceCode }, { "User-Agent": "varlatch-cli/0.14.0 (linux; x64)" }),
    lookup: (token: string, userCode: string) => call("/v1/auth/device/lookup", { userCode }, bearer(token)),
    decide: (token: string, userCode: string, decision: "approve" | "deny", assertion?: unknown) =>
      call("/v1/auth/device/approve", { userCode, decision, ...(assertion === undefined ? {} : { assertion }) }, bearer(token)),
    /** The whole approval: look the code up, sign the challenge, approve. */
    async approve(token: string, userCode: string, passkey: SoftAuthenticator): Promise<Answer> {
      const found = await this.lookup(token, userCode);
      if (found.status !== 200) return found;
      return this.decide(token, userCode, "approve", passkey.assert(found.body.approval.publicKey.challenge));
    },
  };
}

/** A human with a passkey and a dashboard bearer for one Better Auth session. */
export async function approvingHuman(ctx: AppCtx, name: string, existingIdentityId?: string) {
  const identityId = existingIdentityId ?? newId("identity");
  if (!existingIdentityId) {
    await ctx.db.query("INSERT INTO identities (id, kind, name) VALUES ($1, 'human', $2)", [identityId, name]);
  }
  const passkey = await registerSoftPasskey(ctx.db, identityId, RP);
  const session = (sessionId: string) =>
    issueCredential(ctx.db, {
      identityId,
      kind: "browser",
      expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
      authSessionId: sessionId,
    }).then((issued) => issued.token);
  return { identityId, passkey, session, token: await session(`session-${identityId}`) };
}
