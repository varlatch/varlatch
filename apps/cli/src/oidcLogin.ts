// SPDX-License-Identifier: Apache-2.0
/**
 * OIDC login for CI (capability auth.oidc): obtain the platform's OIDC ID
 * token and exchange it at /v1/oidc/token for a short-lived Varlatch
 * credential — no stored secret in the pipeline at all.
 *
 * Token sources, in order: --oidc-token, $VARLATCH_OIDC_TOKEN, then the
 * GitHub Actions runtime endpoint ($ACTIONS_ID_TOKEN_REQUEST_URL — requires
 * `permissions: id-token: write` on the workflow).
 */

export interface OidcTokenSourceEnv {
  VARLATCH_OIDC_TOKEN?: string | undefined;
  ACTIONS_ID_TOKEN_REQUEST_URL?: string | undefined;
  ACTIONS_ID_TOKEN_REQUEST_TOKEN?: string | undefined;
}

export async function obtainOidcIdToken(opts: {
  explicitToken?: string | undefined;
  audience?: string | undefined;
  env?: OidcTokenSourceEnv | undefined;
  fetchImpl?: typeof fetch | undefined;
}): Promise<string> {
  if (opts.explicitToken) return opts.explicitToken;
  const env = opts.env ?? (process.env as OidcTokenSourceEnv);
  if (env.VARLATCH_OIDC_TOKEN) return env.VARLATCH_OIDC_TOKEN;

  const requestUrl = env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const requestToken = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (requestUrl && requestToken) {
    const url = new URL(requestUrl);
    if (opts.audience) url.searchParams.set("audience", opts.audience);
    const fetchImpl = opts.fetchImpl ?? fetch;
    const res = await fetchImpl(url.toString(), {
      headers: { Authorization: `Bearer ${requestToken}`, Accept: "application/json" },
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) {
      throw new Error(
        `GitHub Actions ID token request failed (${res.status}). ` +
          "Does the workflow grant `permissions: id-token: write`?",
      );
    }
    const body = (await res.json()) as { value?: string };
    if (!body.value) throw new Error("GitHub Actions ID token response had no value");
    return body.value;
  }

  throw new Error(
    "No OIDC token available: pass --oidc-token, set VARLATCH_OIDC_TOKEN, " +
      "or run inside GitHub Actions with `permissions: id-token: write`.",
  );
}
