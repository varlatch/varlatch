// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { obtainOidcIdToken } from "../src/oidcLogin.js";

describe("obtainOidcIdToken", () => {
  it("prefers the explicit flag, then the env var", async () => {
    expect(
      await obtainOidcIdToken({ explicitToken: "jwt-flag", env: { VARLATCH_OIDC_TOKEN: "jwt-env" } }),
    ).toBe("jwt-flag");
    expect(await obtainOidcIdToken({ env: { VARLATCH_OIDC_TOKEN: "jwt-env" } })).toBe("jwt-env");
  });

  it("fetches from the GitHub Actions endpoint with audience and bearer", async () => {
    const calls: { url: string; auth: string | undefined }[] = [];
    const fetchImpl = (async (url: unknown, init?: RequestInit) => {
      calls.push({
        url: String(url),
        auth: (init?.headers as Record<string, string>).Authorization,
      });
      return Response.json({ value: "jwt-gha" });
    }) as typeof fetch;
    const token = await obtainOidcIdToken({
      audience: "varlatch",
      env: {
        ACTIONS_ID_TOKEN_REQUEST_URL: "https://gha.example/token?api-version=2",
        ACTIONS_ID_TOKEN_REQUEST_TOKEN: "runtime-token",
      },
      fetchImpl,
    });
    expect(token).toBe("jwt-gha");
    expect(calls[0].url).toContain("audience=varlatch");
    expect(calls[0].url).toContain("api-version=2");
    expect(calls[0].auth).toBe("Bearer runtime-token");
  });

  it("explains the id-token permission on GitHub failures", async () => {
    const fetchImpl = (async () => new Response(null, { status: 403 })) as typeof fetch;
    await expect(
      obtainOidcIdToken({
        env: {
          ACTIONS_ID_TOKEN_REQUEST_URL: "https://gha.example/token",
          ACTIONS_ID_TOKEN_REQUEST_TOKEN: "t",
        },
        fetchImpl,
      }),
    ).rejects.toThrow(/id-token: write/);
  });

  it("fails with guidance when no source exists", async () => {
    await expect(obtainOidcIdToken({ env: {} })).rejects.toThrow(/--oidc-token|VARLATCH_OIDC_TOKEN/);
  });
});
