// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create } from "react-test-renderer";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The account pages read the current organization's identities for the
 * role line. Before an organization slug is known they must not ask for
 * GET /v1/organizations//identities.
 */

const fake = vi.hoisted(() => ({
  api: {} as Record<string, ReturnType<typeof vi.fn>>,
  org: undefined as string | undefined,
}));
vi.hoisted(() => vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true));
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api, identityId: "idn_me" }) }));
vi.mock("../src/lib/realtime", () => ({ useMeRealtime: () => {} }));
vi.mock("../src/shell/Shell", () => ({ useCurrentOrg: () => fake.org }));
vi.mock("../src/features/projects/hooks", () => ({ useOrgName: (org: string | undefined) => org }));
vi.mock("../src/components/PageHeader", () => ({ PageHeader: () => null, Tabs: () => null }));
vi.mock("react-router-dom", () => ({ Outlet: () => null, useLocation: () => ({ pathname: "/account" }) }));

import { AccountLayout } from "../src/features/account/AccountLayout";

async function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    create(
      <QueryClientProvider client={client}>
        <AccountLayout />
      </QueryClientProvider>,
    );
  });
  for (let i = 0; i < 4; i++) await act(async () => new Promise((resolve) => globalThis.setTimeout(resolve, 0)));
}

beforeEach(() => {
  fake.org = undefined;
  fake.api = {
    getMyProfile: vi.fn(async () => ({ name: "Me", email: "me@example.com", image: null })),
    listMyCredentials: vi.fn(async () => ({ items: [] })),
    listIdentities: vi.fn(async () => ({ items: [] })),
  };
});

describe("account layout identities", () => {
  it("makes no identities request without an organization slug", async () => {
    await mount();
    expect(fake.api.listIdentities).not.toHaveBeenCalled();
  });

  it("reads the identities of the current organization", async () => {
    fake.org = "acme";
    await mount();
    expect(fake.api.listIdentities).toHaveBeenCalledWith("acme");
  });
});
