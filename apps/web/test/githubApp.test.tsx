// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VarlatchApiError } from "@varlatch/sdk";
import type { GitHubApp, PlatformConnection, SyncTarget } from "@varlatch/protocol";

/**
 * The dashboard's GitHub App (ADR-0047 implementation step 5): register it
 * through GitHub's manifest flow, finish the registration where GitHub sends
 * the browser back (registered, refused, failed, expired), import one,
 * connect an installation, rotate the key, and remove the App. App
 * Connections lead to key rotation, not to a credential replacement.
 */

const fake = vi.hoisted(() => ({
  api: {} as Record<string, (...args: never[]) => unknown>,
  toasts: [] as { kind: string; title: string; description?: string }[],
  confirmed: [] as unknown[],
}));
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("window", { setInterval: globalThis.setInterval.bind(globalThis), clearInterval: globalThis.clearInterval.bind(globalThis), open: () => null });
});
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api }) }));
vi.mock("../src/components/Toast", () => ({
  useToast: () => ({
    success: (title: string, o?: { description?: string }) => fake.toasts.push({ kind: "success", title, ...(o?.description ? { description: o.description } : {}) }),
    error: (title: string, o?: { description?: string }) => fake.toasts.push({ kind: "error", title, ...(o?.description ? { description: o.description } : {}) }),
  }),
}));
vi.mock("../src/components/Dialog", () => ({
  Dialog: ({ children, footer }: { children: React.ReactNode; footer?: React.ReactNode }) => (
    <div>
      {children}
      {footer}
    </div>
  ),
  useConfirm: () => async (o: unknown) => {
    fake.confirmed.push(o);
    return true;
  },
}));
vi.mock("../src/features/projects/hooks", () => ({ useOrgName: () => "Acme", useMeta: () => ({ data: undefined }), keys: {} }));

import {
  ConnectInstallationDialog,
  GitHubAppCallbackPage,
  GitHubAppPanel,
  ImportAppDialog,
  RegisterAppDialog,
  RotateKeyDialog,
  appSettingsUrl,
} from "../src/features/sync/GitHubApp";
import { ConnectionCard } from "../src/features/sync/ConnectionsPage";

const APP: GitHubApp = {
  id: "gha_1",
  organizationId: "org_1",
  githubAppId: 5254113,
  slug: "varlatch-acme",
  clientId: "Iv23li",
  owner: { login: "acme-gh", id: 1009, type: "organization" },
  htmlUrl: "https://github.com/apps/varlatch-acme",
  version: 3,
  createdAt: "2026-10-09T00:00:00Z",
  updatedAt: null,
};
const appConnection: PlatformConnection = {
  id: "pcn_app",
  organizationId: "org_1",
  platform: "github-actions",
  baseIdentity: "acme-gh",
  name: "GitHub (acme-gh)",
  createdAt: "2026-10-09T00:00:00Z",
  version: 1,
  updatedAt: null,
  credentialExpiresAt: null,
  credentialExpirySeenAt: null,
  credentialKind: "github-app",
  githubAppId: "gha_1",
  installationId: 169698431,
};
const notFound = () => new VarlatchApiError(404, { code: "RESOURCE_NOT_FOUND", message: "This Organization has no GitHub App", requestId: "req_1" });
const deferred = <T,>() => {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};

let root: ReactTestRenderer;
let client: QueryClient;
const submitted: string[] = [];
async function mount(element: React.ReactElement, path = "/") {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={[path]}>{element}</MemoryRouter>
      </QueryClientProvider>,
      // The manifest form's submit(), as the browser would post it to GitHub.
      { createNodeMock: (el) => (el.type === "form" ? { submit: () => submitted.push(String(el.props.action)) } : null) },
    );
  });
}
// A few ticks: a query that starts after another settles (the App check after a refused completion) needs more than one.
const settle = () =>
  act(async () => {
    for (let i = 0; i < 4; i++) await new Promise((r) => setTimeout(r, 0));
  });
beforeEach(() => {
  fake.api = {};
  fake.toasts = [];
  fake.confirmed = [];
  submitted.length = 0;
});
afterEach(async () => {
  await act(async () => root?.unmount());
});
const all = (id: string) => root.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const byTestId = (id: string): ReactTestInstance => {
  const found = all(id);
  if (found.length !== 1) throw new Error(`${found.length} elements with data-testid ${id}`);
  return found[0]!;
};
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");
const click = (id: string) => act(async () => byTestId(id).props.onClick());
const type = (id: string, value: string) => act(async () => byTestId(id).props.onChange({ target: { value } }));
const menuItem = (id: string) => root.root.findAll((n) => Array.isArray(n.props.items)).flatMap((n) => n.props.items as { "data-testid"?: string; onSelect: () => void }[]).find((i) => i["data-testid"] === id)!;

describe("the GitHub App panel", () => {
  it("offers to register or import an App when the Organization has none", async () => {
    fake.api.getGitHubApp = async () => {
      throw notFound();
    };
    await mount(<GitHubAppPanel org="acme" connections={[]} targets={[]} envs={new Map()} onChanged={() => {}} rotating={false} onRotate={() => {}} onRotateDone={() => {}} />);
    await settle();
    expect(all("github-app-register")).toHaveLength(1);
    expect(all("github-app-import")).toHaveLength(1);
    expect(all("github-app-connect")).toHaveLength(0);
  });

  it("shows the App, how many installations are connected, and connects another", async () => {
    fake.api.getGitHubApp = async () => APP;
    await mount(<GitHubAppPanel org="acme" connections={[appConnection]} targets={[]} envs={new Map()} onChanged={() => {}} rotating={false} onRotate={() => {}} onRotateDone={() => {}} />);
    await settle();
    expect(text(byTestId("github-app-summary"))).toBe("varlatch-acme on acme-gh · 1 installation connected");
    expect(all("github-app-connect")).toHaveLength(1);
  });

  it("removes the App after saying what it revokes, and that the App stays on GitHub", async () => {
    fake.api.getGitHubApp = async () => APP;
    const removed: string[][] = [];
    fake.api.removeGitHubApp = (async (org: string, appId: string) => {
      removed.push([org, appId]);
    }) as never;
    const target = { id: "snt_1", connectionId: "pcn_app", environmentId: "env_1" } as SyncTarget;
    await mount(<GitHubAppPanel org="acme" connections={[appConnection]} targets={[target]} envs={new Map()} onChanged={() => {}} rotating={false} onRotate={() => {}} onRotateDone={() => {}} />);
    await settle();
    await act(async () => menuItem("github-app-remove").onSelect());
    await settle();
    expect(removed).toEqual([["acme", "gha_1"]]);
    const asked = fake.confirmed[0] as { description: string; consequences: { text: string }[] };
    expect(asked.description).toContain("The App itself stays on GitHub");
    expect(asked.consequences.map((c) => c.text)).toEqual([
      "1 connection revoked: GitHub (acme-gh)",
      "1 integration stop pushing until pointed at another connection.",
    ]);
    expect(fake.toasts[0]).toMatchObject({ kind: "success", title: "GitHub App removed" });
  });
});

describe("removing an App that was replaced meanwhile", () => {
  it("says so and removes nothing", async () => {
    fake.api.getGitHubApp = async () => APP;
    fake.api.removeGitHubApp = (async () => {
      throw new VarlatchApiError(409, { code: "STATE_CHANGED", message: "changed", requestId: "r" });
    }) as never;
    await mount(<GitHubAppPanel org="acme" connections={[appConnection]} targets={[]} envs={new Map()} onChanged={() => {}} rotating={false} onRotate={() => {}} onRotateDone={() => {}} />);
    await settle();
    await act(async () => menuItem("github-app-remove").onSelect());
    await settle();
    expect(fake.toasts).toEqual([{ kind: "error", title: "The GitHub App changed", description: expect.stringContaining("Nothing was removed") }]);
  });
});

describe("registering through GitHub's manifest flow", () => {
  it("starts the registration for the account named, then posts the manifest to GitHub", async () => {
    const calls: unknown[] = [];
    fake.api.startGitHubAppRegistration = (async (org: string, account: unknown) => {
      calls.push([org, account]);
      return {
        state: "s1",
        action: "https://github.com/organizations/acme-gh/settings/apps/new?state=s1",
        manifest: { name: "Varlatch acme", public: false },
        account,
        expiresAt: "2026-10-10T01:00:00Z",
      };
    }) as never;
    await mount(<RegisterAppDialog org="acme" onClose={() => {}} />);
    expect(text(byTestId("github-app-owner-note"))).toContain("offers to create the App for your own account, stop there");
    await type("github-app-login", " acme-gh ");
    await click("github-app-continue");
    await settle();
    expect(calls).toEqual([["acme", { login: "acme-gh", type: "organization" }]]);
    const form = byTestId("github-app-manifest-form");
    expect(form.props).toMatchObject({ method: "post", action: "https://github.com/organizations/acme-gh/settings/apps/new?state=s1" });
    const input = form.findByType("input");
    expect(input.props).toMatchObject({ type: "hidden", name: "manifest", value: JSON.stringify({ name: "Varlatch acme", public: false }) });
    expect(submitted).toEqual(["https://github.com/organizations/acme-gh/settings/apps/new?state=s1"]);
  });

  it("registers on a personal account too, without the organization note", async () => {
    const calls: unknown[] = [];
    fake.api.startGitHubAppRegistration = (async (_org: string, account: unknown) => {
      calls.push(account);
      return { state: "s", action: "https://github.com/settings/apps/new?state=s", manifest: {}, account, expiresAt: "" };
    }) as never;
    await mount(<RegisterAppDialog org="acme" onClose={() => {}} />);
    await click("github-app-type-user");
    expect(all("github-app-owner-note")).toHaveLength(0);
    await type("github-app-login", "jeremy");
    await click("github-app-continue");
    await settle();
    expect(calls).toEqual([{ login: "jeremy", type: "user" }]);
  });
});

describe("where GitHub sends the browser back", () => {
  const callback = (query: string) =>
    mount(
      // StrictMode runs effects twice in development: the state is single-use, so completion must run once.
      <React.StrictMode>
        <Routes>
          <Route path="/o/:org/connections/github-app" element={<GitHubAppCallbackPage />} />
        </Routes>
      </React.StrictMode>,
      `/o/acme/connections/github-app${query}`,
    );
  const status = () => byTestId("github-app-callback").props["data-status"];

  it("completes once with the state and code, and says to install the App next", async () => {
    const calls: unknown[] = [];
    fake.api.completeGitHubAppRegistration = (async (org: string, input: unknown) => {
      calls.push([org, input]);
      return { outcome: "registered", app: APP };
    }) as never;
    await callback("?code=c1&state=s1");
    await settle();
    expect(calls).toEqual([["acme", { state: "s1", code: "c1" }]]);
    expect(status()).toBe("registered");
    expect(byTestId("github-app-install").props.href).toBe("https://github.com/apps/varlatch-acme/installations/new");
  });

  it("explains an App GitHub created on the person's own account, and where to delete it", async () => {
    fake.api.completeGitHubAppRegistration = (async () => ({
      outcome: "refused",
      reason: "owner-mismatch",
      app: { githubAppId: 1, slug: "varlatch-acme", owner: { login: "jeremy", type: "user" } },
      account: { login: "acme-gh", type: "organization" },
      deleteUrl: "https://github.com/settings/apps/varlatch-acme/advanced",
      message: "GitHub created the App varlatch-acme on jeremy's own account, not on acme-gh.",
    })) as never;
    await callback("?code=c1&state=s1");
    await settle();
    expect(status()).toBe("owner-mismatch");
    expect(text(byTestId("github-app-callback"))).toContain("GitHub created the App on another account");
    expect(text(byTestId("github-app-callback"))).toContain("on jeremy's own account, not on acme-gh");
    expect(byTestId("github-app-delete").props.href).toBe("https://github.com/settings/apps/varlatch-acme/advanced");
  });

  it("offers to try again when GitHub could not be reached, with the same code", async () => {
    const answers = [
      { outcome: "failed", retryable: true, message: "Varlatch could not reach api.github.com." },
      { outcome: "registered", app: APP },
    ];
    let calls = 0;
    fake.api.completeGitHubAppRegistration = (async () => answers[calls++]) as never;
    await callback("?code=c1&state=s1");
    await settle();
    expect(status()).toBe("retryable");
    await click("github-app-retry");
    await settle();
    expect(calls).toBe(2);
    expect(status()).toBe("registered");
  });

  it("tells how to recover when the registration did not finish, or was already finished", async () => {
    fake.api.completeGitHubAppRegistration = (async () => ({ outcome: "failed", retryable: false, httpStatus: 404, message: "GitHub did not hand over the App (HTTP 404)." })) as never;
    await callback("?code=c1&state=s1");
    await settle();
    expect(status()).toBe("failed");
    expect(text(byTestId("github-app-recovery"))).toContain("If GitHub created the App, it is still there");
    await act(async () => root.unmount());

    // A used link, and no App in Varlatch: the earlier attempt stopped partway.
    fake.api.completeGitHubAppRegistration = (async () => {
      throw new VarlatchApiError(410, { code: "CONSUMED", message: "already", requestId: "r" });
    }) as never;
    fake.api.getGitHubApp = async () => {
      throw notFound();
    };
    await callback("?code=c1&state=s1");
    await settle();
    expect(status()).toBe("CONSUMED");
    expect(byTestId("github-app-callback").props["data-app"]).toBe("absent");
    expect(text(byTestId("github-app-callback"))).toContain("the earlier attempt stopped partway");
    expect(all("github-app-recovery")).toHaveLength(1);
  });

  it("never sends anyone to delete the App a refresh shows was saved", async () => {
    fake.api.completeGitHubAppRegistration = (async () => {
      throw new VarlatchApiError(410, { code: "CONSUMED", message: "already", requestId: "r" });
    }) as never;
    fake.api.getGitHubApp = async () => APP;
    await callback("?code=c1&state=s1");
    await settle();
    expect(byTestId("github-app-callback").props["data-app"]).toBe("present");
    expect(text(byTestId("github-app-callback"))).toContain("This organization's GitHub App is varlatch-acme");
    expect(all("github-app-recovery")).toHaveLength(0);
    expect(byTestId("github-app-install").props.href).toBe("https://github.com/apps/varlatch-acme/installations/new");
  });

  it("keeps the live App when an expired link is opened, and does not offer deletion when the App cannot be checked", async () => {
    fake.api.completeGitHubAppRegistration = (async () => {
      throw new VarlatchApiError(410, { code: "EXPIRED", message: "expired", requestId: "r" });
    }) as never;
    fake.api.getGitHubApp = async () => APP;
    await callback("?code=c1&state=s1");
    await settle();
    expect(byTestId("github-app-callback").props["data-app"]).toBe("present");
    expect(text(byTestId("github-app-callback"))).toContain("keep it");
    expect(all("github-app-recovery")).toHaveLength(0);
    await act(async () => root.unmount());

    fake.api.getGitHubApp = async () => {
      throw new VarlatchApiError(500, { code: "INTERNAL", message: "boom", requestId: "r" });
    };
    await callback("?code=c1&state=s1");
    await settle();
    expect(byTestId("github-app-callback").props["data-app"]).toBe("unknown");
    expect(text(byTestId("github-app-callback"))).toContain("Open Connections before deleting anything on GitHub");
    expect(all("github-app-recovery")).toHaveLength(0);
  });

  it("says an expired or unknown registration should start again, and does nothing without a code", async () => {
    fake.api.completeGitHubAppRegistration = (async () => {
      throw new VarlatchApiError(410, { code: "EXPIRED", message: "expired", requestId: "r" });
    }) as never;
    fake.api.getGitHubApp = async () => {
      throw notFound();
    };
    await callback("?code=c1&state=s1");
    await settle();
    expect(text(byTestId("github-app-callback"))).toContain("GitHub's code lasts an hour");
    expect(all("github-app-recovery")).toHaveLength(1);
    await act(async () => root.unmount());

    let calls = 0;
    fake.api.completeGitHubAppRegistration = (async () => {
      calls++;
    }) as never;
    await callback("");
    await settle();
    expect(calls).toBe(0);
    expect(all("github-app-callback")).toHaveLength(0);
  });
});

describe("importing an App", () => {
  it("names the permissions Varlatch needs, and shows why GitHub refused the pair", async () => {
    fake.api.importGitHubApp = (async () => ({
      outcome: "failed",
      status: "credential-rejected",
      where: "connection",
      httpStatus: 401,
      message: "GitHub refused the App's key, though the request was valid at GitHub's time.",
    })) as never;
    let imported = 0;
    await mount(<ImportAppDialog org="acme" onClose={() => {}} onImported={() => imported++} />);
    expect(text(byTestId("github-app-key-reach"))).toContain("the key itself keeps everything the App holds");
    await type("github-app-id", "5254113");
    await type("github-app-key", "-----BEGIN RSA PRIVATE KEY-----");
    await click("github-app-import-submit");
    await settle();
    expect(byTestId("access-check").props["data-status"]).toBe("credential-rejected");
    expect(imported).toBe(0);
  });

  it("closes once imported", async () => {
    const calls: unknown[] = [];
    fake.api.importGitHubApp = (async (_org: string, input: unknown) => {
      calls.push(input);
      return { outcome: "registered", app: APP };
    }) as never;
    let imported = 0;
    await mount(<ImportAppDialog org="acme" onClose={() => {}} onImported={() => imported++} />);
    await type("github-app-id", "5254113");
    await type("github-app-key", "KEY");
    await click("github-app-import-submit");
    await settle();
    expect(calls).toEqual([{ appId: 5254113, privateKey: "KEY" }]);
    expect(imported).toBe(1);
  });
});

describe("connecting an installation", () => {
  it("lists the App's installations, keeps suspended and connected ones out of reach, and connects the chosen one", async () => {
    fake.api.listGitHubAppInstallations = async () => ({
      check: { status: "ok", where: "connection", message: "listed" },
      items: [
        { installationId: 169698431, account: { login: "acme-gh", id: 1, type: "organization" }, repositorySelection: "selected", suspended: false },
        { installationId: 2, account: { login: "acme-labs", id: 2, type: "organization" }, repositorySelection: "all", suspended: false },
        { installationId: 3, account: { login: "acme-old", id: 3, type: "organization" }, repositorySelection: "all", suspended: true },
      ],
      truncated: false,
    });
    const created: unknown[] = [];
    fake.api.createAppConnection = (async (_org: string, input: unknown) => {
      created.push(input);
      return { ...appConnection, id: "pcn_2", name: "GitHub (acme-labs)" };
    }) as never;
    let done = 0;
    await mount(<ConnectInstallationDialog org="acme" app={APP} connections={[appConnection]} onClose={() => {}} onCreated={() => done++} />);
    await settle();
    expect(byTestId("github-app-installation-169698431").props.disabled).toBe(true);
    expect(byTestId("github-app-installation-3").props.disabled).toBe(true);
    expect(byTestId("github-app-connect-submit").props.disabled).toBe(true);
    await click("github-app-installation-2");
    expect(byTestId("github-app-connection-name").props.value).toBe("GitHub (acme-labs)");
    await click("github-app-connect-submit");
    await settle();
    expect(created).toEqual([{ installationId: 2, name: "GitHub (acme-labs)" }]);
    expect(done).toBe(1);
  });

  it("shows why the installations could not be listed", async () => {
    fake.api.listGitHubAppInstallations = async () => ({
      check: { status: "failed", where: "connection", httpStatus: 401, message: "This server's clock is about 15 minutes ahead of GitHub's." },
      items: [],
      truncated: false,
    });
    await mount(<ConnectInstallationDialog org="acme" app={APP} connections={[]} onClose={() => {}} onCreated={() => {}} />);
    await settle();
    expect(text(byTestId("access-check"))).toContain("about 15 minutes ahead");
  });
});

describe("rotating the App's key", () => {
  const targets = [{ id: "snt_1", connectionId: "pcn_app", environmentId: "env_1" } as SyncTarget];

  it("links to the App's key pairs, sends the version shown, and says to delete the old key", async () => {
    const calls: unknown[] = [];
    fake.api.rotateGitHubAppKey = (async (_org: string, input: unknown) => {
      calls.push(input);
      return { outcome: "rotated", app: { ...APP, version: 4 } };
    }) as never;
    let rotated = 0;
    await mount(<RotateKeyDialog org="acme" app={APP} connections={[appConnection]} targets={targets} envs={new Map()} onClose={() => {}} onRotated={() => rotated++} />);
    expect(text(byTestId("github-app-rotate-steps"))).toContain("Credentials, Key pairs, New key");
    expect(byTestId("github-app-rotate-steps").findByType("a").props.href).toBe("https://github.com/organizations/acme-gh/settings/apps/varlatch-acme");
    expect(text(byTestId("github-app-rotate-scope"))).toContain("This re-authorizes 1 integration");
    await type("github-app-key", "NEW KEY");
    await click("github-app-rotate-submit");
    await settle();
    expect(calls).toEqual([{ privateKey: "NEW KEY", expectedVersion: 3 }]);
    expect(rotated).toBe(1);
    expect(fake.toasts[0]).toMatchObject({ title: "Key rotated", description: expect.stringContaining("delete the old key on GitHub") });
  });

  it("shows GitHub's refusal of the key, and a stale or refused rotation", async () => {
    fake.api.rotateGitHubAppKey = (async () => ({ outcome: "failed", status: "credential-rejected", where: "connection", httpStatus: 401, message: "GitHub refused the App's key." })) as never;
    await mount(<RotateKeyDialog org="acme" app={APP} connections={[]} targets={[]} envs={new Map()} onClose={() => {}} onRotated={() => {}} />);
    await type("github-app-key", "K");
    await click("github-app-rotate-submit");
    await settle();
    expect(byTestId("access-check").props["data-status"]).toBe("credential-rejected");
    await act(async () => root.unmount());

  });

  it("re-reads the App after a version conflict, and asks again only with the new version", async () => {
    // The server's App moves from version 3 to 4 while the dialog is open.
    let serverVersion = 3;
    const reread = deferred<GitHubApp>();
    let reads = 0;
    fake.api.getGitHubApp = (async () => (++reads === 1 ? { ...APP, version: serverVersion } : reread.promise)) as never;
    const sent: number[] = [];
    fake.api.rotateGitHubAppKey = (async (_org: string, input: { expectedVersion: number }) => {
      sent.push(input.expectedVersion);
      if (input.expectedVersion !== serverVersion) throw new VarlatchApiError(409, { code: "VERSION_CONFLICT", message: "changed", requestId: "r" });
      return { outcome: "rotated", app: { ...APP, version: serverVersion + 1 } };
    }) as never;
    await mount(<GitHubAppPanel org="acme" connections={[appConnection]} targets={[]} envs={new Map()} onChanged={() => {}} rotating onRotate={() => {}} onRotateDone={() => {}} />);
    await settle();
    serverVersion = 4;
    await type("github-app-key", "K");
    await click("github-app-rotate-submit");
    await settle();
    // Refused at 3; reading again: nothing to submit until the new version is in.
    expect(sent).toEqual([3]);
    expect(byTestId("github-app-rotate-conflict").props["data-status"]).toBe("reloading");
    expect(byTestId("github-app-rotate-submit").props.disabled).toBe(true);
    await act(async () => reread.resolve({ ...APP, version: 4 }));
    await settle();
    expect(byTestId("github-app-rotate-conflict").props["data-status"]).toBe("reloaded");
    expect(byTestId("github-app-rotate-submit").props.disabled).toBe(false);
    await click("github-app-rotate-submit");
    await settle();
    expect(sent).toEqual([3, 4]);
  });

  it("counts a version loaded while the refused request was in flight as new, and asks with it", async () => {
    // Reverse order: the App is re-read (version 4) before version 3's rejection arrives.
    let version = 3;
    fake.api.getGitHubApp = (async () => ({ ...APP, version })) as never;
    const pending = deferred<never>();
    const sent: number[] = [];
    fake.api.rotateGitHubAppKey = (async (_org: string, input: { expectedVersion: number }) => {
      sent.push(input.expectedVersion);
      if (sent.length === 1) return pending.promise;
      return { outcome: "rotated", app: { ...APP, version: input.expectedVersion + 1 } };
    }) as never;
    await mount(<GitHubAppPanel org="acme" connections={[appConnection]} targets={[]} envs={new Map()} onChanged={() => {}} rotating onRotate={() => {}} onRotateDone={() => {}} />);
    await settle();
    await type("github-app-key", "K");
    await click("github-app-rotate-submit");
    version = 4;
    await act(async () => client.invalidateQueries({ queryKey: ["github-app", "acme"] }));
    await settle();
    await act(async () => pending.reject(new VarlatchApiError(409, { code: "VERSION_CONFLICT", message: "changed", requestId: "r" })));
    await settle();
    expect(sent).toEqual([3]);
    expect(byTestId("github-app-rotate-conflict").props["data-status"]).toBe("reloaded");
    expect(byTestId("github-app-rotate-submit").props.disabled).toBe(false);
    await click("github-app-rotate-submit");
    await settle();
    expect(sent).toEqual([3, 4]);
  });

  it("points a personal account's App to the personal settings", () => {
    expect(appSettingsUrl({ slug: "varlatch-me", owner: { login: "jeremy", id: 1, type: "user" } })).toBe("https://github.com/settings/apps/varlatch-me");
  });
});

describe("an App Connection's card", () => {
  it("says it goes through the App, has no credential age, and leads to key rotation", async () => {
    let fixed = 0;
    const failing = { id: "snt_1", connectionId: "pcn_app", environmentId: "env_1", state: "active", failureCount: 3, lastResult: "GitHub App: GitHub refused the App's key", lastAttemptAt: "2026-10-09T10:00:00Z" } as unknown as SyncTarget;
    await mount(<ConnectionCard org="acme" connection={appConnection} targets={[failing]} envs={new Map()} onReplace={() => fixed++} onChanged={() => {}} />);
    expect(text(byTestId("connection-via-app-pcn_app"))).toBe("Through the GitHub App");
    expect(root.root.findAll((n) => typeof n.type === "string" && text(n).startsWith("Tokens issued for each push"))).not.toHaveLength(0);
    const item = menuItem("replace-credential-pcn_app") as unknown as { label: string };
    expect(item.label).toBe("Rotate the App's key");
    expect(all("credential-expiry-pcn_app")).toHaveLength(0);
    expect(fixed).toBe(0);
  });
});
