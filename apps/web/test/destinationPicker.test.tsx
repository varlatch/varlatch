// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AccessCheck, DestinationListing, PlatformConnection } from "@varlatch/protocol";

/**
 * The Destination step lists what the chosen connection can see, keeps the
 * field typeable for what it cannot, and never shows another connection's
 * list. Review still checks the destination, picked or typed.
 */

const fake = vi.hoisted(() => ({ api: {} as Record<string, (...args: never[]) => unknown> }));
vi.hoisted(() => vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true));
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: fake.api }) }));
vi.mock("../src/components/Toast", () => ({ useToast: () => ({ success: () => {}, error: () => {} }) }));
vi.mock("../src/components/Dialog", () => ({
  Dialog: ({ children, footer }: { children: React.ReactNode; footer?: React.ReactNode }) => (
    <div>
      {children}
      {footer}
    </div>
  ),
  useConfirm: () => async () => true,
}));

import { AddIntegrationDialog } from "../src/features/sync/AddIntegrationDialog";

const OK: AccessCheck = { status: "ok", where: "connection", message: "ok" };
const REJECTED: AccessCheck = { status: "credential-rejected", where: "connection", httpStatus: 401, message: "GitHub rejected the token." };
const listed = (...repos: string[]): DestinationListing => ({
  check: OK,
  items: repos.map((name) => ({ destination: { repo: name }, label: name, detail: "private" })),
  truncated: false,
});

/** Calls that resolve (or fail) only when the test says so. */
function deferred<T>() {
  const calls: { input: Record<string, unknown>; resolve: (v: T) => void; reject: (e: unknown) => void }[] = [];
  const fn = (_org: string, input: Record<string, unknown>) =>
    new Promise<T>((resolve, reject) => {
      calls.push({ input, resolve, reject });
    });
  return { calls, fn };
}

const github = (id: string, owner: string): PlatformConnection =>
  ({ id, platform: "github-actions", name: `GitHub ${owner}`, baseIdentity: owner, version: 1 }) as PlatformConnection;
const coolify = { id: "pcn_c", platform: "coolify", name: "Coolify", baseIdentity: "https://coolify.example.com", version: 1 } as PlatformConnection;

let root: ReactTestRenderer;
let listings: ReturnType<typeof deferred<DestinationListing>>;
let checks: ReturnType<typeof deferred<AccessCheck>>;
let createdTargets: Record<string, unknown>[];

beforeEach(() => {
  listings = deferred<DestinationListing>();
  checks = deferred<AccessCheck>();
  createdTargets = [];
  fake.api = {
    listPlatformDestinations: listings.fn as never,
    checkPlatformAccess: checks.fn as never,
    effectiveConfiguration: (async () => ({ items: [{ name: "PORT", sensitive: false }] })) as never,
    getActiveContract: (async () => ({ contract: { items: [] } })) as never,
    createSyncTarget: (async (...args: unknown[]) => {
      createdTargets.push(args[3] as Record<string, unknown>);
      return {};
    }) as never,
  };
});
afterEach(async () => {
  await act(async () => root?.unmount());
});

async function open(connections: PlatformConnection[]) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(
      <QueryClientProvider client={client}>
        <AddIntegrationDialog
          open
          onClose={() => {}}
          onCreated={() => {}}
          org="acme"
          project="api"
          envName="development"
          adapters={["github-actions", "coolify"]}
          connections={connections}
        />
      </QueryClientProvider>,
    );
  });
}

const all = (id: string) => root.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const byTestId = (id: string): ReactTestInstance => {
  const found = all(id);
  if (found.length !== 1) throw new Error(`${found.length} elements with data-testid ${id}`);
  return found[0]!;
};
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");
const listStatus = () => byTestId("destination-list").props["data-status"] as string;
const options = () =>
  root.root
    .findAll((n) => typeof n.type === "string" && String(n.props["data-testid"] ?? "").startsWith("destination-option-"))
    .map((n) => String(n.props["data-testid"]).slice("destination-option-".length));
async function click(id: string) {
  await act(async () => byTestId(id).props.onClick());
}
async function type(id: string, value: string) {
  await act(async () => byTestId(id).props.onChange({ target: { value } }));
}
async function settle(fn: () => void) {
  await act(async () => {
    fn();
    await Promise.resolve();
  });
}
async function toDestination(connectionId: string) {
  await click(`connection-option-${connectionId}`);
  await click("wizard-next");
}

describe("Destination step", () => {
  it("lists the connection's repositories, and picking one fills the field", async () => {
    await open([github("pcn_a", "acme")]);
    await toDestination("pcn_a");
    expect(listings.calls).toHaveLength(1);
    expect(listings.calls[0]!.input).toEqual({ connectionId: "pcn_a" });
    expect(listStatus()).toBe("pending");
    expect(byTestId("wizard-next").props.disabled).toBe(true);

    await settle(() => listings.calls[0]!.resolve(listed("api", "web", "worker")));
    expect(options()).toEqual(["api", "web", "worker"]);
    await click("destination-option-web");
    expect(byTestId("dest-repo").props.value).toBe("web");
    expect(byTestId("wizard-next").props.disabled).toBe(false);
    // A picked repository keeps the others in view, to pick another.
    expect(options()).toEqual(["api", "web", "worker"]);

    await type("dest-repo", "w");
    expect(options()).toEqual(["web", "worker"]);
    expect(text(byTestId("destination-list-count"))).toContain("2 of 3 repositories");
  });

  it("never shows a previous connection's list, and clears its destination", async () => {
    await open([github("pcn_a", "acme"), github("pcn_b", "other")]);
    await toDestination("pcn_a");
    await settle(() => listings.calls[0]!.resolve(listed("api")));
    await click("destination-option-api");

    // Back to the connection, pick another: a second listing, the field cleared.
    await click("wizard-back");
    await click("connection-option-pcn_b");
    await click("wizard-next");
    expect(byTestId("dest-repo").props.value).toBe("");
    expect(listings.calls).toHaveLength(2);
    expect(listings.calls[1]!.input).toEqual({ connectionId: "pcn_b" });

    // Back and forth again while B's listing is out: A's answers never land.
    await click("wizard-back");
    await click("connection-option-pcn_a");
    await click("wizard-next");
    await click("wizard-back");
    await click("connection-option-pcn_b");
    await click("wizard-next");
    await settle(() => listings.calls[2]!.resolve(listed("from-a")));
    expect(listStatus()).toBe("pending");
    await settle(() => listings.calls[3]!.resolve(listed("from-b")));
    await settle(() => listings.calls[1]!.resolve(listed("stale-b")));
    expect(options()).toEqual(["from-b"]);
  });

  it("clears a picked destination when a new connection's owner changes", async () => {
    await open([]);
    await click("platform-card-github-actions");
    await type("base-identity", "acme");
    await type("connection-name", "GitHub");
    await type("connection-credential", "test-token");
    await click("wizard-next");
    await settle(() => listings.calls[0]!.resolve(listed("api")));
    await click("destination-option-api");
    await type("dest-gh-environment", "production");

    await click("wizard-back");
    await type("base-identity", "other-owner");
    await click("wizard-next");
    expect(listings.calls[1]!.input).toMatchObject({ platform: "github-actions", baseIdentity: "other-owner" });
    expect(byTestId("dest-repo").props.value).toBe("");
    expect(byTestId("dest-gh-environment").props.value).toBe("");
  });

  it("keeps the destination when the owner is only retyped in another case", async () => {
    await open([]);
    await click("platform-card-github-actions");
    await type("base-identity", "acme");
    await type("connection-name", "GitHub");
    await type("connection-credential", "test-token");
    await click("wizard-next");
    await settle(() => listings.calls[0]!.resolve(listed("api")));
    await click("destination-option-api");
    await click("wizard-back");
    await type("base-identity", "Acme");
    await click("wizard-next");
    expect(byTestId("dest-repo").props.value).toBe("api");
  });

  it("says when the credential sees nothing, and takes a typed name", async () => {
    await open([github("pcn_a", "acme")]);
    await toDestination("pcn_a");
    await settle(() => listings.calls[0]!.resolve(listed()));
    expect(listStatus()).toBe("empty");
    expect(text(byTestId("destination-list"))).toContain("This credential sees no repositories");
    await type("dest-repo", "not-created-yet");
    expect(byTestId("wizard-next").props.disabled).toBe(false);
  });

  it("names the App's installation, not a credential, for an App connection", async () => {
    await open([{ ...github("pcn_app", "acme"), name: "GitHub (acme)", credentialKind: "github-app" } as PlatformConnection]);
    await toDestination("pcn_app");
    await settle(() => listings.calls[0]!.resolve(listed("api", "web")));
    expect(text(byTestId("destination-list-count"))).toContain("2 repositories the App's installation includes");
    expect(text(byTestId("destination-list-count"))).not.toContain("credential");
  });

  it("says no unarchived repositories are listed for the App's installation, and how to change that", async () => {
    await open([{ ...github("pcn_app", "acme"), credentialKind: "github-app" } as PlatformConnection]);
    await toDestination("pcn_app");
    await settle(() => listings.calls[0]!.resolve(listed()));
    expect(text(byTestId("destination-list"))).toContain(
      "No unarchived repositories are listed for the App's installation: add one to it on GitHub, or unarchive one there.",
    );
  });

  it("offers Try again on an empty list, for a destination created since", async () => {
    await open([github("pcn_a", "acme")]);
    await toDestination("pcn_a");
    await settle(() => listings.calls[0]!.resolve(listed()));
    await click("destination-retry");
    expect(listings.calls).toHaveLength(2);
    await settle(() => listings.calls[1]!.resolve(listed("created-since")));
    expect(options()).toEqual(["created-since"]);
  });

  it("reloads a loaded list too", async () => {
    await open([github("pcn_a", "acme")]);
    await toDestination("pcn_a");
    await settle(() => listings.calls[0]!.resolve(listed("api")));
    await click("destination-retry");
    expect(listStatus()).toBe("pending");
    await settle(() => listings.calls[1]!.resolve(listed("api", "new-repo")));
    expect(options()).toEqual(["api", "new-repo"]);
  });

  it("shows why a listing failed, retries it, and still takes a typed name", async () => {
    await open([github("pcn_a", "acme")]);
    await toDestination("pcn_a");
    await settle(() => listings.calls[0]!.resolve({ check: REJECTED, items: [], truncated: false }));
    expect(listStatus()).toBe("failed");
    expect(text(byTestId("destination-list"))).toContain("GitHub rejected the token.");

    await click("destination-retry");
    expect(listings.calls).toHaveLength(2);
    await settle(() => listings.calls[1]!.reject(new Error("Network error")));
    expect(listStatus()).toBe("error");
    expect(text(byTestId("destination-list"))).toContain("Network error");

    await type("dest-repo", "api");
    expect(byTestId("wizard-next").props.disabled).toBe(false);
    await click("destination-retry");
    await settle(() => listings.calls[2]!.resolve(listed("api", "web")));
    expect(listStatus()).toBe("ok");
  });

  it("calls a truncated list partial, and never claims an empty one is complete", async () => {
    await open([github("pcn_a", "acme")]);
    await toDestination("pcn_a");
    await settle(() => listings.calls[0]!.resolve({ ...listed("api"), truncated: true }));
    expect(text(byTestId("destination-list-count"))).toContain("a partial list");
    expect(text(byTestId("destination-list-count"))).not.toContain("1,000");

    await click("destination-retry");
    await settle(() => listings.calls[1]!.resolve({ ...listed(), truncated: true }));
    const empty = text(byTestId("destination-list"));
    expect(empty).not.toContain("This credential sees no repositories");
    expect(empty).toContain("stopped reading before it found any repositories");
    expect(all("destination-retry")).toHaveLength(1);
  });

  it("lists a Coolify team's applications by name, picks the UUID, and Review still checks it", async () => {
    await open([coolify]);
    await toDestination("pcn_c");
    await settle(() =>
      listings.calls[0]!.resolve({
        check: OK,
        items: [
          { destination: { applicationUuid: "api123" }, label: "api" },
          { destination: { applicationUuid: "web123" }, label: "web", detail: "web.example.com" },
        ],
        truncated: false,
      }),
    );
    await type("dest-app", "example.com");
    expect(options()).toEqual(["web123"]);
    await click("destination-option-web123");
    expect(byTestId("dest-app").props.value).toBe("web123");

    await click("wizard-next");
    await click("wizard-next");
    expect(checks.calls).toHaveLength(1);
    expect(checks.calls[0]!.input).toEqual({ connectionId: "pcn_c", destination: { applicationUuid: "web123" } });
    expect(text(byTestId("integration-review"))).toContain("web (web123)");
    expect(byTestId("confirm-integration").props.disabled).toBe(true);
    await settle(() => checks.calls[0]!.resolve({ status: "not-found", where: "destination", message: "gone" }));
    expect(text(byTestId("confirm-integration"))).toBe("Create anyway");
    await click("confirm-integration");
    expect(createdTargets).toHaveLength(1);
    expect(createdTargets[0]!.destination).toMatchObject({ applicationUuid: "web123" });
  });

  it("does not list for Convex, whose deployment is the destination", async () => {
    await open([{ id: "pcn_x", platform: "convex", name: "Convex", baseIdentity: "https://happy-animal-123.convex.cloud", version: 1 } as PlatformConnection]);
    await toDestination("pcn_x");
    expect(listings.calls).toHaveLength(0);
    expect(all("destination-list")).toHaveLength(0);
  });
});
