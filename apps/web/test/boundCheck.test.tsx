// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AccessCheck, PlatformConnection } from "@varlatch/protocol";

/**
 * An access check counts only for the inputs it checked: a dialog never
 * saves an edited credential on an older check's success, never saves after
 * it closed, and never creates an integration while its check is out.
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

import { useBoundCheck } from "../src/features/sync/useBoundCheck";
import { NewConnectionDialog, ReplaceCredentialDialog } from "../src/features/sync/ConnectionsPage";
import { AddIntegrationDialog } from "../src/features/sync/AddIntegrationDialog";

const OK: AccessCheck = { status: "ok", where: "connection", message: "ok" };
const REJECTED: AccessCheck = { status: "credential-rejected", where: "connection", httpStatus: 401, message: "rejected" };

/** Checks that resolve only when the test says so, in order. */
function deferredChecks() {
  const calls: { input: unknown; resolve: (r: AccessCheck) => void }[] = [];
  const check = (_org: string, input: unknown) =>
    new Promise<AccessCheck>((resolve) => {
      calls.push({ input, resolve });
    });
  return { calls, check };
}

let root: ReactTestRenderer;
async function mount(element: React.ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root = create(<QueryClientProvider client={client}>{element}</QueryClientProvider>);
  });
}
afterEach(async () => {
  await act(async () => root?.unmount());
});

const byTestId = (id: string): ReactTestInstance => root.root.find((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const text = (node: ReactTestInstance | string): string =>
  typeof node === "string" ? node : node.children.map((c) => text(c as ReactTestInstance | string)).join("");
async function click(id: string) {
  await act(async () => byTestId(id).props.onClick());
}
async function type(id: string, value: string) {
  await act(async () => byTestId(id).props.onChange({ target: { value } }));
}
async function settle(resolve: () => void) {
  await act(async () => {
    resolve();
    await Promise.resolve();
  });
}

describe("useBoundCheck", () => {
  let hook: ReturnType<typeof useBoundCheck<string, AccessCheck>>;
  const Probe = ({ input, check }: { input: string; check: (i: string) => Promise<AccessCheck> }) => {
    hook = useBoundCheck(input, check);
    return null;
  };

  it("drops a completion for inputs that changed, and acts on the checked inputs otherwise", async () => {
    const checks = deferredChecks();
    const check = (i: string) => checks.check("org", i);
    const then = vi.fn();
    await act(async () => {
      root = create(<Probe input="first" check={check} />);
    });
    await act(async () => hook.run(then));
    expect(hook.pending).toBe(true);
    await act(async () => root.update(<Probe input="second" check={check} />));
    expect(hook.pending).toBe(false);
    await settle(() => checks.calls[0]!.resolve(OK));
    expect(then).not.toHaveBeenCalled();
    expect(hook.result).toBeUndefined();
    expect(hook.settled).toBe(false);

    await act(async () => hook.run(then));
    await settle(() => checks.calls[1]!.resolve(OK));
    expect(then).toHaveBeenCalledWith(OK, "second");
    expect(hook.settled).toBe(true);
  });

  it("lets only the latest attempt count, even for the same inputs", async () => {
    const checks = deferredChecks();
    const then = vi.fn();
    await act(async () => {
      root = create(<Probe input="same" check={(i) => checks.check("org", i)} />);
    });
    await act(async () => hook.run(then));
    await act(async () => hook.run(then));
    await settle(() => checks.calls[1]!.resolve(REJECTED));
    expect(hook.result).toEqual(REJECTED);
    await settle(() => checks.calls[0]!.resolve(OK));
    expect(hook.result).toEqual(REJECTED);
    expect(then).toHaveBeenCalledTimes(1);
    expect(then).toHaveBeenCalledWith(REJECTED, "same");
  });

  it("stays pending while a newer attempt is out, whatever an older one says", async () => {
    const checks = deferredChecks();
    await act(async () => {
      root = create(<Probe input="same" check={(i) => checks.check("org", i)} />);
    });
    await act(async () => hook.run());
    await act(async () => hook.run());
    await settle(() => checks.calls[0]!.resolve(OK));
    expect(hook.pending).toBe(true);
    expect(hook.settled).toBe(false);
    expect(hook.result).toBeUndefined();
  });

  it("drops a completion after unmount", async () => {
    const checks = deferredChecks();
    const then = vi.fn();
    await act(async () => {
      root = create(<Probe input="first" check={(i) => checks.check("org", i)} />);
    });
    await act(async () => hook.run(then));
    await act(async () => root.unmount());
    await settle(() => checks.calls[0]!.resolve(OK));
    expect(then).not.toHaveBeenCalled();
  });
});

describe("New connection", () => {
  let checks: ReturnType<typeof deferredChecks>;
  let created: unknown[];
  beforeEach(() => {
    checks = deferredChecks();
    created = [];
    fake.api = {
      checkPlatformAccess: checks.check as never,
      createPlatformConnection: (async (_org: string, input: unknown) => {
        created.push(input);
        return { name: "x" };
      }) as never,
    };
  });
  const fill = async (credential: string) => {
    await type("connection-base-identity", "https://coolify.example.com");
    await type("connection-display-name", "Coolify");
    await type("connection-new-credential", credential);
  };

  it("never saves a credential edited while an older check was out", async () => {
    await mount(<NewConnectionDialog org="acme" adapters={["coolify"]} initial="coolify" onClose={() => {}} onCreated={() => {}} />);
    await fill("first-token");
    await click("save-connection");
    await type("connection-new-credential", "edited-token");
    await settle(() => checks.calls[0]!.resolve(OK));
    expect(created).toEqual([]);

    await click("save-connection");
    expect(checks.calls[1]!.input).toMatchObject({ credential: "edited-token" });
    await settle(() => checks.calls[1]!.resolve(OK));
    expect(created).toEqual([{ platform: "coolify", baseIdentity: "https://coolify.example.com", credential: "edited-token", name: "Coolify" }]);
  });

  it("never saves after the dialog closed", async () => {
    await mount(<NewConnectionDialog org="acme" adapters={["coolify"]} initial="coolify" onClose={() => {}} onCreated={() => {}} />);
    await fill("token");
    await click("save-connection");
    await act(async () => root.unmount());
    await settle(() => checks.calls[0]!.resolve(OK));
    expect(created).toEqual([]);
  });

  it("offers Save anyway only for the inputs that failed", async () => {
    await mount(<NewConnectionDialog org="acme" adapters={["coolify"]} initial="coolify" onClose={() => {}} onCreated={() => {}} />);
    await fill("token");
    await click("save-connection");
    await settle(() => checks.calls[0]!.resolve(REJECTED));
    expect(text(byTestId("save-connection"))).toBe("Save anyway");
    await type("connection-new-credential", "another-token");
    expect(text(byTestId("save-connection"))).toBe("Create connection");
  });
});

describe("Replace credential", () => {
  it("never replaces with a credential edited while an older check was out", async () => {
    const checks = deferredChecks();
    const replaced: string[] = [];
    fake.api = {
      checkPlatformAccess: checks.check as never,
      replacePlatformCredential: (async (_org: string, _id: string, input: { credential: string }) => {
        replaced.push(input.credential);
        return {};
      }) as never,
    };
    const connection = { id: "pcn_1", platform: "coolify", name: "Coolify", baseIdentity: "https://coolify.example.com", version: 1 } as PlatformConnection;
    await mount(<ReplaceCredentialDialog org="acme" connection={connection} targets={[]} envs={new Map()} onClose={() => {}} onReplaced={() => {}} />);
    await type("new-credential-pcn_1", "first-token");
    await click("confirm-credential-pcn_1");
    await type("new-credential-pcn_1", "edited-token");
    await settle(() => checks.calls[0]!.resolve(OK));
    expect(replaced).toEqual([]);

    await click("confirm-credential-pcn_1");
    await settle(() => checks.calls[1]!.resolve(OK));
    expect(replaced).toEqual(["edited-token"]);
  });
});

describe("Add integration", () => {
  it("keeps Create disabled until the check is back, then keeps the explicit override", async () => {
    const checks = deferredChecks();
    const createdTargets: unknown[] = [];
    fake.api = {
      checkPlatformAccess: checks.check as never,
      effectiveConfiguration: (async () => ({ items: [{ name: "PORT", sensitive: false }] })) as never,
      getActiveContract: (async () => ({ contract: { items: [] } })) as never,
      createSyncTarget: (async (...args: unknown[]) => {
        createdTargets.push(args[3]);
        return {};
      }) as never,
    };
    const connection = { id: "pcn_1", platform: "convex", name: "Convex", baseIdentity: "https://happy-animal-123.convex.cloud", version: 1 } as PlatformConnection;
    await mount(
      <AddIntegrationDialog
        open
        onClose={() => {}}
        onCreated={() => {}}
        org="acme"
        project="api"
        envName="development"
        adapters={["convex"]}
        connections={[connection]}
      />,
    );
    await click("connection-option-pcn_1");
    await click("wizard-next");
    await click("wizard-next");
    await click("wizard-next");
    expect(checks.calls).toHaveLength(1);
    expect(byTestId("confirm-integration").props.disabled).toBe(true);

    await settle(() => checks.calls[0]!.resolve(REJECTED));
    const confirm = byTestId("confirm-integration");
    expect(confirm.props.disabled).toBe(false);
    expect(text(confirm)).toBe("Create anyway");
    expect(createdTargets).toEqual([]);

    await click("access-retry");
    expect(byTestId("confirm-integration").props.disabled).toBe(true);
    await settle(() => checks.calls[1]!.resolve(OK));
    expect(text(byTestId("confirm-integration"))).toBe("Create integration");
    await click("confirm-integration");
    expect(createdTargets).toHaveLength(1);
  });

  it("keeps Create disabled when an older review check returns before the newer one", async () => {
    const checks = deferredChecks();
    fake.api = {
      checkPlatformAccess: checks.check as never,
      effectiveConfiguration: (async () => ({ items: [] })) as never,
      getActiveContract: (async () => ({ contract: { items: [] } })) as never,
    };
    const connection = { id: "pcn_1", platform: "convex", name: "Convex", baseIdentity: "https://happy-animal-123.convex.cloud", version: 1 } as PlatformConnection;
    await mount(
      <AddIntegrationDialog
        open
        onClose={() => {}}
        onCreated={() => {}}
        org="acme"
        project="api"
        envName="development"
        adapters={["convex"]}
        connections={[connection]}
      />,
    );
    await click("connection-option-pcn_1");
    await click("wizard-next");
    await click("wizard-next");
    await click("wizard-next");
    // Back to Items and to Review again: a second check of the same inputs.
    await click("wizard-step-3");
    await click("wizard-next");
    expect(checks.calls).toHaveLength(2);
    await settle(() => checks.calls[0]!.resolve(OK));
    expect(byTestId("confirm-integration").props.disabled).toBe(true);
    await settle(() => checks.calls[1]!.resolve(REJECTED));
    expect(byTestId("confirm-integration").props.disabled).toBe(false);
    expect(text(byTestId("confirm-integration"))).toBe("Create anyway");
  });
});
