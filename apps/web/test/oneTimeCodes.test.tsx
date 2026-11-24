// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Environment } from "@varlatch/protocol";
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("window", globalThis);
});
const effectiveConfiguration = vi.fn();
const discloseSecrets = vi.fn();
const api = { effectiveConfiguration, discloseSecrets };
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api, authEpoch: 0, accessEpoch: 0 }) }));
vi.mock("../src/lib/tailnetConnection", async (original) => ({
  ...(await original<object>()),
  useTailnetConnection: () => ({ connection: { status: "idle" }, client: null }),
}));
vi.mock("../src/shell/Shell", () => ({ errorMessage: (err: unknown) => (err instanceof Error ? err.message : String(err)) }));
vi.mock("../src/components/Dialog", () => ({
  Dialog: ({ open, children, footer }: { open: boolean; children: React.ReactNode; footer: React.ReactNode }) =>
    open ? (
      <div>
        {children}
        {footer}
      </div>
    ) : null,
}));
import { describeEvent, emptyResolver, segmentsText } from "../src/features/audit/describe";
import { codeLabel, isSensitive, seedProblem, type ServerItem } from "../src/features/values/model";
import { qrReader } from "../src/features/values/qr";
import { RotateDialog } from "../src/features/values/RotateDialog";
import { SeedDialog } from "../src/features/values/SeedDialog";
import { useDisclosure } from "../src/features/values/useDisclosure";
import { useExport } from "../src/features/values/useExport";

/** One-time codes (ADR-0061): the seed goes in once, and no bulk path asks for it. */

const URI = "otpauth://totp/Portal:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXQ&issuer=Portal";
const code = { issuer: "Portal", account: "alice", algorithm: "SHA1", digits: 6, periodSeconds: 30 } as const;
const item: ServerItem = { name: "PORTAL_OTP", sensitive: true, source: "self", versionId: "v1", value: null, totp: code };
const env = { id: "env_1", projectId: "prj_1", name: "production", kind: "shared", tier: "production", createdAt: "2026-10-01T00:00:00Z" } as Environment;

let root: ReactTestRenderer | undefined;
const render = async (node: React.ReactElement) => {
  await act(async () => {
    if (root) root.update(node);
    else root = create(node);
  });
};
const all = (id: string) => root!.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === id);
const one = (id: string) => all(id)[0]!;
const text = (node: ReactTestInstance): string => node.children.map((c) => (typeof c === "string" ? c : text(c))).join("");
const type = (id: string, value: string) => act(async () => one(id).props.onChange({ target: { value } }));

beforeEach(() => {
  effectiveConfiguration.mockReset();
  discloseSecrets.mockReset();
});
afterEach(async () => {
  if (root) await act(async () => root!.unmount());
  root = undefined;
  vi.unstubAllGlobals();
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.stubGlobal("window", globalThis);
});

describe("the model", () => {
  it("names a code by what may be read of it", () => {
    expect(codeLabel(item)).toBe("Portal · alice");
    expect(codeLabel({ ...item, totp: { ...code, issuer: "" } })).toBe("alice");
    expect(codeLabel({ ...item, totp: { ...code, issuer: "", account: "" } })).toBe("");
    expect(codeLabel({ name: "X", sensitive: true, source: "self" })).toBeNull();
    expect(isSensitive(item, undefined)).toBe(true);
  });

  it("says what is plainly wrong with a seed, never repeating it", () => {
    expect(seedProblem(`  ${URI}\n`)).toBeNull();
    for (const bad of ["JBSWY3DPEHPK3PXP", "https://x?secret=JBSWY3DPEHPK3PXP", "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP", "otpauth://totp/x", "otpauth://totp/x?secret="]) {
      expect(seedProblem(bad)).toBeTruthy();
      expect(seedProblem(bad)).not.toContain("JBSWY");
    }
  });
});

describe("the seed dialog", () => {
  const open = (onSave: (name: string, uri: string) => Promise<void>, over: { item?: string } = {}) =>
    render(<SeedDialog open project="api" env="production" exists={(n) => n === "TAKEN"} onClose={() => {}} onSave={onSave} {...over} />);

  it("sends a name and the pasted URI once, and keeps neither", async () => {
    const onSave = vi.fn().mockResolvedValue(undefined);
    await open(onSave);
    expect(one("confirm-seed").props.disabled).toBe(true);
    await type("seed-name", "portal otp");
    await type("seed-uri", ` ${URI} `);
    expect(one("seed-uri").props.type).toBe("password");
    await act(async () => one("confirm-seed").props.onClick());
    expect(onSave).toHaveBeenCalledExactlyOnceWith("PORTAL_OTP", URI);
    expect(one("seed-uri").props.value).toBe("");
  });

  it("refuses a name that has a value, and text that is no seed", async () => {
    await open(vi.fn());
    await type("seed-uri", URI);
    await type("seed-name", "TAKEN");
    expect(one("confirm-seed").props.disabled).toBe(true);
    await type("seed-name", "FREE");
    expect(one("confirm-seed").props.disabled).toBe(false);
    await type("seed-uri", "JBSWY3DPEHPK3PXP");
    expect(one("confirm-seed").props.disabled).toBe(true);
    expect(text(one("seed-error"))).toBe("Not an otpauth://totp/ URI.");
  });

  it("replaces the seed of an item, and shows the server's refusal", async () => {
    const onSave = vi.fn().mockRejectedValue(new Error("otpauth: the secret of the otpauth URI is too weak"));
    await open(onSave, { item: "PORTAL_OTP" });
    expect(all("seed-name")).toHaveLength(0);
    await type("seed-uri", URI);
    await act(async () => one("confirm-seed").props.onClick());
    expect(onSave).toHaveBeenCalledWith("PORTAL_OTP", URI);
    expect(text(one("seed-error"))).toContain("too weak");
  });

  it("reads a QR image in the browser where the browser can", async () => {
    await open(vi.fn());
    expect(all("seed-qr")).toHaveLength(0);
    await act(async () => root!.unmount());
    root = undefined;
    const found: { rawValue: string }[] = [{ rawValue: URI }];
    const close = vi.fn();
    vi.stubGlobal("createImageBitmap", async () => ({ close }));
    vi.stubGlobal("BarcodeDetector", class {
      detect = async () => found;
    });
    await open(vi.fn());
    const pick = () => act(async () => one("seed-qr").props.onChange({ target: { files: [new Blob(["x"])], value: "x" } }));
    await pick();
    expect(one("seed-uri").props.value).toBe(URI);
    expect(close).toHaveBeenCalled();
    found[0] = { rawValue: "https://example.com/?secret=JBSWY3DPEHPK3PXP" };
    await pick();
    expect(text(one("seed-error"))).toBe("That QR code holds no otpauth:// URI.");
    found.length = 0;
    await pick();
    expect(text(one("seed-error"))).toBe("No QR code was found in that image.");
  });

  it("has no QR reader without the browser's", () => {
    expect(qrReader({})).toBeNull();
    expect(qrReader({ BarcodeDetector: class {} })).toBeNull();
  });
});

describe("the rotate dialog of a seed", () => {
  it("takes an otpauth URI and offers no generated value", async () => {
    const onRotate = vi.fn().mockResolvedValue(undefined);
    await render(<RotateDialog open seed item="PORTAL_OTP" project="api" env="production" targets={["GitHub"]} onClose={() => {}} onRotate={onRotate} />);
    expect(all("rotate-generate")).toHaveLength(0);
    await type("rotate-value", "not a seed");
    expect(one("confirm-rotate").props.disabled).toBe(true);
    await type("rotate-value", URI);
    await act(async () => one("confirm-rotate").props.onClick());
    expect(onRotate).toHaveBeenCalledWith(URI, 86_400);
  });
});

describe("bulk paths", () => {
  it("an export neither asks for a seed nor writes one", async () => {
    effectiveConfiguration.mockResolvedValue({ environmentId: "env_1", items: [item, { name: "API_KEY", sensitive: true, source: "self", versionId: "v2", value: null }] });
    discloseSecrets.mockResolvedValue({ items: [{ name: "API_KEY", versionId: "v2", value: "k" }], withheld: [] });
    let hook!: ReturnType<typeof useExport>;
    const Probe = () => {
      hook = useExport("acme", "api", env);
      return null;
    };
    await render(<Probe />);
    await act(async () => hook.setIncludeSecrets(true));
    const file = await hook.build();
    expect(discloseSecrets).toHaveBeenCalledExactlyOnceWith("acme", "api", "production", { items: ["API_KEY"] });
    expect(file.text).toContain("# PORTAL_OTP: one-time code, never exported\n");
    expect(file.text).toContain("API_KEY=k\n");
  });

  it("a reveal asks for seeds only when it says so", async () => {
    discloseSecrets.mockResolvedValue({ items: [], withheld: [] });
    let hook!: ReturnType<typeof useDisclosure>;
    const Probe = () => {
      hook = useDisclosure("acme", "api");
      return null;
    };
    await render(<Probe />);
    await act(async () => void (await hook.reveal("production", "all")));
    await act(async () => void (await hook.reveal("production", ["A", "PORTAL_OTP"])));
    await act(async () => void (await hook.reveal("production", ["PORTAL_OTP"], true)));
    expect(discloseSecrets.mock.calls.map((c) => c[3])).toEqual([
      { scope: "all-authorized-secrets" },
      { items: ["A", "PORTAL_OTP"] },
      { items: ["PORTAL_OTP"], totpSeeds: true },
    ]);
  });
});

describe("the audit log", () => {
  const sentence = (eventType: string, metadata: object, resource: object = {}) =>
    segmentsText(describeEvent({ eventId: "e", eventType, occurredAt: "2026-11-24T09:00:00Z", decision: "allow", actorIdentityId: "i", resource, metadata } as never, emptyResolver).segments);
  it("tells a seed's write, reveal and use from a value's", () => {
    expect(sentence("value.written", { totp: true }, { itemName: "PORTAL_OTP" })).toContain("set the seed of PORTAL_OTP");
    expect(sentence("secret.disclosed", { mode: "requested", items: "PORTAL_OTP@v1", totpSeeds: 1 })).toContain("revealed the seed of PORTAL_OTP");
    expect(sentence("capability.exercised", { items: "PORTAL_OTP@v1", oneTimeCodes: "PORTAL_OTP@v1=2026-11-24T09:00:00.000Z" })).toContain("got a one-time code, using PORTAL_OTP");
    expect(sentence("capability.exercised", { items: "API_KEY@v1" })).toContain("used API_KEY");
  });
});
