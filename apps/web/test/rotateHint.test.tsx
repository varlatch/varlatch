// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { afterEach, describe, expect, it, vi } from "vitest";
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
});
vi.mock("../src/shell/Shell", () => ({ errorMessage: (err: unknown) => String(err) }));
vi.mock("../src/components/Dialog", () => ({
  Dialog: ({ open, children, footer }: { open: boolean; children: React.ReactNode; footer: React.ReactNode }) =>
    open ? (
      <div>
        {children}
        {footer}
      </div>
    ) : null,
}));
import { RotateDialog } from "../src/features/values/RotateDialog";

/** The Contract's rotation hint is shown before a rotation starts (ADR-0053). */

let root: ReactTestRenderer | undefined;
const hints = () => root!.root.findAll((n) => typeof n.type === "string" && n.props["data-testid"] === "rotate-hint");
const text = (node: ReactTestInstance): string => node.children.map((c) => (typeof c === "string" ? c : text(c))).join("");

async function open(rotationHint?: string) {
  await act(async () => {
    root = create(
      <RotateDialog open item="ADMIN_KEY" project="api" env="production" targets={[]} rotationHint={rotationHint} onClose={() => {}} onRotate={async () => {}} />,
    );
  });
}

afterEach(async () => {
  if (root) await act(async () => root!.unmount());
  root = undefined;
});

describe("the rotate dialog", () => {
  it("shows the Contract's rotation hint", async () => {
    await open("Change the instance secret, restart, then set the new key here.");
    expect(hints()).toHaveLength(1);
    expect(text(hints()[0]!)).toContain("Change the instance secret, restart, then set the new key here.");
  });

  it("shows nothing extra without one", async () => {
    await open();
    expect(hints()).toHaveLength(0);
  });
});
