// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useState } from "react";
import { act, create, type ReactTestRenderer } from "react-test-renderer";
import { afterEach, describe, expect, it, vi } from "vitest";
vi.hoisted(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
});
vi.mock("../src/lib/session", () => ({ useSession: () => ({ api: {} }) }));
vi.mock("../src/components/Toast", () => ({ useToast: () => ({ success: () => {}, error: () => {}, info: () => {} }) }));
import { GraceInput } from "../src/features/projects/ManagedContractEditor";

/** The grace field keeps what is being typed, and reports seconds (ADR-0053). */

let root: ReactTestRenderer | undefined;
let reported: (number | undefined)[] = [];
let setOutside: (s: number | undefined) => void = () => {};

function Harness({ initial }: { initial?: number }) {
  const [seconds, setSeconds] = useState<number | undefined>(initial);
  setOutside = setSeconds;
  return (
    <GraceInput
      name="ADMIN_KEY"
      seconds={seconds}
      disabled={false}
      onChange={(s) => {
        reported.push(s);
        setSeconds(s);
      }}
    />
  );
}
const input = () => root!.root.findByType("input");
const type = async (value: string) => act(async () => input().props.onChange({ target: { value } }));

afterEach(async () => {
  if (root) await act(async () => root!.unmount());
  root = undefined;
  reported = [];
});

describe("the grace field", () => {
  it("keeps unfinished input such as '.' and '0.' while typing half an hour", async () => {
    await act(async () => {
      root = create(<Harness />);
    });
    for (const step of [".", ".5"]) await type(step);
    expect(input().props.value).toBe(".5");
    expect(reported.at(-1)).toBe(1800);
    await type("0.");
    expect(input().props.value).toBe("0.");
  });

  it("shows hours for a stored value and follows an outside change such as undo", async () => {
    await act(async () => {
      root = create(<Harness initial={86400} />);
    });
    expect(input().props.value).toBe("24");
    await act(async () => setOutside(7200));
    expect(input().props.value).toBe("2");
    await act(async () => setOutside(undefined));
    expect(input().props.value).toBe("");
  });
});
