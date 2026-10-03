// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { startAuthentication, type PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/browser";
import { Fingerprint, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import { VarlatchApiError, type DeviceSignInLookup } from "@varlatch/sdk";
import { useSession } from "../../lib/session";
import { Button, Callout, Field, Input } from "../../components/ui";
import { BrandMark } from "../../shell/BrandMark";
import { CenteredCard } from "../../shell/AuthScreens";
import { formatDateTime, formatTime } from "../../lib/time";

/**
 * Device sign-in's verification page: a CLI started a sign-in elsewhere
 * (`varlatch login --start`) and showed an address and a code. The person,
 * already signed in here, types the code (it is never taken from the URL),
 * reads who asks, and approves with a fresh passkey confirmation, or denies.
 */

type Step =
  | { kind: "enter"; error?: string }
  | { kind: "confirm"; userCode: string; lookup: DeviceSignInLookup; error?: string }
  | { kind: "done"; decision: "approved" | "denied" };

const LOOPBACK = new Set(["127.0.0.1", "[::1]", "localhost"]);

function lifetime(seconds: number): string {
  if (seconds % 3600 === 0) return `${seconds / 3600} hour${seconds === 3600 ? "" : "s"}`;
  if (seconds % 60 === 0) return `${seconds / 60} minutes`;
  return `${seconds} seconds`;
}

function lookupError(err: unknown): string {
  if (err instanceof VarlatchApiError) {
    if (err.code === "RESOURCE_NOT_FOUND") return "No pending sign-in has this code. Check the code the CLI shows: it lasts 10 minutes.";
    if (err.code === "RATE_LIMITED") {
      const retryAt = typeof err.details?.retryAt === "string" ? err.details.retryAt : null;
      return `Too many wrong codes. Code entry is paused${retryAt ? ` until ${formatTime(retryAt)}` : " for a few minutes"}.`;
    }
    if (err.code === "PERMISSION_DENIED") return err.message;
  }
  return err instanceof Error ? err.message : String(err);
}

export function DevicePage() {
  const { api } = useSession();
  const [step, setStep] = useState<Step>({ kind: "enter" });
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState<"lookup" | "approve" | "deny" | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const profile = useQuery({ queryKey: ["my-profile"], queryFn: () => api.getMyProfile(), retry: false });
  useEffect(() => {
    if (step.kind === "enter") input.current?.focus();
  }, [step.kind]);

  if (location.protocol !== "https:" && !LOOPBACK.has(location.hostname)) {
    return (
      <Frame>
        <Callout tone="danger" icon={<ShieldAlert size={16} />} title="This page needs HTTPS">
          Approving a sign-in here would send its details over an unencrypted connection. Open this address with https://.
        </Callout>
      </Frame>
    );
  }

  const lookUp = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy("lookup");
    try {
      const lookup = await api.lookupDeviceSignIn(code);
      setStep({ kind: "confirm", userCode: code, lookup });
    } catch (err) {
      setStep({ kind: "enter", error: lookupError(err) });
    } finally {
      setBusy(null);
    }
  };

  const decide = async (decision: "approve" | "deny") => {
    if (step.kind !== "confirm") return;
    setBusy(decision);
    try {
      let assertion: unknown;
      if (decision === "approve") {
        const options = step.lookup.approval?.publicKey as PublicKeyCredentialRequestOptionsJSON | undefined;
        if (!options) throw new Error("You have no passkey to approve with.");
        try {
          assertion = await startAuthentication({ optionsJSON: options });
        } catch (err) {
          // Cancelled or timed out in the browser: nothing was sent, the challenge is still usable.
          setStep({ ...step, error: `The passkey confirmation did not complete (${err instanceof Error ? err.name : "cancelled"}). Nothing was approved.` });
          return;
        }
      }
      const result = await api.decideDeviceSignIn({ userCode: step.userCode, decision, ...(assertion ? { assertion } : {}) });
      setStep({ kind: "done", decision: result.decision });
    } catch (err) {
      if (err instanceof VarlatchApiError && err.code === "STATE_CHANGED") {
        setStep({ kind: "enter", error: "This sign-in was already decided, or it expired. Nothing changed." });
      } else if (err instanceof VarlatchApiError && err.code === "PERMISSION_DENIED") {
        setCode("");
        setStep({ kind: "enter", error: `${err.message}.` });
      } else {
        setStep({ kind: "enter", error: lookupError(err) });
      }
    } finally {
      setBusy(null);
    }
  };

  if (step.kind === "done") {
    return (
      <Frame>
        <div data-testid="device-result" data-decision={step.decision} className="text-center">
          {step.decision === "approved" ? (
            <ShieldCheck size={36} className="mx-auto text-accent" aria-hidden="true" />
          ) : (
            <ShieldX size={36} className="mx-auto text-deny" aria-hidden="true" />
          )}
          <h1 className="mt-4 text-[20px] font-semibold">{step.decision === "approved" ? "Sign-in approved" : "Sign-in denied"}</h1>
          <p className="mt-2 text-[13px] text-muted">
            {step.decision === "approved"
              ? "Go back to the CLI: it finishes signing in with varlatch login --wait. You can close this page."
              : "The CLI is told the sign-in was refused. Nothing was signed in."}
          </p>
        </div>
      </Frame>
    );
  }

  if (step.kind === "confirm") {
    const { signIn, approval } = step.lookup;
    const until = new Date(Date.now() + signIn.ttlSeconds * 1000).toISOString();
    const who = profile.data?.name;
    return (
      <Frame>
        <div data-testid="device-confirm">
          <h1 className="text-[20px] font-semibold">Approve this sign-in?</h1>
          <p className="mt-3 text-[14px] leading-relaxed">
            A Varlatch CLI asks to sign in as <strong>you{who ? ` (${who})` : ""}</strong>. Approving signs that CLI in as you, with your
            access, for <strong>{lifetime(signIn.ttlSeconds)}</strong> (until about {formatDateTime(until)}).
          </p>
          <dl className="mt-4 space-y-1.5 rounded-lg border border-bd bg-inset px-4 py-3 text-[13px]">
            <Detail label="Code" value={signIn.userCode} testId="device-detail-code" />
            <Detail label="Requested from" value={signIn.requesterIp ?? "unknown address"} testId="device-detail-ip" />
            <Detail label="User agent" value={signIn.requesterUserAgent ?? "not given"} testId="device-detail-agent" />
            <Detail label="At" value={formatDateTime(signIn.requestedAt)} />
            {signIn.name && <Detail label="Name" value={signIn.name} />}
          </dl>
          <p className="mt-4 text-[13px] font-medium">Approve only a sign-in you started yourself.</p>
          {!approval && (
            <Callout tone="warn" className="mt-3" title="You have no passkey to approve with">
              Add a passkey under Account, Security, then enter the code again. You can still deny.
            </Callout>
          )}
          {step.error && (
            <p className="mt-3 text-[13px] text-deny" role="alert" data-testid="device-error">
              {step.error}
            </p>
          )}
          <div className="mt-5 flex gap-2">
            <Button
              variant="primary"
              size="lg"
              className="flex-1"
              icon={<Fingerprint size={18} />}
              loading={busy === "approve"}
              disabled={!approval || busy !== null}
              data-testid="device-approve"
              onClick={() => void decide("approve")}
            >
              Approve with passkey
            </Button>
            <Button
              variant="danger"
              size="lg"
              loading={busy === "deny"}
              disabled={busy !== null}
              data-testid="device-deny"
              onClick={() => void decide("deny")}
            >
              Deny
            </Button>
          </div>
          <button
            type="button"
            className="mt-4 text-[13px] text-muted underline-offset-2 hover:text-fg hover:underline"
            onClick={() => {
              setCode("");
              setStep({ kind: "enter" });
            }}
          >
            Enter a different code
          </button>
        </div>
      </Frame>
    );
  }

  return (
    <Frame>
      <form onSubmit={(e) => void lookUp(e)} data-testid="device-enter">
        <h1 className="text-[20px] font-semibold">Sign in a CLI</h1>
        <p className="mt-2 text-[13px] text-muted">
          Enter the code the Varlatch CLI shows. You will see who asks before anything is approved.
        </p>
        <Field label="Code" htmlFor="device-code" className="mt-5" error={step.error}>
          <Input
            id="device-code"
            ref={input}
            mono
            autoComplete="off"
            autoCapitalize="characters"
            spellCheck={false}
            placeholder="XXXX-XXXX"
            maxLength={16}
            value={code}
            invalid={Boolean(step.error)}
            onChange={(e) => setCode(e.target.value.toUpperCase())}
            className="h-10 w-full text-center text-[18px] tracking-[0.2em]"
            data-testid="device-code-input"
          />
        </Field>
        <Button
          type="submit"
          variant="primary"
          size="lg"
          className="mt-5 w-full"
          loading={busy === "lookup"}
          disabled={code.replace(/[\s-]/g, "").length < 8}
          data-testid="device-continue"
        >
          Continue
        </Button>
      </form>
    </Frame>
  );
}

function Frame({ children }: { children: React.ReactNode }) {
  return (
    <CenteredCard testId="device-page">
      <div className="rounded-2xl border border-bd bg-raised px-8 pb-7 pt-8 shadow-pop">
        <div className="mb-5 flex justify-center">
          <BrandMark size={40} />
        </div>
        {children}
      </div>
    </CenteredCard>
  );
}

function Detail({ label, value, testId }: { label: string; value: string; testId?: string }) {
  return (
    <div className="flex gap-3">
      <dt className="w-28 shrink-0 text-muted">{label}</dt>
      <dd className="min-w-0 break-words font-mono text-[12.5px]" data-testid={testId}>
        {value}
      </dd>
    </div>
  );
}
