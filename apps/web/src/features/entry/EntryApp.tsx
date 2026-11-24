// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useRef, useState } from "react";
import { Check, Fingerprint, QrCode, ShieldAlert, Timer } from "lucide-react";
import type { EntryLinkView } from "@varlatch/protocol";
import { Button, Callout, Field, Input, Spinner, StatusDot, Textarea, cn } from "../../components/ui";
import { BrandMark } from "../../shell/BrandMark";
import { CenteredCard } from "../../shell/CenteredCard";
import { showPreferredTheme } from "../../lib/theme";
import { qrReader } from "../values/qr";
import { EntryRefusal, lookup, signIn, signedIn, strayEnds, submit, takeToken } from "./client";

/**
 * The entry page (ADR-0063): a person enters one Secret's value for an
 * application that asked for it, once, and the application never sees it.
 * Shown to people who may not know Varlatch, from a link somebody sent: so it
 * says whose words are whose, shows no link but none of its own, and holds
 * the value in this one field until it is sent.
 */

type Step =
  | { kind: "loading" }
  | { kind: "stopped"; title: string; text: string; tone: "danger" | "neutral" }
  | { kind: "sign-in"; wrong?: string }
  | { kind: "form"; view: EntryLinkView }
  | { kind: "done"; item: string };

const STOPPED: Record<string, string> = {
  RESOURCE_NOT_FOUND: "This link is not known",
  CONSUMED: "A value was entered already",
  EXPIRED: "This link has ended",
  STATE_CHANGED: "The value changed meanwhile",
  RATE_LIMITED: "Wait a few minutes",
};

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Whether this browser may sign in or hold a value here at all. */
export function secureEnough(loc: { protocol: string; hostname: string }): boolean {
  return loc.protocol === "https:" || ["127.0.0.1", "[::1]", "localhost"].includes(loc.hostname);
}

export function EntryApp() {
  const token = useRef("");
  const bearer = useRef<string | null>(null);
  const [step, setStep] = useState<Step>({ kind: "loading" });

  const refused = useCallback((err: unknown) => {
    if (err instanceof EntryRefusal) {
      if (err.reason === "not-for-you") return setStep({ kind: "sign-in", wrong: err.message });
      if (err.code === "AUTHENTICATION_REQUIRED" || err.code === "INVALID_CREDENTIAL") {
        bearer.current = null;
        return setStep({ kind: "sign-in" });
      }
      if (err.code === "PASSKEY_VERIFICATION_REQUIRED") return setStep({ kind: "sign-in", wrong: err.message });
      return setStep({ kind: "stopped", tone: "danger", title: STOPPED[err.code] ?? "This link cannot be used", text: err.message });
    }
    setStep({ kind: "stopped", tone: "danger", title: "This link cannot be used", text: message(err) });
  }, []);

  const look = useCallback(async () => {
    try {
      const view = await lookup(token.current, bearer.current);
      if (!view.signInRequired) return setStep({ kind: "form", view });
      // Somebody signed in in this browser already is asked nothing.
      bearer.current = await signedIn().catch(() => null);
      if (!bearer.current) return setStep({ kind: "sign-in" });
      setStep({ kind: "form", view: await lookup(token.current, bearer.current) });
    } catch (err) {
      refused(err);
    }
  }, [refused]);

  useEffect(() => {
    showPreferredTheme();
    const open = () => {
      const taken = takeToken();
      if (taken === "" && token.current !== "") return;
      token.current = taken;
      if (!secureEnough(window.location)) {
        return setStep({ kind: "stopped", tone: "danger", title: "This page needs HTTPS", text: "A value entered here would be sent unencrypted. Open the link with https://." });
      }
      if (taken === "") {
        return setStep({
          kind: "stopped",
          tone: "neutral",
          title: "Open your link again",
          text: "This page has no link: it may not have been copied whole, or the page was reloaded. Open it again from where you got it.",
        });
      }
      setStep({ kind: "loading" });
      void look();
    };
    open();
    // Another link opened in this tab.
    window.addEventListener("hashchange", open);
    return () => window.removeEventListener("hashchange", open);
  }, [look]);

  let body: React.ReactNode;
  if (step.kind === "loading")
    body = (
      <div className="grid place-items-center py-10">
        <Spinner size={18} />
      </div>
    );
  else if (step.kind === "stopped")
    body = (
      <Callout tone={step.tone} icon={<ShieldAlert size={16} />} title={step.title} data-testid="entry-stopped">
        {step.text}
      </Callout>
    );
  else if (step.kind === "sign-in")
    body = (
      <SignIn
        wrong={step.wrong}
        onSignIn={async () => {
          bearer.current = await signIn(step.wrong !== undefined);
          setStep({ kind: "loading" });
          await look();
        }}
      />
    );
  else if (step.kind === "done")
    body = (
      <Callout tone="success" icon={<Check size={16} />} title="Entered" data-testid="entry-done">
        The value of <span className="font-mono">{step.item}</span> is stored in Varlatch. It cannot be shown here again, and this link does nothing any
        more. You can close this page.
      </Callout>
    );
  else
    body = (
      <EntryForm
        view={step.view}
        onSubmit={async (value) => {
          await submit(token.current, bearer.current, value);
          token.current = "";
          bearer.current = null;
          setStep({ kind: "done", item: step.view.item ?? "" });
        }}
        onRefused={refused}
      />
    );
  return (
    <CenteredCard testId="entry-page">
      <div className="rounded-2xl border border-bd bg-raised px-7 pb-7 pt-7 shadow-pop">
        <div className="mb-5 flex items-center gap-3">
          <BrandMark size={34} />
          <div className="min-w-0">
            <h1 className="text-[17px] font-semibold leading-tight">Enter a secret</h1>
            <p className="mt-0.5 flex items-center gap-2 font-mono text-[12.5px] text-muted">
              <StatusDot tone="ok" />
              <span className="truncate">{window.location.host}</span>
            </p>
          </div>
        </div>
        {body}
      </div>
    </CenteredCard>
  );
}

function SignIn({ wrong, onSignIn }: { wrong: string | undefined; onSignIn: () => Promise<void> }) {
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");
  return (
    <div data-testid="entry-sign-in">
      {wrong ? (
        <Callout tone="warn" title="Sign in as the person it is for" data-testid="entry-wrong-person">
          {wrong}
        </Callout>
      ) : (
        <p className="text-[13px] text-muted">This link is for a person of the organization that asked. Sign in to see what it is for.</p>
      )}
      <Button
        variant="primary"
        size="lg"
        className="mt-5 w-full"
        loading={busy}
        icon={<Fingerprint size={18} />}
        data-testid="entry-sign-in-button"
        onClick={() => {
          setBusy(true);
          setStatus("Waiting for your authenticator…");
          onSignIn()
            .catch((err: unknown) => setStatus(`Sign-in failed: ${message(err)}`))
            .finally(() => setBusy(false));
        }}
      >
        {wrong ? "Sign in as somebody else" : "Continue with passkey"}
      </Button>
      <p className="mt-3 min-h-5 text-center text-[13px] text-muted" aria-live="polite">
        {status}
      </p>
    </div>
  );
}

const WHO: Record<EntryLinkView["restrictedTo"], string> = {
  anyone: "Anyone who has this link can enter the value, once.",
  member: "Any member of the organization who has this link can enter the value, once.",
  identity: "This link is for you alone, once.",
};

function EntryForm({
  view,
  onSubmit,
  onRefused,
}: {
  view: EntryLinkView;
  onSubmit: (value: { value: string } | { otpauth: string }) => Promise<void>;
  onRefused: (err: unknown) => void;
}) {
  const seed = view.accepts === "otpauth";
  const [value, setValue] = useState("");
  const [lines, setLines] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [left, setLeft] = useState(view.expiresInSeconds ?? 0);
  const file = useRef<HTMLInputElement>(null);
  const readQr = seed ? qrReader() : null;

  useEffect(() => {
    const ends = Date.now() + (view.expiresInSeconds ?? 0) * 1000;
    const timer = setInterval(() => setLeft(Math.max(0, Math.ceil((ends - Date.now()) / 1000))), 1000);
    // The browser may keep the page (back and forward): not with a value in it.
    const clear = () => setValue("");
    window.addEventListener("pagehide", clear);
    return () => {
      clearInterval(timer);
      window.removeEventListener("pagehide", clear);
    };
  }, [view.expiresInSeconds]);

  const send = async () => {
    if (value === "" || busy) return;
    setBusy(true);
    setError("");
    try {
      const sent = value;
      await onSubmit(seed ? { otpauth: sent.trim() } : { value: sent });
      setValue("");
    } catch (err) {
      // What can be put right here keeps the form and what was typed.
      if (err instanceof EntryRefusal && (err.code === "VALIDATION_FAILED" || err.code === "UNREACHABLE" || err.code === "MAINTENANCE" || err.code === "RATE_LIMITED")) {
        setError(err.message);
      } else {
        setValue("");
        onRefused(err);
      }
    } finally {
      setBusy(false);
    }
  };

  const fromImage = async (image: Blob | undefined) => {
    if (!image || !readQr) return;
    setError("");
    try {
      const text = await readQr(image);
      if (text === null || !text.startsWith("otpauth://")) setError("No QR code of a two-factor setup was found in that image.");
      else setValue(text);
    } catch {
      setError("That image could not be read.");
    }
  };

  // A pasted line break is the value's: the one-line field would drop it.
  const paste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    const text = e.clipboardData.getData("text");
    if (seed || !/[\r\n]/.test(text.replace(/[\r\n]+$/, ""))) return;
    e.preventDefault();
    setLines(true);
    setValue(text);
  };

  const label = seed ? "otpauth:// URI" : "Value";
  const field = {
    id: "entry-value",
    "data-testid": "entry-value",
    value,
    disabled: busy,
    // Not a password of this site: no password manager should keep it.
    autoComplete: "off",
    "data-1p-ignore": true,
    "data-lpignore": "true",
    "data-bwignore": true,
    autoCapitalize: "off",
    autoCorrect: "off",
    spellCheck: false,
  } as const;
  return (
    <form
      method="post"
      className="space-y-5"
      data-testid="entry-form"
      onSubmit={(e) => {
        e.preventDefault();
        void send();
      }}
    >
      <p className="text-[13px] text-muted">
        <span className="font-medium text-fg" data-testid="entry-requester">
          {view.requestedBy?.name}
        </span>{" "}
        {view.requestedBy?.kind === "human" ? "asks" : "(an application of this organization) asks"} for this value. It goes to Varlatch and not through whoever
        asked, and it cannot be read back here.
      </p>
      <dl className="grid grid-cols-[104px_1fr] gap-x-3 gap-y-1.5 text-[13px]" data-testid="entry-place">
        <dt className="text-muted">Organization</dt>
        <dd className="min-w-0 break-words">{view.organization}</dd>
        <dt className="text-muted">Project</dt>
        <dd className="min-w-0 break-words">
          {view.project} <span className="text-muted">/ {view.environment}</span>
        </dd>
        <dt className="text-muted">Item</dt>
        <dd className="min-w-0 break-all font-mono text-[12.5px]" data-testid="entry-item">
          {view.item}
        </dd>
      </dl>
      {view.description && (
        <figure className="rounded-lg border border-dashed border-bd-strong bg-inset px-4 py-3" data-testid="entry-description">
          <figcaption className="text-xs text-muted">
            What {view.requestedBy?.name} wrote. These are not Varlatch's words, and nobody checked them:
          </figcaption>
          <blockquote className="mt-1.5 break-words text-[13px]">{view.description}</blockquote>
        </figure>
      )}
      {view.replace && (
        <Callout tone="warn" title="This replaces a value" data-testid="entry-replaces">
          Whatever uses {view.item} gets the new value from then on.
        </Callout>
      )}
      <Field label={label} htmlFor="entry-value" error={error || undefined} hint={seed ? "What an authenticator app would scan, as text." : undefined}>
        {lines ? (
          <Textarea
            {...field}
            rows={5}
            className="w-full font-mono [-webkit-text-security:disc]"
            onChange={(e) => setValue(e.target.value)}
          />
        ) : (
          <Input {...field} type="password" mono className="w-full" data-autofocus onPaste={paste} onChange={(e) => setValue(e.target.value)} />
        )}
      </Field>
      <div className={cn("flex flex-wrap items-center gap-2 text-xs text-muted", !seed && "-mt-2")}>
        {seed && readQr && (
          <>
            <input ref={file} type="file" accept="image/*" className="hidden" data-testid="entry-qr" onChange={(e) => void fromImage(e.target.files?.[0])} />
            <Button size="sm" icon={<QrCode size={13} />} onClick={() => file.current?.click()}>
              Read a QR image
            </Button>
          </>
        )}
        {!seed && !lines && (
          <button type="button" className="link" data-testid="entry-lines" onClick={() => setLines(true)}>
            The value has several lines
          </button>
        )}
        {!seed && strayEnds(value) && (
          <span className="text-warn" data-testid="entry-stray">
            It begins or ends with a space or a line break.{" "}
            <button type="button" className="link" onClick={() => setValue(value.trim())}>
              Remove it
            </button>
          </span>
        )}
      </div>
      <Button type="submit" variant="primary" size="lg" className="w-full" data-testid="entry-submit" loading={busy} disabled={value === "" || left === 0}>
        Store it in Varlatch
      </Button>
      <div className="space-y-1.5 border-t border-bd pt-4 text-xs text-muted">
        <p className="flex items-center gap-1.5" data-testid="entry-left">
          <Timer size={13} aria-hidden="true" />
          {left > 0 ? `This link ends in ${left >= 120 ? `${Math.floor(left / 60)} minutes` : `${left} seconds`}.` : "This link has ended: ask for another one."}
        </p>
        <p>{WHO[view.restrictedTo]}</p>
        <p>Enter only what is named above. This form never asks for your sign-in to Varlatch, a PIN or a payment.</p>
      </div>
    </form>
  );
}
