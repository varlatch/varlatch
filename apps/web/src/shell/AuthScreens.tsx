// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Fingerprint, Plus } from "lucide-react";
import { useSession } from "../lib/session";
import { Button, Spinner, StatusDot } from "../components/ui";
import { BrandMark } from "./BrandMark";
import { NewOrgDialog } from "./Shell";

/** Centered card on the dot-grid backdrop: every signed-out screen. */
export function CenteredCard({ children, testId }: { children: React.ReactNode; testId?: string }) {
  return (
    <main className="relative grid min-h-screen place-items-center overflow-hidden p-6" data-testid={testId}>
      <div className="dot-grid pointer-events-none absolute inset-0" aria-hidden="true" />
      <div className="relative w-full max-w-[420px]">{children}</div>
    </main>
  );
}

export function SignInScreen() {
  const { signInWithPasskey } = useSession();
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const meta = useQuery({
    queryKey: ["meta-public"],
    queryFn: async () => (await fetch("/v1/meta")).json() as Promise<{ serverVersion?: string }>,
    retry: false,
    staleTime: Infinity,
  });
  return (
    <CenteredCard>
      <div className="rounded-2xl border border-bd bg-raised px-8 pb-6 pt-9 text-center shadow-pop">
        <div className="flex justify-center">
          <BrandMark size={52} />
        </div>
        <h1 className="mt-5 text-[22px] font-semibold tracking-[-0.01em]">Sign in to Varlatch</h1>
        <p className="mt-1.5 inline-flex items-center gap-2 font-mono text-[13px] text-muted">
          <StatusDot tone="ok" />
          {location.host}
        </p>
        <Button
          variant="primary"
          size="lg"
          className="mt-6 w-full"
          loading={busy}
          icon={<Fingerprint size={18} />}
          onClick={() => {
            setBusy(true);
            setStatus("Waiting for your authenticator…");
            signInWithPasskey()
              .catch((err) => setStatus(`Sign-in failed: ${err instanceof Error ? err.message : String(err)}`))
              .finally(() => setBusy(false));
          }}
        >
          Continue with passkey
        </Button>
        <p id="signin-status" className="mt-3 min-h-5 text-[13px] text-muted" aria-live="polite">
          {status || "No passwords exist here. Your passkey lives on your device or security key."}
        </p>
        <div className="mt-5 border-t border-bd pt-4 text-[13px] text-muted">
          Lost your passkey? Ask an organization admin for a recovery link.
        </div>
      </div>
      {meta.data?.serverVersion && (
        <p className="mt-5 text-center font-mono text-xs text-subtle">Varlatch {meta.data.serverVersion} · self-hosted</p>
      )}
    </CenteredCard>
  );
}

export function MaintenanceScreen() {
  return (
    <CenteredCard testId="maintenance-screen">
      <div className="rounded-2xl border border-bd bg-raised px-8 py-8 shadow-pop">
        <div className="flex items-center gap-3">
          <BrandMark size={36} />
          <div>
            <h1 className="font-semibold">Varlatch is under maintenance</h1>
            <p className="mt-0.5 flex items-center gap-2 text-[13px] text-muted">
              <StatusDot tone="muted" className="animate-pulse" /> Reconnecting by itself
            </p>
          </div>
        </div>
        <p className="mt-5 text-[13px] leading-relaxed text-muted">
          A restore or an upgrade is in progress. This page continues on its own when it finishes; there is no
          need to sign in again.
        </p>
      </div>
    </CenteredCard>
  );
}

/** Banner over a signed-in app while the installation is in maintenance. */
export function MaintenanceBanner() {
  return (
    <div
      role="status"
      aria-live="polite"
      data-testid="maintenance-status"
      className="fixed left-1/2 top-3 z-[90] flex -translate-x-1/2 items-center gap-2.5 rounded-full border border-bd bg-raised px-4 py-2 text-[13px] text-muted shadow-pop"
    >
      <StatusDot tone="muted" className="animate-pulse" />
      Maintenance in progress · requests resume automatically
    </div>
  );
}

/** Signed in, but no organization exists or is visible yet. */
export function WelcomeScreen() {
  const { identityId } = useSession();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  return (
    <CenteredCard>
      <div className="rounded-2xl border border-bd bg-raised px-8 py-9 text-center shadow-pop">
        <div className="flex justify-center">
          <BrandMark size={48} />
        </div>
        <h1 className="mt-5 text-[22px] font-semibold">Welcome to Varlatch</h1>
        <p className="mt-1.5 text-[13px] text-muted" data-testid="whoami" title={`Signed in as ${identityId ?? ""}`}>
          You are signed in. Create your first organization to start adding projects.
        </p>
        <Button variant="primary" size="lg" className="mt-6 w-full" icon={<Plus size={16} />} onClick={() => setCreating(true)}>
          Create an organization
        </Button>
      </div>
      <NewOrgDialog
        open={creating}
        onClose={() => setCreating(false)}
        onCreated={async (slug) => {
          setCreating(false);
          await qc.invalidateQueries({ queryKey: ["orgs"] });
          navigate(`/o/${slug}/projects`);
        }}
      />
    </CenteredCard>
  );
}

export function FullPageLoading() {
  return (
    <div className="grid min-h-[50vh] place-items-center">
      <Spinner size={18} />
    </div>
  );
}
