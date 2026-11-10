// SPDX-License-Identifier: AGPL-3.0-or-later
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { startAuthentication, type PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/browser";
import { KeyRound, Laptop, MoreHorizontal, Plus, ShieldAlert, ShieldCheck } from "lucide-react";
import { VarlatchApiError, type OwnPasskey } from "@varlatch/sdk";
import { addPasskey, useSession } from "../../lib/session";
import { formatDate } from "../../lib/time";
import { Badge, Button, Callout, Menu, SectionCard, Spinner } from "../../components/ui";
import { useConfirm, usePrompt } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { errorMessage } from "../../shell/Shell";
import { approvalOutcomeMessage } from "../security-controls/approval";

/**
 * Passkeys: recovery relies on redundant enrolled passkeys, so enrolling a
 * second one needs no CLI. The last passkey cannot be removed here; that is
 * break-glass recovery, not a button.
 *
 * Each passkey shows its provenance (ADR-0054 Decision 4). A passkey added
 * here, while signed in, starts unconfirmed: confirming it takes a trusted
 * passkey of the same person, with a PIN or biometric. Signing in works with
 * any passkey; only trusted ones will be able to approve operations once
 * an organization turns on a Security Control.
 */

/** Where a passkey's trust comes from, in words. */
export function provenanceText(p: OwnPasskey): string {
  if (p.trust !== "trusted") return "Added while signed in. Confirm it with a trusted passkey.";
  switch (p.trustedVia) {
    case "existing-at-upgrade":
      return "Trusted: it was already enrolled when Varlatch began recording where passkeys come from.";
    case "setup-grant":
      return p.setupGrantKind === "invite"
        ? "Trusted: enrolled with an invitation link."
        : p.setupGrantKind === "bootstrap"
          ? "Trusted: enrolled when this installation was set up."
          : "Trusted: enrolled with a link from whoever runs this server.";
    case "confirmed":
      return `Trusted: confirmed with another passkey${p.trustedAt ? ` on ${formatDate(p.trustedAt)}` : ""}.`;
    default:
      return "Trusted.";
  }
}

function confirmationError(err: unknown): string {
  if (err instanceof VarlatchApiError && err.code === "RATE_LIMITED") return "Too many confirmations started. Wait a few minutes and try again.";
  return errorMessage(err);
}

export function SecurityPage() {
  const { api } = useSession();
  const qc = useQueryClient();
  const prompt = usePrompt();
  const confirm = useConfirm();
  const toast = useToast();
  const passkeys = useQuery({ queryKey: ["me-passkeys"], queryFn: () => api.listMyPasskeys() });
  const invalidate = () => void qc.invalidateQueries({ queryKey: ["me-passkeys"] });
  const add = useMutation({
    mutationFn: (name: string) => addPasskey(name),
    onSuccess: () => {
      invalidate();
      toast.success("Passkey added", { description: "Confirm it with a trusted passkey so it can approve changes later." });
    },
    onError: (err) => toast.error("Could not add the passkey", { description: errorMessage(err) }),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.removeMyPasskey(id),
    onSuccess: invalidate,
    // Removing a trusted passkey can need an approval (ADR-0054 Decision 4):
    // the session's approval dialog asks for it, and says so here when it
    // was not given or could not be used.
    onError: (err) => toast.error("Could not remove the passkey", { description: approvalOutcomeMessage(err) ?? errorMessage(err) }),
  });
  const confirmKey = useMutation({
    mutationFn: async (id: string) => {
      const { publicKey } = await api.startPasskeyConfirmation(id);
      let assertion: unknown;
      try {
        assertion = await startAuthentication({ optionsJSON: publicKey as unknown as PublicKeyCredentialRequestOptionsJSON });
      } catch (err) {
        // Cancelled or timed out in the browser: nothing was sent.
        throw new Error(`The passkey prompt did not complete (${err instanceof Error ? err.name : "cancelled"}). Nothing changed.`);
      }
      return api.confirmMyPasskey(id, assertion);
    },
    onSuccess: () => {
      invalidate();
      toast.success("Passkey confirmed", { description: "It is now trusted." });
    },
    onError: (err) => toast.error("Could not confirm the passkey", { description: confirmationError(err) }),
  });
  const items = passkeys.data?.items ?? [];
  const trusted = items.filter((p) => p.trust === "trusted");
  return (
    <div className="space-y-6">
      <SectionCard
        title="Passkeys"
        description="How you sign in. Keep at least two, so losing a device never locks you out."
        data-testid="passkeys-list"
        actions={
          <Button
            variant="primary"
            icon={<Plus size={15} />}
            data-testid="add-passkey"
            loading={add.isPending}
            onClick={async () => {
              const name = await prompt({
                title: "Add a passkey",
                description: "Your browser or security key asks you to confirm next. The new passkey starts unconfirmed: confirm it afterwards with a trusted one.",
                label: "Name",
                placeholder: "e.g. laptop, YubiKey",
                confirmLabel: "Continue",
              });
              if (name) add.mutate(name);
            }}
          >
            Add passkey
          </Button>
        }
      >
        {passkeys.isLoading ? (
          <div className="px-5 py-4">
            <Spinner />
          </div>
        ) : (
          <div className="grid gap-3 p-4 sm:grid-cols-2">
            {items.map((p) => (
              <div key={p.id} data-passkey={p.id} data-trust={p.trust} className="flex items-start gap-3.5 rounded-lg border border-bd bg-raised p-4">
                <span className="flex size-10 shrink-0 items-center justify-center rounded-lg border border-bd bg-inset text-muted">
                  {p.deviceType === "singleDevice" ? <KeyRound size={18} /> : <Laptop size={18} />}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="flex items-center gap-2">
                    <span className="truncate font-medium">{p.name ?? "Unnamed passkey"}</span>
                    {p.trust === "trusted" ? (
                      <Badge tone="accent" data-testid={`passkey-trust-${p.id}`}>
                        <ShieldCheck size={11} aria-hidden="true" /> Trusted
                      </Badge>
                    ) : (
                      <Badge tone="warn" data-testid={`passkey-trust-${p.id}`}>
                        Unconfirmed
                      </Badge>
                    )}
                  </span>
                  <span className="block text-xs text-muted">
                    {p.createdAt ? `added ${formatDate(p.createdAt)}` : "added before dates were recorded"}
                    {p.backedUp ? " · synced across devices" : " · this device only"}
                  </span>
                  <span className="mt-1 block text-xs text-muted" data-testid={`passkey-provenance-${p.id}`}>
                    {provenanceText(p)}
                  </span>
                  {p.trust !== "trusted" && trusted.length > 0 && (
                    <Button
                      size="sm"
                      className="mt-2"
                      icon={<ShieldCheck size={14} />}
                      data-testid={`confirm-passkey-${p.id}`}
                      loading={confirmKey.isPending && confirmKey.variables === p.id}
                      disabled={confirmKey.isPending}
                      onClick={() => confirmKey.mutate(p.id)}
                    >
                      Confirm with another passkey
                    </Button>
                  )}
                </span>
                <Menu
                  label={`Actions for ${p.name ?? "passkey"}`}
                  items={[
                    {
                      label: "Remove…",
                      danger: true,
                      disabled: items.length < 2,
                      "data-testid": `remove-passkey-${p.id}`,
                      onSelect: async () => {
                        const ok = await confirm({
                          title: `Remove ${p.name ?? "this passkey"}?`,
                          description: "You can no longer sign in with it. Also delete it from that device's password manager.",
                          confirmLabel: "Remove passkey",
                          tone: "danger",
                        });
                        if (ok) remove.mutate(p.id);
                      },
                    },
                  ]}
                >
                  <MoreHorizontal size={16} />
                </Menu>
              </div>
            ))}
          </div>
        )}
        {items.length > 0 && trusted.length === 0 && (
          <div className="px-4 pb-4">
            <Callout tone="warn" icon={<ShieldAlert size={17} />} title="None of your passkeys is trusted" data-testid="no-trusted-passkey">
              Signing in works as before. A passkey added while signed in can only be confirmed with a trusted one, so for a trusted passkey ask whoever runs this Varlatch server for a new enrollment link: <code>varlatch admin reenroll</code>, or <code>admin recover</code> for an Installation Admin.
            </Callout>
          </div>
        )}
        {items.length === 1 && (
          <div className="px-4 pb-4">
            <Callout tone="warn" icon={<ShieldAlert size={17} />} title="Only one passkey">
              If you lose this device, only whoever runs this Varlatch server can send you a link to enroll a new one. Add a second passkey, for example a security key.
            </Callout>
          </div>
        )}
        {items.length === 0 && !passkeys.isLoading && (
          <p className="px-5 pb-4 text-[13px] text-muted">No passkeys are visible for this session.</p>
        )}
      </SectionCard>
      <p className="text-xs text-muted" data-testid="passkey-trust-explainer">
        A trusted passkey came with your account, from a link sent to you, or was confirmed with another trusted passkey. A passkey added here starts unconfirmed until you confirm it with a trusted one that asks for your PIN, fingerprint or face, so a stolen session cannot add its own key and pass it off as yours. Signing in works with any of your passkeys. Only a trusted passkey can approve a change that needs your approval, such as turning an organization's security control down or off.
      </p>
      <p className="text-xs text-muted">
        Passkeys never leave your devices. Varlatch stores only their public keys. <Badge className="ml-1">no passwords</Badge>
      </p>
    </div>
  );
}
