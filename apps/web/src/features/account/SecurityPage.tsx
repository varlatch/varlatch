// SPDX-License-Identifier: AGPL-3.0-or-later
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Laptop, MoreHorizontal, Plus, ShieldAlert } from "lucide-react";
import { addPasskey, deletePasskey, listPasskeys } from "../../lib/session";
import { formatDate } from "../../lib/time";
import { Badge, Button, Callout, Menu, SectionCard, Spinner } from "../../components/ui";
import { useConfirm, usePrompt } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { errorMessage } from "../../shell/Shell";

/**
 * Passkeys: recovery relies on redundant enrolled passkeys, so enrolling a
 * second one needs no CLI. The last passkey cannot be removed here; that is
 * break-glass recovery, not a button.
 */
export function SecurityPage() {
  const qc = useQueryClient();
  const prompt = usePrompt();
  const confirm = useConfirm();
  const toast = useToast();
  const passkeys = useQuery({ queryKey: ["me-passkeys"], queryFn: listPasskeys });
  const invalidate = () => void qc.invalidateQueries({ queryKey: ["me-passkeys"] });
  const add = useMutation({
    mutationFn: (name: string) => addPasskey(name),
    onSuccess: () => {
      invalidate();
      toast.success("Passkey added");
    },
    onError: (err) => toast.error("Could not add the passkey", { description: errorMessage(err) }),
  });
  const remove = useMutation({
    mutationFn: deletePasskey,
    onSuccess: invalidate,
    onError: (err) => toast.error("Could not remove the passkey", { description: errorMessage(err) }),
  });
  const items = passkeys.data ?? [];
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
                description: "Your browser or security key asks you to confirm next.",
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
              <div key={p.id} data-passkey={p.id} className="flex items-start gap-3.5 rounded-lg border border-bd bg-raised p-4">
                <span className="flex size-10 shrink-0 items-center justify-center rounded-lg border border-bd bg-inset text-muted">
                  {p.deviceType === "singleDevice" ? <KeyRound size={18} /> : <Laptop size={18} />}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-medium">{p.name ?? "Unnamed passkey"}</span>
                  <span className="block text-xs text-muted">
                    added {formatDate(p.createdAt)}
                    {p.backedUp ? " · synced across devices" : " · this device only"}
                  </span>
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
      <p className="text-xs text-muted">
        Passkeys never leave your devices. Varlatch stores only their public keys. <Badge className="ml-1">no passwords</Badge>
      </p>
    </div>
  );
}
