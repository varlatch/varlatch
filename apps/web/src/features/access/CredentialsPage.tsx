// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMeRealtime } from "../../lib/realtime";
import { addPasskey, deletePasskey, listPasskeys, useSession } from "../../lib/session";
import { Button, Card, Mono } from "../../components/ui";

/**
 * Passkeys section (ADR-0006): recovery relies on redundant enrolled
 * passkeys, so enrolling a second one must not require a CLI grant. The
 * last passkey cannot be removed from here — that path is break-glass
 * recovery (recovery codes / admin re-enrollment), not a UI button.
 */
function PasskeysSection() {
  const qc = useQueryClient();
  const passkeys = useQuery({ queryKey: ["me-passkeys"], queryFn: listPasskeys });
  const invalidate = () => void qc.invalidateQueries({ queryKey: ["me-passkeys"] });
  const add = useMutation({
    mutationFn: () => {
      const name = window.prompt("Name for the new passkey (e.g. “laptop”, “yubikey”):");
      if (!name) return Promise.resolve();
      return addPasskey(name);
    },
    onSuccess: invalidate,
  });
  const remove = useMutation({ mutationFn: deletePasskey, onSuccess: invalidate });
  const items = passkeys.data ?? [];

  return (
    <>
      <div className="flex items-center justify-between">
        <div>
          <h2 className="font-semibold">Passkeys</h2>
          <p className="text-muted text-sm">
            How you sign in. Keep at least two enrolled (e.g. a device and a security key) so
            losing one never locks you out.
          </p>
        </div>
        <Button data-testid="add-passkey" onClick={() => add.mutate()} disabled={add.isPending}>
          Add passkey
        </Button>
      </div>
      <Card data-testid="passkeys-list">
        {items.length === 0 && (
          <p className="text-muted text-sm">
            {passkeys.isLoading ? "Loading…" : "No passkeys visible for this session."}
          </p>
        )}
        {items.map((p) => (
          <div
            key={p.id}
            data-passkey={p.id}
            className="flex items-center gap-3 border-t border-bd first:border-t-0 py-2 text-sm"
          >
            <div className="flex-1">
              <p>{p.name ?? "Unnamed passkey"}</p>
              <p className="text-muted text-xs">
                <Mono>{p.id}</Mono> · {p.deviceType}
                {p.backedUp && " · synced"} · enrolled {new Date(p.createdAt).toLocaleString()}
              </p>
            </div>
            <Button
              variant="danger"
              data-testid={`remove-passkey-${p.id}`}
              disabled={items.length < 2 || remove.isPending}
              title={items.length < 2 ? "You cannot remove your only passkey" : undefined}
              onClick={() => {
                if (!window.confirm(`Remove passkey “${p.name ?? p.id}”? Also delete it from that device's credential manager.`)) return;
                remove.mutate(p.id);
              }}
            >
              Remove
            </Button>
          </div>
        ))}
      </Card>
      {(add.error ?? remove.error ?? passkeys.error) && (
        <p className="text-deny text-sm">{String(add.error ?? remove.error ?? passkeys.error)}</p>
      )}
    </>
  );
}

/**
 * My Credentials (ADR-0007): every bearer the signed-in identity holds,
 * individually revocable. Revoking the current one signs this session out.
 */
export function CredentialsPage() {
  const { api } = useSession();
  const qc = useQueryClient();
  useMeRealtime(["credential"], [["me-credentials"]]);
  const creds = useQuery({ queryKey: ["me-credentials"], queryFn: () => api.listMyCredentials() });
  const revoke = useMutation({
    mutationFn: (id: string) => api.revokeMyCredential(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["me-credentials"] }),
  });
  const items = creds.data?.items ?? [];

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">My credentials</h1>
      <p className="text-muted text-sm">
        Every API credential issued to your identity — CLI logins, browser sessions, and anything
        else. Revocation is immediate and per-credential; your passkeys are separate and stay valid.
      </p>
      <Card data-testid="credentials-list">
        {items.length === 0 && <p className="text-muted text-sm">No credentials.</p>}
        {items.map((c) => (
          <div key={c.id} data-credential={c.id} className="flex items-center gap-3 border-t border-bd first:border-t-0 py-2 text-sm">
            <div className="flex-1">
              <p>
                {c.name}
                {c.current && (
                  <span className="ml-2 rounded-full border border-accent/50 px-2 py-0.5 text-xs text-accent">
                    this session
                  </span>
                )}
                {c.revokedAt && <span className="ml-2 text-deny text-xs">revoked</span>}
              </p>
              <p className="text-muted text-xs">
                <Mono>{c.id}</Mono> · {c.kind} · created {new Date(c.createdAt).toLocaleString()}
                {c.expiresAt && ` · expires ${new Date(c.expiresAt).toLocaleString()}`}
              </p>
            </div>
            {!c.revokedAt && (
              <Button
                variant="danger"
                data-testid={`revoke-credential-${c.id}`}
                onClick={() => {
                  if (c.current && !window.confirm("Revoke this session's credential? You will be signed out.")) return;
                  revoke.mutate(c.id);
                }}
              >
                Revoke
              </Button>
            )}
          </div>
        ))}
      </Card>
      {revoke.error && <p className="text-deny text-sm">{String(revoke.error)}</p>}
      <PasskeysSection />
    </div>
  );
}
