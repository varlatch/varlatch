// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Avatar, Button, Card, InfoTip, Input, Mono, Select } from "../../components/ui";
import { useSession } from "../../lib/session";
import { useIdentities } from "./shared";

/**
 * Members: every human in the organization, plus the invite flow. Enrollment
 * is passkey-only (ADR-0006): an invite is a one-time link, never an email
 * with a shared secret. Access itself comes from Grants, not membership.
 */
export function MembersTab({ org }: { org: string }) {
  const { api } = useSession();
  const identities = useIdentities(org);
  const people = identities.data?.items.filter((i) => i.kind === "human") ?? [];
  const [name, setName] = useState("");
  const [role, setRole] = useState<"admin" | "member">("member");
  const [inviteUrl, setInviteUrl] = useState<string | null>(null);
  const invite = useMutation({
    mutationFn: () => api.createInvitation(org, { name, role }),
    onSuccess: (r) => {
      setInviteUrl(`${window.location.origin}/enroll#${r.token}`);
      setName("");
    },
  });

  return (
    <div className="space-y-4">
      <p className="text-muted text-sm max-w-3xl">
        Everyone with an account in this organization. People sign in with a passkey — inviting
        someone mints a one-time enrollment link they open on their own device; no password or
        shared secret ever exists. Membership alone conveys no access: what a person can actually
        do is decided by Grants.
        <InfoTip
          className="ml-1"
          text='The org role ("admin"/"member") governs org administration only — day-to-day access to projects, environments, and secrets always comes from Grants.'
        />
      </p>
      <Card data-testid="people-section">
        <div className="flex items-center justify-between mb-3">
          <h2 className="font-medium flex items-center gap-1.5">
            People
            <InfoTip text="Human members of this organization. Inviting someone creates an enrollment link they open once to register a passkey; access itself comes from Grants." />
          </h2>
          <div className="flex gap-2 items-center">
            <Input
              data-testid="invite-name"
              placeholder="Person's name"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            <Select
              value={role}
              onChange={(v) => setRole(v as "admin" | "member")}
              aria-label="Org role for the invitee"
              options={[
                { value: "member", label: "member" },
                { value: "admin", label: "admin" },
              ]}
            />
            <Button data-testid="create-invite" disabled={!name || invite.isPending} onClick={() => invite.mutate()}>
              Create invite link
            </Button>
          </div>
        </div>
        {invite.error && <p className="text-deny text-sm mb-2">{String(invite.error)}</p>}
        {inviteUrl && (
          <div
            data-testid="invite-url"
            className="mb-3 rounded-md border border-accent/40 bg-accent-dim/30 p-3 text-sm"
          >
            <p className="mb-1">
              Hand this link to the invitee. It is shown once and expires; they enroll a passkey on
              their own device — no shared secret ever exists.
            </p>
            <Mono className="break-all text-accent">{inviteUrl}</Mono>
          </div>
        )}
        {people.length === 0 ? (
          <p className="text-muted text-sm">
            No members yet. Create an invite link above and hand it to the first person — they
            enroll a passkey and appear here.
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-muted">
                <th className="py-1.5 font-medium">Member</th>
                <th className="font-medium">
                  Org role{" "}
                  <InfoTip text="Admin can manage the organization itself (members, policy). Everything else — reading projects, using secrets — is granted explicitly on the Grants tab." />
                </th>
                <th className="text-right font-medium">Identity</th>
              </tr>
            </thead>
            <tbody>
              {people.map((i) => (
                <tr key={i.id} data-identity={i.name} className="border-t border-bd">
                  <td className="py-2">
                    <span className="flex items-center gap-2.5">
                      <Avatar name={i.name} image={i.image ?? null} size="md" />
                      <span className="min-w-0">
                        <span className="block truncate">{i.name}</span>
                        {i.email && <span className="block truncate text-xs text-muted">{i.email}</span>}
                      </span>
                    </span>
                  </td>
                  <td>
                    {i.orgRole ? (
                      <span className="inline-flex items-center rounded-full border border-bd px-2 py-0.5 text-xs">
                        {i.orgRole}
                      </span>
                    ) : (
                      <span className="text-muted">—</span>
                    )}
                    {i.disabled && <span className="ml-2 text-xs text-deny">disabled</span>}
                  </td>
                  <td className="text-right">
                    <Mono className="text-muted text-xs">{i.id}</Mono>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
