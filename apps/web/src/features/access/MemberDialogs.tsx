// SPDX-License-Identifier: AGPL-3.0-or-later
import { useNavigate } from "react-router-dom";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import type { Grant, MemberReview } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { dropLostOrganizations } from "../../lib/membership";
import { Badge, Button, Callout } from "../../components/ui";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { errorMessage } from "../../shell/Shell";
import { permissionPhrase, scopeParts, type Names } from "./model";

/**
 * Removing a person, leaving, and demotion (ADR-0052 Decisions 2 to 4).
 * Removal changes nothing that belongs to the organization: the dialog says
 * what the person set up that may keep working without them.
 */

export interface MemberRef {
  id: string;
  name: string;
}

const CHANGE_WORDS: Record<string, string> = {
  created: "created",
  repointed: "re-pointed",
  destination_changed: "destination changed",
  credential_replaced: "credential replaced",
};

/** The number of things a review lists. */
export function reviewCount(review: MemberReview): number {
  return (
    review.syncTargets.length +
    review.connections.length +
    review.webhooks.length +
    review.oidcBindings.length +
    review.credentials.length +
    review.personalEnvironments.length
  );
}

/** What the person set up that may keep working without them, by kind, with each thing's state. */
export function ReviewList({ review, names }: { review: MemberReview; names: Names }) {
  const where = (projectId: string, environmentId: string) => {
    const project = names.project(projectId)?.slug ?? "a project";
    const env = names.environment(environmentId)?.name ?? "an environment";
    return `${project} / ${env}`;
  };
  const changes = (c: string[]) => c.map((x) => CHANGE_WORDS[x] ?? x).join(", ");
  const sections: { title: string; hint?: string; items: { key: string; label: string; detail: string; state?: string; muted?: boolean }[] }[] = [
    {
      title: "Integrations",
      items: review.syncTargets.map((t) => ({
        key: t.id,
        label: `${t.platform} for ${where(t.projectId, t.environmentId)}`,
        detail: changes(t.changes),
        state: t.state,
        muted: t.state === "revoked",
      })),
    },
    {
      title: "Connections",
      items: review.connections.map((c) => ({
        key: c.id,
        label: `${c.name} (${c.platform}, ${c.credentialKind === "github-app" ? "GitHub App" : "token"})`,
        detail: changes(c.changes),
        ...(c.revoked ? { state: "revoked", muted: true } : {}),
      })),
    },
    {
      title: "Webhooks",
      hint: "Each signing secret was shown to its creator once.",
      items: review.webhooks.map((w) => ({
        key: w.id,
        label: w.host || "a webhook",
        detail: "",
        ...(w.revoked ? { state: "revoked", muted: true } : {}),
      })),
    },
    {
      title: "OIDC bindings",
      items: review.oidcBindings.map((b) => ({
        key: b.id,
        label: `${b.identityName} from ${b.issuer}`,
        detail: "",
        ...(b.revoked ? { state: "revoked", muted: true } : {}),
      })),
    },
    {
      title: "Machine credentials whose token they were shown",
      items: review.credentials.map((c) => ({
        key: c.id,
        label: `${c.name ?? "A credential"} for ${c.identityName}`,
        detail: "",
        state: c.state,
        muted: c.state !== "valid",
      })),
    },
    {
      title: "Personal environments",
      items: review.personalEnvironments.map((e) => ({
        key: e.id,
        label: `${names.project(e.projectId)?.slug ?? "a project"} / ${e.name}`,
        detail: "",
      })),
    },
  ].filter((s) => s.items.length > 0);
  return (
    <div className="space-y-3" data-testid="member-review">
      {sections.map((s) => (
        <div key={s.title}>
          <p className="text-[13px] font-medium">{s.title}</p>
          {s.hint && <p className="text-xs text-muted">{s.hint}</p>}
          <ul className="mt-1 space-y-1">
            {s.items.map((item) => (
              <li key={item.key} data-review-item={item.key} className="flex flex-wrap items-center gap-2 text-[13px]">
                <span className={item.muted ? "text-muted" : undefined}>{item.label}</span>
                {item.detail && <span className="text-xs text-muted">{item.detail}</span>}
                {item.state && (
                  <Badge tone={item.muted ? "mono" : item.state === "valid" || item.state === "active" ? "warn" : "mono"} className="font-mono">
                    {item.state}
                  </Badge>
                )}
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}

/**
 * Remove someone, or leave (`self`). The review list is read before the
 * decision and returned again by the removal itself.
 */
export function RemoveMemberDialog({
  org,
  orgName,
  person,
  self,
  names,
  onClose,
}: {
  org: string;
  orgName: string;
  person: MemberRef | null;
  self: boolean;
  names: Names;
  onClose: () => void;
}) {
  const { api } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const target = self ? "me" : (person?.id ?? "");
  const review = useQuery({
    queryKey: ["member-review", org, target],
    queryFn: () => api.reviewMember(org, target),
    enabled: person !== null,
    staleTime: 0,
  });
  const remove = useMutation({
    mutationFn: () => api.removeMember(org, target),
    onSuccess: async () => {
      onClose();
      if (self) {
        // This organization's data goes now, before the signal arrives.
        await dropLostOrganizations(qc, () => api.listOrganizations(), org);
        navigate("/", { replace: true });
        toast.success(`You left ${orgName}`);
        return;
      }
      toast.success(`Removed ${person?.name ?? "them"} from ${orgName}`);
      for (const key of ["identities", "grants", "groups", "teams", "invitations"]) {
        void qc.invalidateQueries({ queryKey: [key, org] });
      }
    },
  });
  const name = person?.name ?? "";
  const listed = review.data ? reviewCount(review.data) : 0;
  return (
    <Dialog
      open={person !== null}
      onClose={() => {
        remove.reset();
        onClose();
      }}
      size="lg"
      tone="danger"
      data-testid="remove-member-dialog"
      title={self ? `Leave ${orgName}?` : `Remove ${name} from ${orgName}?`}
      description={
        self
          ? "You lose access to this organization from your next request. Your sign-in and your other organizations are not affected. To come back, an admin has to invite you again."
          : "Their access ends from their next request: the membership ends, the Grants given to them directly are revoked, they leave every group and team, and the invitations they issued that are still pending are revoked. Their sign-in and their other organizations are not affected."
      }
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="danger"
            data-testid="confirm-remove-member"
            loading={remove.isPending}
            disabled={review.isLoading}
            onClick={() => remove.mutate()}
          >
            {self ? "Leave organization" : `Remove ${name}`}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        {review.isLoading && <p className="text-[13px] text-muted">Looking up what {self ? "you" : "they"} set up here…</p>}
        {review.error && <p className="text-[13px] text-deny">Could not list what to review: {errorMessage(review.error)}</p>}
        {review.data && listed === 0 && (
          <p className="text-[13px] text-muted" data-testid="member-review-empty">
            Nothing {self ? "you" : "they"} set up here needs review.
          </p>
        )}
        {review.data && listed > 0 && (
          <>
            <Callout tone="warn" title={`${listed} thing${listed === 1 ? "" : "s"} to review`}>
              {self ? "You" : "They"} set these up or changed them. They belong to the organization and keep working; removal
              changes none of them. Removal also does not reach a credential, token or platform account held outside Varlatch.
            </Callout>
            <ReviewList review={review.data} names={names} />
          </>
        )}
        {remove.error && (
          <p className="text-[13px] text-deny" data-testid="remove-member-error">
            {errorMessage(remove.error)}
          </p>
        )}
      </div>
    </Dialog>
  );
}

/**
 * Admin to member. Only the built-in admin role goes: Grants given directly
 * or through groups and teams stay, since access adds up, so the dialog
 * lists them for the admin to revoke what should go.
 */
export function DemoteDialog({
  org,
  person,
  self,
  grants,
  names,
  nameOf,
  roleName,
  onClose,
}: {
  org: string;
  person: MemberRef | null;
  self: boolean;
  grants: Grant[];
  names: Names;
  nameOf: (id: string | null | undefined) => string;
  roleName: (id: string | null | undefined) => string | null;
  onClose: () => void;
}) {
  const { api } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  // Grants to groups and teams count when the person is in them.
  const groupIds = [...new Set(grants.map((g) => g.subjectGroupId).filter((id): id is string => Boolean(id)))];
  const memberships = useQueries({
    queries: groupIds.map((id) => ({
      queryKey: ["group-members", org, id],
      queryFn: () => api.listGroupMembers(org, id),
      enabled: person !== null,
    })),
  });
  const inGroups = new Set(groupIds.filter((_, i) => memberships[i]?.data?.items.some((m) => m.identityId === person?.id)));
  const staying = grants.filter((g) => g.subjectIdentityId === person?.id || (g.subjectGroupId && inGroups.has(g.subjectGroupId)));
  const demote = useMutation({
    mutationFn: () => api.changeMemberRole(org, person?.id ?? "", "member"),
    onSuccess: () => {
      onClose();
      toast.success(`${self ? "You are" : `${person?.name ?? "They"} is`} now a member`);
      void qc.invalidateQueries({ queryKey: ["identities", org] });
    },
  });
  const loading = memberships.some((m) => m.isLoading);
  return (
    <Dialog
      open={person !== null}
      onClose={() => {
        demote.reset();
        onClose();
      }}
      size="md"
      data-testid="demote-member-dialog"
      title={self ? "Make yourself a member?" : `Make ${person?.name ?? ""} a member?`}
      description={`${self ? "You lose" : "They lose"} the admin role: everything that only the admin role allowed. Grants given directly or through groups and teams stay, because access adds up.`}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" data-testid="confirm-demote" loading={demote.isPending} onClick={() => demote.mutate()}>
            Make member
          </Button>
        </>
      }
    >
      <div className="space-y-2">
        {loading && <p className="text-[13px] text-muted">Looking up their Grants…</p>}
        {!loading && staying.length === 0 && (
          <p className="text-[13px] text-muted" data-testid="demote-no-grants">
            No other Grants: after this, {self ? "you have" : "they have"} the member defaults only.
          </p>
        )}
        {!loading && staying.length > 0 && (
          <>
            <p className="text-[13px]">Still granted after this change (revoke what should go on the Grants tab):</p>
            <ul className="space-y-1" data-testid="demote-staying">
              {staying.map((g) => (
                <li key={g.id} data-grant={g.id} className="text-[13px]">
                  {permissionPhrase(g.actions, roleName(g.roleId))}
                  <span className="text-muted"> on </span>
                  {scopeParts(g.scope, names).map((p) => p.label).join(" · ")}
                  {g.subjectGroupId && <span className="text-muted"> through {nameOf(g.subjectGroupId)}</span>}
                </li>
              ))}
            </ul>
          </>
        )}
        {demote.error && (
          <p className="text-[13px] text-deny" data-testid="demote-error">
            {errorMessage(demote.error)}
          </p>
        )}
      </div>
    </Dialog>
  );
}
