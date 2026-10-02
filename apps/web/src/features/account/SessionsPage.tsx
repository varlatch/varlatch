// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronRight, KeyRound, LogOut, Monitor, Terminal } from "lucide-react";
import type { OwnCredential } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { timeAgo, timeUntil, useNow } from "../../lib/time";
import { Badge, Button, SectionCard, Spinner, cn } from "../../components/ui";
import { useConfirm } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { errorMessage } from "../../shell/Shell";

/**
 * Every credential issued to the signed-in identity: browser sessions, CLI
 * logins and anything else. Each dashboard page load exchanges a fresh
 * short-lived browser credential (the bearer lives in memory only), so other
 * browser sessions are folded into one group with a bulk revoke.
 */
export function SessionsPage() {
  const { api } = useSession();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const toast = useToast();
  const now = useNow();
  const creds = useQuery({ queryKey: ["me-credentials"], queryFn: () => api.listMyCredentials() });
  const [showBrowsers, setShowBrowsers] = useState(false);
  const [showEnded, setShowEnded] = useState(false);
  const invalidate = () => void qc.invalidateQueries({ queryKey: ["me-credentials"] });
  const revoke = useMutation({
    mutationFn: async (ids: string[]) => {
      for (const id of ids) await api.revokeMyCredential(id);
    },
    onSuccess: invalidate,
    onError: (err) => toast.error("Could not revoke", { description: errorMessage(err) }),
  });

  const items = (creds.data?.items ?? []) as OwnCredential[];
  const current = items.find((c) => c.current);
  const others = items.filter((c) => !c.current);
  const live = (c: OwnCredential) => !c.revokedAt && (!c.expiresAt || new Date(c.expiresAt).getTime() > now);
  const browsers = others.filter((c) => c.kind === "browser" && live(c));
  const endedBrowsers = others.filter((c) => c.kind === "browser" && !live(c));
  const rest = others
    .filter((c) => c.kind !== "browser")
    .sort((a, b) => Number(!live(a)) - Number(!live(b)) || b.createdAt.localeCompare(a.createdAt));
  const revocableOthers = others.filter(live);

  const revokeOne = async (c: OwnCredential) => {
    if (c.current) {
      const ok = await confirm({
        title: "Sign out this browser?",
        description: "This revokes the credential this page is using. You will need your passkey to sign in again.",
        confirmLabel: "Sign out",
        tone: "danger",
      });
      if (!ok) return;
    }
    revoke.mutate([c.id]);
  };

  return (
    <SectionCard
      title="Active sessions"
      description="Revocation is immediate and per credential. Your passkeys are separate and stay valid."
      data-testid="credentials-list"
      actions={
        revocableOthers.length > 0 && (
          <Button
            variant="danger"
            icon={<LogOut size={14} />}
            data-testid="revoke-others"
            onClick={async () => {
              const ok = await confirm({
                title: "Sign out everywhere else?",
                description: `Revokes ${revocableOthers.length} other credential${revocableOthers.length === 1 ? "" : "s"}: browser sessions, CLI logins and tokens issued to you. This browser stays signed in.`,
                confirmLabel: "Sign out everywhere else",
                tone: "danger",
              });
              if (ok) revoke.mutate(revocableOthers.map((c) => c.id));
            }}
          >
            Sign out everywhere else
          </Button>
        )
      }
    >
      {creds.isLoading ? (
        <div className="px-5 py-4">
          <Spinner />
        </div>
      ) : items.length === 0 ? (
        <p className="px-5 py-4 text-[13px] text-muted">No credentials.</p>
      ) : (
        <ul>
          {current && <CredentialRow c={current} now={now} onRevoke={() => void revokeOne(current)} />}
          {browsers.length > 0 && (
            <li className="border-b border-bd">
              <div className="flex items-center gap-3 px-5 py-3">
                <button
                  type="button"
                  aria-expanded={showBrowsers}
                  onClick={() => setShowBrowsers((v) => !v)}
                  className="flex min-w-0 flex-1 cursor-pointer items-center gap-3 text-left"
                >
                  <ChevronRight size={15} className={cn("text-muted transition-transform", showBrowsers && "rotate-90")} />
                  <CredentialIcon kind="browser" />
                  <span>
                    <span className="block font-medium">Other browser sessions · {browsers.length}</span>
                    <span className="block text-xs text-muted">Short-lived; each dashboard tab or reload gets its own and they expire by themselves</span>
                  </span>
                </button>
                <Button size="sm" variant="secondary" onClick={() => revoke.mutate(browsers.map((c) => c.id))}>
                  Revoke all
                </Button>
              </div>
              {showBrowsers && (
                <ul className="border-t border-bd bg-hover/30">
                  {browsers.map((c) => (
                    <CredentialRow key={c.id} c={c} now={now} nested onRevoke={() => void revokeOne(c)} />
                  ))}
                </ul>
              )}
            </li>
          )}
          {rest.map((c) => (
            <CredentialRow key={c.id} c={c} now={now} onRevoke={() => void revokeOne(c)} />
          ))}
          {endedBrowsers.length > 0 && (
            <li>
              <button
                type="button"
                aria-expanded={showEnded}
                onClick={() => setShowEnded((v) => !v)}
                className="flex w-full cursor-pointer items-center gap-3 px-5 py-3 text-left text-[13px] text-muted hover:text-fg"
              >
                <ChevronRight size={15} className={cn("transition-transform", showEnded && "rotate-90")} />
                Ended browser sessions · {endedBrowsers.length}
                <span className="text-xs">expired or revoked; kept for your records</span>
              </button>
              {showEnded && (
                <ul className="border-t border-bd bg-hover/30">
                  {endedBrowsers.map((c) => (
                    <CredentialRow key={c.id} c={c} now={now} nested onRevoke={() => undefined} />
                  ))}
                </ul>
              )}
            </li>
          )}
        </ul>
      )}
    </SectionCard>
  );
}

function CredentialIcon({ kind }: { kind: string }) {
  const Icon = kind === "browser" ? Monitor : kind === "cli" ? Terminal : KeyRound;
  return (
    <span className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-bd bg-inset text-muted">
      <Icon size={16} />
    </span>
  );
}

function label(c: OwnCredential): string {
  const client = (c as OwnCredential & { client?: string | null }).client;
  if (c.kind === "browser") return client ? `Browser · ${client}` : "Browser session";
  if (c.kind === "cli") return client ? `CLI · ${client}` : (c.name ?? "CLI login");
  return c.name ?? c.kind;
}

function CredentialRow({ c, now, nested, onRevoke }: { c: OwnCredential; now: number; nested?: boolean; onRevoke: () => void }) {
  const revoked = Boolean(c.revokedAt);
  const expired = !revoked && c.expiresAt && new Date(c.expiresAt).getTime() <= now;
  return (
    <li data-credential={c.id} className={cn("flex items-center gap-3 border-b border-bd px-5 py-3 last:border-b-0", nested && "pl-14", (revoked || expired) && "opacity-60")}>
      {!nested && <CredentialIcon kind={c.kind} />}
      <span className="min-w-0 flex-1">
        <span className="flex flex-wrap items-center gap-2">
          <span className={cn("font-medium", revoked && "line-through")}>{c.current ? `This browser${(c as { client?: string | null }).client ? ` · ${(c as { client?: string | null }).client}` : ""}` : label(c)}</span>
          {c.current && <Badge tone="accent">this session</Badge>}
          {revoked && <Badge tone="danger">revoked</Badge>}
          {expired && <Badge>expired</Badge>}
        </span>
        <span className="block text-xs text-muted">
          {c.kind} · issued {timeAgo(c.createdAt, now)}
          {c.useCount > 0 && ` · used ${c.useCount} time${c.useCount === 1 ? "" : "s"}`}
          {c.maxUses ? ` of ${c.maxUses}` : ""}
          {c.expiresAt && !revoked && !expired && ` · expires ${timeUntil(c.expiresAt, now)}`}
          {c.current && " · renews automatically"}
        </span>
      </span>
      {!revoked && !expired && (
        <Button size="sm" variant={c.current ? "danger" : "secondary"} data-testid={`revoke-credential-${c.id}`} onClick={onRevoke}>
          {c.current ? "Sign out" : "Revoke"}
        </Button>
      )}
    </li>
  );
}

