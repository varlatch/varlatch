// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState, type ReactNode } from "react";
import { BookOpen, ChevronDown, ChevronRight } from "lucide-react";
import { Card, Mono, cn } from "../../components/ui";

/**
 * Collapsible plain-language walkthrough of the access model:
 * identity → (roles / groups / teams) → grants → evaluation, consistent with
 * ADR-0015 (authorization), ADR-0028 (roles/groups/teams), ADR-0029 (updates),
 * ADR-0022 (broker capabilities), and ADR-0014 (tailnet requirements).
 */
export function HowAccessWorks() {
  const [open, setOpen] = useState(false);
  return (
    <Card data-testid="how-access-works" className="p-0 overflow-hidden">
      <button
        type="button"
        data-testid="how-access-works-toggle"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className="flex w-full cursor-pointer items-center gap-2 px-4 py-3 text-left text-sm font-medium hover:bg-inset/40"
      >
        <BookOpen size={15} className="text-accent" aria-hidden="true" />
        How access works
        <span className="font-normal text-muted">— the model in five steps</span>
        <span className="flex-1" />
        {open ? (
          <ChevronDown size={15} className="text-muted" aria-hidden="true" />
        ) : (
          <ChevronRight size={15} className="text-muted" aria-hidden="true" />
        )}
      </button>
      {open && (
        <div className="border-t border-bd px-4 py-4 text-sm space-y-4">
          <Step n={1} title="Everything starts default-deny">
            Nobody — human or machine — can do anything until a grant says so. There are no
            implicit permissions to hunt for: if it isn't granted, it's denied. That makes the
            Grants tab the complete, readable answer to "who can do what?".
          </Step>
          <Step n={2} title="Identities are who; kinds say how they sign in">
            An <b>identity</b> is anything that can act: a person (signs in with a passkey; no
            passwords exist) or a machine (a CI job, server, broker, or AI agent that presents a
            token or federates via OIDC). Being an identity by itself conveys zero access — it
            only answers "who is asking?".
          </Step>
          <Step n={3} title="Grants are the only source of permission">
            A <b>grant</b> is one sentence: <i>subject</i> (an identity, or a group/team of
            identities) may perform <i>these actions</i> (picked directly, via a preset shortcut,
            or via a reusable role) within <i>this scope</i> (whole organization, one project, a
            tier, specific environments, or everything a team owns). Grants are additive — each
            one only ever adds ability, and revoking one takes effect on the very next request.
          </Step>
          <Step n={4} title="Roles, groups, and teams keep grants tidy">
            These three exist so you write fewer grants, not to add power of their own.
            A <b>role</b> names a reusable bundle of actions (edit the role, every grant citing
            it follows). A <b>group</b> collects identities so one grant covers all members.
            A <b>team</b> is a group that also owns projects, so one grant can say "the backend
            team, on the backend team's projects". Membership changes never require touching
            grants.
          </Step>
          <Step n={5} title="Every request is evaluated fresh">
            On each request the server expands the caller's groups/teams and roles into the full
            set of applicable grants and checks the requested action against them. Two mechanisms
            can then only <em>narrow</em> the outcome: <b>requirements</b> (e.g. "production
            secrets only from a verified tailnet device") subtract access based on where the
            request comes from, and <b>broker capabilities</b> are short-lived run receipts for
            AI agents — the agent's own <Mono>secret.use</Mono> grant is still re-checked on
            every exercise. Every decision, allow or deny, lands in the audit log.
          </Step>
          <p className="text-muted text-xs">
            Rule of thumb: <b>Members / Machines</b> answer "who exists", <b>Roles &amp; teams</b>
            {" "}answer "how do I avoid repeating myself", <b>Grants</b> answer "who may do what,
            where", and <b>Advanced</b> narrows or observes — it never grants.
          </p>
        </div>
      )}
    </Card>
  );
}

function Step({ n, title, children }: { n: number; title: string; children: ReactNode }) {
  return (
    <div className="flex gap-3">
      <span
        aria-hidden="true"
        className={cn(
          "mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full",
          "border border-accent/50 text-accent text-[11px] font-semibold",
        )}
      >
        {n}
      </span>
      <div>
        <p className="font-medium mb-0.5">{title}</p>
        <p className="text-muted">{children}</p>
      </div>
    </div>
  );
}
