// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link2, X } from "lucide-react";
import type { EntryLink } from "@varlatch/protocol";
import { CopyButton } from "../../components/CodeBlock";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Button, Callout, Field, Input, Select, Switch } from "../../components/ui";
import { useSession } from "../../lib/session";
import { timeUntil, useNow } from "../../lib/time";
import { errorMessage } from "../../shell/Shell";

const FOR: Record<EntryLink["restrictedTo"], string> = {
  anyone: "anyone who has it",
  member: "a member",
  identity: "one person",
};

const TTL = [
  { value: "300", label: "5 minutes" },
  { value: "900", label: "15 minutes" },
  { value: "3600", label: "1 hour" },
];

/** The entry links of an item (ADR-0063): who was asked for its value, and asking somebody. */
export function EntryLinksPanel({ org, project, env, item, has, seed }: { org: string; project: string; env: string; item: string; has: boolean; seed: boolean }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const now = useNow(15_000);
  const [asking, setAsking] = useState(false);
  const queryKey = ["entry-links", org, project, env];
  const links = useQuery({ queryKey, queryFn: () => api.listEntryLinks(org, project, env), retry: false, refetchInterval: 15_000 });
  const pending = (links.data?.items ?? []).filter((l) => l.item === item && l.status === "pending");
  const cancel = useMutation({
    mutationFn: (id: string) => api.cancelEntryLink(org, project, env, id),
    onSuccess: () => qc.invalidateQueries({ queryKey }),
    onError: (err) => toast.error("Could not cancel the link", { description: errorMessage(err) }),
  });
  return (
    <div className="space-y-3" data-testid="entry-links">
      <div className="flex items-center justify-between gap-3">
        <p className="text-[13px] text-muted">A link somebody enters this value with, once. They see nothing else, and you do not see the value.</p>
        <Button size="sm" icon={<Link2 size={13} />} data-testid="entry-ask" onClick={() => setAsking(true)}>
          Ask somebody…
        </Button>
      </div>
      {pending.map((l) => (
        <div key={l.id} className="flex items-center gap-3 rounded-lg border border-bd bg-inset px-3 py-2 text-[13px]" data-testid={`entry-link-${l.id}`}>
          <span className="min-w-0 flex-1">
            Waiting for {FOR[l.restrictedTo]}
            <span className="block text-xs text-muted">ends {timeUntil(l.expiresAt, now)}</span>
          </span>
          <Button size="sm" variant="ghost" icon={<X size={13} />} loading={cancel.isPending && cancel.variables === l.id} onClick={() => cancel.mutate(l.id)}>
            Cancel link
          </Button>
        </div>
      ))}
      <EntryLinkDialog
        open={asking}
        org={org}
        project={project}
        env={env}
        item={item}
        has={has}
        seed={seed}
        onClose={() => setAsking(false)}
        onMade={() => void qc.invalidateQueries({ queryKey })}
      />
    </div>
  );
}

export function EntryLinkDialog({
  open,
  org,
  project,
  env,
  item,
  has,
  seed,
  onClose,
  onMade,
}: {
  open: boolean;
  org: string;
  project: string;
  env: string;
  item: string;
  /** The item has a value, which the link replaces. */
  has: boolean;
  /** It is the seed of one-time codes. */
  seed: boolean;
  onClose: () => void;
  onMade: () => void;
}) {
  const { api } = useSession();
  const [restrictedTo, setRestrictedTo] = useState<EntryLink["restrictedTo"]>("member");
  const [person, setPerson] = useState("");
  const [description, setDescription] = useState("");
  const [ttl, setTtl] = useState("900");
  const [otp, setOtp] = useState(seed);
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const identities = useQuery({ queryKey: ["identities", org], queryFn: () => api.listIdentities(org), enabled: open && restrictedTo === "identity", retry: false });
  useEffect(() => {
    // The address is shown once: nothing keeps it after this dialog.
    setUrl("");
    setError("");
    setDescription("");
    setPerson("");
    setRestrictedTo("member");
    setOtp(seed);
  }, [open, item, seed]);

  const people = (identities.data?.items ?? []).filter((i) => i.kind === "human" && i.orgRole);
  const ready = !busy && (restrictedTo !== "identity" || person !== "");
  const make = async () => {
    if (!ready) return;
    setBusy(true);
    setError("");
    try {
      const made = await api.createEntryLink(org, project, env, {
        item,
        restrictedTo,
        ttlSeconds: Number(ttl),
        ...(restrictedTo === "identity" ? { identityId: person } : {}),
        ...(description.trim() ? { description: description.trim() } : {}),
        ...(has ? { replace: true } : {}),
        ...(otp ? { accepts: "otpauth" as const } : {}),
      });
      setUrl(made.url);
      onMade();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={() => !busy && onClose()}
      size="md"
      data-testid="entry-dialog"
      title={
        <>
          Ask for <span className="font-mono">{item}</span>
        </>
      }
      description={
        <span className="font-mono text-[12.5px]">
          {project} / {env}
        </span>
      }
      footer={
        url ? (
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        ) : (
          <>
            <Button variant="secondary" onClick={onClose} disabled={busy}>
              Cancel
            </Button>
            <Button variant="primary" data-testid="entry-make" disabled={!ready} loading={busy} onClick={() => void make()}>
              Make the link
            </Button>
          </>
        )
      }
    >
      {url ? (
        <div className="space-y-3">
          <p className="text-[13px] text-muted">
            Send it to whoever has the value. It is shown here once, and works once. Signing out does not end it; revoking this browser's sessions from another one does.
          </p>
          <div className="flex items-stretch gap-2">
            <code className="min-w-0 flex-1 break-all rounded-lg border border-bd bg-inset px-3 py-2 text-[12.5px]" data-testid="entry-url">
              {url}
            </code>
            <CopyButton value={url}>Copy</CopyButton>
          </div>
        </div>
      ) : (
        <form
          className="space-y-5"
          onSubmit={(e) => {
            e.preventDefault();
            void make();
          }}
        >
          {has && (
            <Callout tone="warn" title="It has a value">
              Whoever enters one replaces it.
            </Callout>
          )}
          <Field label="Who may enter it" htmlFor="entry-for">
            <Select
              id="entry-for"
              data-testid="entry-for"
              value={restrictedTo}
              onChange={(v) => setRestrictedTo(v as EntryLink["restrictedTo"])}
              options={[
                { value: "member", label: "A member, signed in" },
                { value: "identity", label: "One person, signed in" },
                { value: "anyone", label: "Anyone who has the link" },
              ]}
            />
          </Field>
          {restrictedTo === "anyone" && (
            <Callout tone="warn" title="Nobody is asked who they are" data-testid="entry-open-warning">
              Whoever gets the link first can enter a value of theirs, and the audit log cannot say who it was. Send it where only the right person reads it.
            </Callout>
          )}
          {restrictedTo === "identity" && (
            <Field label="Person" htmlFor="entry-person">
              <Select id="entry-person" data-testid="entry-person" value={person} onChange={setPerson} placeholder="Choose a member" options={people.map((p) => ({ value: p.id, label: p.name }))} />
            </Field>
          )}
          <Field label="A few words for them" htmlFor="entry-words" hint="Optional, plain text, shown as yours. Links and addresses are refused.">
            <Input id="entry-words" data-testid="entry-words" maxLength={280} value={description} onChange={(e) => setDescription(e.target.value)} />
          </Field>
          <Field label="It ends after" htmlFor="entry-ttl">
            <Select id="entry-ttl" data-testid="entry-ttl" value={ttl} onChange={setTtl} options={TTL} />
          </Field>
          {!has && (
            <label className="flex items-center justify-between gap-3 text-[13px]">
              It is the seed of one-time codes
              <Switch checked={otp} onChange={setOtp} label="It is the seed of one-time codes" />
            </label>
          )}
          {error && <p className="text-xs text-deny">{error}</p>}
        </form>
      )}
    </Dialog>
  );
}
