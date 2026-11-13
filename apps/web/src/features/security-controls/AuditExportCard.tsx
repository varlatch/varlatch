// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Archive, CircleAlert, CircleCheck, CircleDashed, Fingerprint, OctagonX, PauseCircle, TriangleAlert } from "lucide-react";
import type {
  AuditExport,
  AuditExportCheck,
  AuditExportDestinationInput,
  AuditExportRetention,
  AuditExportStatus,
} from "@varlatch/sdk";
import { useSession } from "../../lib/session";
import { formatDateTime, timeAgo, useNow } from "../../lib/time";
import { Badge, Button, Callout, Field, Input, SectionCard, Segmented, Switch } from "../../components/ui";
import { Dialog, useConfirm } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { errorMessage } from "../../shell/Shell";

/**
 * The audit export on the Security page (ADR-0056 Decision 11): the
 * organization's audit log copied to an S3-compatible bucket it controls.
 * Shown to whoever may manage the organization; with no export, one line
 * that it is not set up, and the way to set it up.
 *
 * Creating and lengthening or strengthening retention need no approval. A
 * new destination, a new key, a shorter or removed retention and removal
 * always need the person's approval with a trusted passkey: the session's
 * approval dialog asks for it when the server answers STEP_UP_REQUIRED, and
 * the form says so before it is sent. The secret access key is typed into a
 * password field, sent once, and never shown again.
 */

export const auditExportKey = (org: string) => ["audit-export", org] as const;

export const AUDIT_EXPORT_DOCS = "https://docs.varlatch.com/reference/audit-export/";

const LOCK_WORDS: Record<AuditExport["objectLock"], string> = {
  verified: "Object Lock verified",
  accepted: "lock headers accepted, not verified for this provider",
  "not-set": "no retention",
};

/** One hour: the page warns when the oldest event not yet exported is older. */
const LAG_WARNING_MS = 3_600_000;
/** Two hours without a heartbeat is how the bucket shows the copy stopped (Decision 7). */
const HEARTBEAT_STALE_MS = 2 * 3_600_000;

/** Whether the export is live: active, or draining after the organization's deletion. */
const isLive = (e: AuditExport | null) => e !== null && (e.state === "active" || e.state === "draining");
const hostOf = (endpoint: string) => {
  try {
    return new URL(endpoint).host;
  } catch {
    return endpoint;
  }
};
const retentionWords = (r: AuditExportRetention | null) => (r ? `${r.mode}, ${r.days} day${r.days === 1 ? "" : "s"}` : "none");

/**
 * A destination as the server stores it (normalizeDestination): the
 * endpoint's origin, and a prefix that is empty or ends with "/". So the
 * dialog compares what would really change, and never warns about an
 * approval for a change the server would find empty.
 */
export function normalizedDestination(d: AuditExportDestinationInput): AuditExportDestinationInput {
  const endpoint = normalizedEndpoint(d.endpoint);
  const prefix = (d.prefix ?? "").trim();
  return {
    endpoint,
    region: d.region.trim(),
    bucket: d.bucket.trim(),
    prefix: prefix !== "" && !prefix.endsWith("/") ? `${prefix}/` : prefix,
    pathStyle: d.pathStyle ?? false,
  };
}

/**
 * The endpoint's origin, as the server stores it, but only for an endpoint
 * the server accepts: http or https, with no user info, path, query or
 * fragment. Anything else is sent as typed, so the server's refusal says
 * what is wrong (`https://u:p@host/x` is not quietly made `https://host`,
 * and `localhost:9000`, whose origin is "null", is not sent as "null").
 */
export function normalizedEndpoint(typed: string): string {
  const text = typed.trim();
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return text;
  }
  const plain =
    (url.protocol === "https:" || url.protocol === "http:") &&
    !url.username && !url.password && !url.search && !url.hash &&
    (url.pathname === "/" || url.pathname === "") &&
    url.origin !== "null";
  return plain ? url.origin : text;
}

/** Whether going from `a` to `b` weakens retention: removed, shorter, or compliance to governance. */
export function retentionLoosens(a: AuditExportRetention | null, b: AuditExportRetention | null): boolean {
  if (a === null) return false;
  if (b === null) return true;
  return b.days < a.days || (a.mode === "compliance" && b.mode === "governance");
}

/** The state in a few words, and its tone. */
export function exportHealth(e: AuditExport, enabled: boolean, now: number): { label: string; tone: "accent" | "warn" | "danger" | "neutral" } {
  if (!enabled) return { label: "Stopped by the host operator", tone: "warn" };
  if (e.state === "removed") return { label: "Removed", tone: "neutral" };
  if (e.state === "completed") return { label: "Completed", tone: "neutral" };
  if (e.state === "abandoned") return { label: "Abandoned", tone: "warn" };
  if (e.stoppedReason !== null || e.unsupportedPlanFormat !== null) return { label: "Stopped", tone: "danger" };
  if (e.failingSince) return { label: "Failing", tone: "danger" };
  if (e.state === "draining") return { label: "Delivering the final events", tone: "warn" };
  const oldest = e.lag?.oldestPendingAt ? Date.parse(e.lag.oldestPendingAt) : null;
  if (oldest !== null && now - oldest > LAG_WARNING_MS) return { label: "Behind", tone: "warn" };
  return { label: "Delivering", tone: "accent" };
}

/** The Security page's section. `status` is GET .../audit-export. */
export function AuditExportCard({ org, status }: { org: string; status: AuditExportStatus }) {
  const now = useNow();
  const [editing, setEditing] = useState<"create" | "change" | "key" | null>(null);
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const { api } = useSession();
  const current = status.export;
  const refresh = () => qc.invalidateQueries({ queryKey: auditExportKey(org) });
  const remove = useMutation({
    mutationFn: (version: number) => api.removeAuditExport(org, version),
    onSuccess: async () => {
      await refresh();
      toast.success("Audit export removed", { description: "What it delivered stays in the bucket." });
    },
    onError: (err) => toast.error("Could not remove the audit export", { description: errorMessage(err) }),
  });
  const check = useMutation({
    mutationFn: (e: AuditExport) => api.checkAuditExport(org, { destination: e.destination, retention: e.retention }),
    onError: (err) => toast.error("Could not check the destination", { description: errorMessage(err) }),
  });
  // A result describes the destination and key it was made with: gone once
  // either changes (every change, a new key included, bumps the version).
  const checkedFor = current ? `${current.id}|${current.version}|${current.destination.endpoint}|${current.destination.bucket}|${current.destination.prefix}` : "";
  const resetCheck = check.reset;
  useEffect(() => {
    resetCheck();
  }, [checkedFor, resetCheck]);

  const askRemove = async (e: AuditExport) => {
    const ok = await confirm({
      title: `Remove the audit export of ${org}?`,
      description: "It needs your approval with a trusted passkey.",
      consequences: [
        { text: "The copy stops, and the export's key is cleared from this installation." },
        { text: `What it delivered stays in ${e.destination.bucket}, under its retention.` },
        { text: "A new export can backfill the whole audit log again." },
      ],
      confirmLabel: "Remove audit export",
      tone: "danger",
      typeToConfirm: org,
    });
    if (ok) remove.mutate(e.version);
  };

  return (
    <SectionCard
      id="security-audit-export"
      title="Audit export"
      description="A copy of this organization's audit log in a bucket you control, with a retention nobody here can shorten."
      className="scroll-mt-6"
      data-testid="security-audit-export"
      actions={
        <a href={AUDIT_EXPORT_DOCS} target="_blank" rel="noreferrer" className="inline-flex h-7 items-center rounded-md border border-bd px-2.5 text-xs font-medium text-fg hover:bg-hover">
          How it works
        </a>
      }
    >
      {!status.enabled && (
        <Callout tone="warn" icon={<PauseCircle size={16} />} className="m-5 mb-0" data-testid="audit-export-off" title="Stopped by the host operator">
          Whoever runs this installation turned audit export off (VARLATCH_AUDIT_EXPORT=off): nothing is delivered and no export can be set up.
          {isLive(current) ? " The export can still be removed." : ""}
        </Callout>
      )}
      {current !== null && isLive(current) ? (
        <ExportStatus
          e={current}
          enabled={status.enabled}
          now={now}
          checked={check.data ?? null}
          checking={check.isPending}
          onCheck={() => check.mutate(current)}
          onChange={() => setEditing("change")}
          onKey={() => setEditing("key")}
          onRemove={() => void askRemove(current)}
          removing={remove.isPending}
        />
      ) : (
        <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4 text-[13px]" data-testid="audit-export-none">
          <span className="flex items-center gap-2">
            <CircleDashed size={16} className="text-muted" aria-hidden="true" />
            {current
              ? `Not set up. The last export was ${current.state}${current.removedAt ? ` on ${formatDateTime(current.removedAt)}` : ""}.`
              : "Not set up. The audit log stays in this installation only."}
          </span>
          <Button size="sm" variant="primary" disabled={!status.enabled} onClick={() => setEditing("create")} data-testid="audit-export-create">
            Set up audit export…
          </Button>
        </div>
      )}
      {editing === "create" && <ExportDialog org={org} current={null} onClose={() => setEditing(null)} />}
      {editing === "change" && current !== null && isLive(current) && <ExportDialog org={org} current={current} onClose={() => setEditing(null)} />}
      {editing === "key" && current !== null && isLive(current) && <KeyDialog org={org} current={current} onClose={() => setEditing(null)} />}
    </SectionCard>
  );
}

function Row({ label, children, testId }: { label: string; children: React.ReactNode; testId?: string }) {
  return (
    <div className="grid grid-cols-[150px_1fr] gap-3 px-5 py-2 text-[13px]" data-testid={testId}>
      <dt className="text-muted">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  );
}

function ExportStatus({
  e,
  enabled,
  now,
  checked,
  checking,
  onCheck,
  onChange,
  onKey,
  onRemove,
  removing,
}: {
  e: AuditExport;
  enabled: boolean;
  now: number;
  checked: AuditExportCheck | null;
  checking: boolean;
  onCheck: () => void;
  onChange: () => void;
  onKey: () => void;
  onRemove: () => void;
  removing: boolean;
}) {
  const health = exportHealth(e, enabled, now);
  // A new export has had no time for one yet: waiting, not stale.
  const awaitingFirst = e.state === "active" && !e.lastHeartbeatAt && now - Date.parse(e.createdAt) <= HEARTBEAT_STALE_MS;
  const heartbeatStale = e.state === "active" && enabled && !awaitingFirst && (!e.lastHeartbeatAt || now - Date.parse(e.lastHeartbeatAt) > HEARTBEAT_STALE_MS);
  const draining = e.state === "draining";
  return (
    <>
      <div className="flex flex-wrap items-center gap-3 border-b border-bd px-5 py-3.5" data-testid="audit-export-live">
        <Badge tone={health.tone} data-testid="audit-export-health">
          {health.label}
        </Badge>
        <span className="text-[13px] text-muted">
          {e.lastSuccessAt ? `Last written ${timeAgo(e.lastSuccessAt, now)}` : "Nothing written yet"}
          {e.lag ? `, ${e.lag.pending} event${e.lag.pending === 1 ? "" : "s"} pending` : ""}
        </span>
        {!draining && (
          <div className="ml-auto flex flex-wrap gap-2">
            <Button size="sm" variant="secondary" loading={checking} disabled={!enabled} onClick={onCheck} data-testid="audit-export-check">
              Check destination
            </Button>
            <Button size="sm" variant="secondary" disabled={!enabled} onClick={onChange} data-testid="audit-export-change">
              Change…
            </Button>
            <Button size="sm" variant="secondary" disabled={!enabled} onClick={onKey} data-testid="audit-export-key">
              Replace key…
            </Button>
            <Button size="sm" variant="danger" loading={removing} onClick={onRemove} data-testid="audit-export-remove">
              Remove…
            </Button>
          </div>
        )}
      </div>
      <div className="space-y-3 px-5 pt-3">
        {draining && (
          <Callout tone="warn" icon={<Archive size={16} />} title="The organization is deleted: delivering its final events" data-testid="audit-export-draining">
            The export's key stays readable by this installation until the final events are delivered, and at the latest until{" "}
            {e.drainDeadline ? formatDateTime(e.drainDeadline) : "30 days after the deletion"}. Then it is cleared.
          </Callout>
        )}
        {e.stoppedReason === "object_conflict" && (
          <Callout tone="danger" icon={<OctagonX size={16} />} title="Stopped: an object with the planned name exists with other content" data-testid="audit-export-conflict">
            Nothing was overwritten. Change the destination, or remove the export.
          </Callout>
        )}
        {e.unsupportedPlanFormat !== null && (
          <Callout tone="danger" icon={<OctagonX size={16} />} title={`Stopped: a pending object is in format ${e.unsupportedPlanFormat}, which this release cannot upload`} data-testid="audit-export-format">
            Whoever runs this installation finishes it with an earlier release, or runs varlatchd admin audit-export discard-plan.
          </Callout>
        )}
        {e.lastError && (
          <Callout tone={e.failingSince ? "danger" : "warn"} icon={<CircleAlert size={16} />} title={e.failingSince ? `Failing since ${formatDateTime(e.failingSince)}` : "The last attempt failed"} data-testid="audit-export-error">
            {e.lastError}
          </Callout>
        )}
        {e.lag?.oldestPendingAt && now - Date.parse(e.lag.oldestPendingAt) > LAG_WARNING_MS && (
          <Callout tone="warn" icon={<TriangleAlert size={16} />} role="status" data-testid="audit-export-lag">
            The oldest event not yet exported is from {formatDateTime(e.lag.oldestPendingAt)}, over an hour ago.
          </Callout>
        )}
        {checked && <CheckResult result={checked} />}
      </div>
      <dl className="py-2">
        <Row label="Destination" testId="audit-export-destination">
          {hostOf(e.destination.endpoint)}, bucket <span className="font-mono">{e.destination.bucket}</span>
          {e.destination.prefix ? (
            <>
              , prefix <span className="font-mono">{e.destination.prefix}</span>
            </>
          ) : null}
        </Row>
        <Row label="Retention" testId="audit-export-retention">
          {retentionWords(e.retention)}; {LOCK_WORDS[e.objectLock]}
          {e.retention === null ? "; versioning not verified" : ""}
        </Row>
        <Row label="Heartbeat" testId="audit-export-heartbeat">
          {e.lastHeartbeatAt ? `last at ${formatDateTime(e.lastHeartbeatAt)}` : awaitingFirst ? "waiting for the first heartbeat" : "none yet"}
          {heartbeatStale ? " (none in the last two hours)" : ""}
          <span className="block text-xs text-muted">A heartbeat object every hour: a bucket without one for two hours means the copy stopped.</span>
        </Row>
        <Row label="The key" testId="audit-export-key-flags">
          {e.keyCanRead === null ? "object read not determined" : e.keyCanRead ? "can read objects" : "write-only"}
          {e.retention === null ? "" : e.retentionReadable === null ? ", retention read not determined" : e.retentionReadable ? ", can read retention" : ", cannot read retention"}
        </Row>
        <Row label="Stream">
          <span className="font-mono text-xs">{e.streamId}</span>, delivered up to position {e.cursor}
        </Row>
      </dl>
      <Checklist e={e} />
    </>
  );
}

function CheckResult({ result }: { result: AuditExportCheck }) {
  if (!result.ok) {
    return (
      <Callout tone="danger" icon={<OctagonX size={16} />} title="The destination check failed" role="alert" data-testid="audit-export-check-result">
        {result.message ?? "No reason given."} Nothing was saved.
      </Callout>
    );
  }
  return (
    <Callout tone="success" icon={<CircleCheck size={16} />} title="The destination passed the check" role="status" data-testid="audit-export-check-result">
      It refuses to overwrite an existing object. {result.objectLock ? `Object Lock: ${LOCK_WORDS[result.objectLock]}.` : ""} Nothing was saved.
    </Callout>
  );
}

/** What Varlatch cannot check for you (Decision 7), with what it can. */
function Checklist({ e }: { e: AuditExport }) {
  const compliance = e.retention?.mode === "compliance" && e.retention.days >= 400;
  const items: { done: boolean | null; text: string }[] = [
    { done: compliance, text: "Compliance retention for at least 400 days: governance can be bypassed by accounts allowed to." },
    { done: null, text: "A bucket in an account the host operator does not control, and not the backup destination." },
    { done: null, text: "Someone watching the heartbeat objects, who acts when none arrives for two hours." },
  ];
  return (
    <ul className="border-t border-bd px-5 py-3 text-[13px]" data-testid="audit-export-checklist">
      {items.map((item) => (
        <li key={item.text} className="flex items-start gap-2 py-1">
          {item.done ? (
            <CircleCheck size={15} className="mt-0.5 shrink-0 text-accent" role="img" aria-label="Done" />
          ) : (
            <CircleDashed size={15} className="mt-0.5 shrink-0 text-muted" role="img" aria-label={item.done === false ? "Not yet" : "Varlatch cannot check this"} />
          )}
          <span>{item.text}</span>
        </li>
      ))}
    </ul>
  );
}

type RetentionChoice = "none" | "governance" | "compliance";

/** Create, or change the destination and retention. */
function ExportDialog({ org, current, onClose }: { org: string; current: AuditExport | null; onClose: () => void }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const d = current?.destination;
  const [endpoint, setEndpoint] = useState(d?.endpoint ?? "");
  const [region, setRegion] = useState(d?.region ?? "");
  const [bucket, setBucket] = useState(d?.bucket ?? "");
  const [prefix, setPrefix] = useState(d?.prefix ?? "");
  const [pathStyle, setPathStyle] = useState(d?.pathStyle ?? false);
  const [mode, setMode] = useState<RetentionChoice>(current ? (current.retention?.mode ?? "none") : "compliance");
  const [days, setDays] = useState(String(current?.retention?.days ?? 400));
  const [accessKeyId, setAccessKeyId] = useState("");
  const [secret, setSecret] = useState("");
  const [from, setFrom] = useState<"beginning" | "now">("beginning");
  const [checked, setChecked] = useState<AuditExportCheck | null>(null);

  const daysOk = /^\d{1,4}$/.test(days) && Number(days) >= 1 && Number(days) <= 3650;
  const retention: AuditExportRetention | null = mode === "none" ? null : { mode, days: Number(days) };
  const destination: AuditExportDestinationInput = { endpoint: endpoint.trim(), region: region.trim(), bucket: bucket.trim(), prefix: prefix.trim(), pathStyle };
  const normalized = normalizedDestination(destination);
  const changedFields = current === null ? [] : (["endpoint", "region", "bucket", "prefix", "pathStyle"] as const).filter((k) => normalized[k] !== current.destination[k]);
  const destinationChanged = changedFields.length > 0;
  const loosens = current !== null && (destinationChanged || retentionLoosens(current.retention, retention));
  const unchanged = current !== null && !destinationChanged && retentionWords(current.retention) === retentionWords(retention);
  const keyOk = current !== null || (accessKeyId.trim() !== "" && secret !== "");
  const ready = destination.endpoint !== "" && destination.region !== "" && destination.bucket.length >= 3 && (mode === "none" || daysOk) && keyOk && !unchanged;

  const done = async (title: string) => {
    setSecret("");
    await qc.invalidateQueries({ queryKey: auditExportKey(org) });
    toast.success(title);
    onClose();
  };
  const save = useMutation({
    mutationFn: async () => {
      if (current === null) {
        await api.createAuditExport(org, { destination, credential: { accessKeyId: accessKeyId.trim(), secretAccessKey: secret }, retention, from });
        return "Audit export set up";
      }
      const changed = await api.changeAuditExport(org, {
        expectedVersion: current.version,
        ...(changedFields.length > 0 ? { destination: Object.fromEntries(changedFields.map((k) => [k, normalized[k]])) } : {}),
        ...(retentionWords(current.retention) !== retentionWords(retention) ? { retention } : {}),
      });
      return changed.changed ? "Audit export changed" : "Nothing to change";
    },
    onSuccess: (title) => done(title),
  });
  const probe = useMutation({
    // Only at setup: a change probes the new destination when it is saved.
    mutationFn: () => api.checkAuditExport(org, { destination, retention, credential: { accessKeyId: accessKeyId.trim(), secretAccessKey: secret } }),
    onSuccess: setChecked,
  });

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title={current ? "Change the audit export" : "Set up audit export"}
      description={
        current
          ? "A new destination starts a new stream there; the old bucket keeps what it received."
          : "Varlatch writes a test object first and checks that the bucket refuses to overwrite it."
      }
      data-testid="audit-export-dialog"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          {current === null && (
            <Button variant="secondary" loading={probe.isPending} disabled={!ready} onClick={() => probe.mutate()} data-testid="audit-export-dialog-check">
              Check
            </Button>
          )}
          <Button variant="primary" loading={save.isPending} disabled={!ready} onClick={() => save.mutate()} data-testid="audit-export-save">
            {current ? (loosens ? "Approve and save…" : "Save") : "Set up"}
          </Button>
        </>
      }
    >
      <form
        className="space-y-4"
        onSubmit={(ev) => {
          ev.preventDefault();
          if (ready) save.mutate();
        }}
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Endpoint" hint="https://s3.eu-central-1.amazonaws.com or https://s3.eu-central-003.backblazeb2.com" className="sm:col-span-2">
            <Input mono className="w-full" value={endpoint} onChange={(ev) => setEndpoint(ev.target.value)} data-testid="audit-export-endpoint" data-autofocus />
          </Field>
          <Field label="Region">
            <Input mono className="w-full" value={region} onChange={(ev) => setRegion(ev.target.value)} data-testid="audit-export-region" />
          </Field>
          <Field label="Bucket">
            <Input mono className="w-full" value={bucket} onChange={(ev) => setBucket(ev.target.value)} data-testid="audit-export-bucket" />
          </Field>
          <Field label="Prefix" hint="Optional. Objects go under <prefix>varlatch-audit/.">
            <Input mono className="w-full" value={prefix} onChange={(ev) => setPrefix(ev.target.value)} data-testid="audit-export-prefix" />
          </Field>
          <Field label="Path-style addressing" hint="For MinIO and some other providers.">
            <Switch checked={pathStyle} onChange={setPathStyle} label="Path-style addressing" data-testid="audit-export-path-style" />
          </Field>
        </div>
        <Field label="Retention (Object Lock)" hint="Compliance for at least 400 days is recommended. The bucket needs Object Lock, and the key permission to set retention.">
          <div className="flex flex-wrap items-center gap-3">
            <Segmented<RetentionChoice>
              value={mode}
              onChange={setMode}
              aria-label="Retention mode"
              options={[
                { value: "none", label: "None", "data-testid": "audit-export-retention-none" },
                { value: "governance", label: "Governance", "data-testid": "audit-export-retention-governance" },
                { value: "compliance", label: "Compliance", "data-testid": "audit-export-retention-compliance" },
              ]}
            />
            {mode !== "none" && (
              <label className="flex items-center gap-2 text-[13px]">
                <Input className="w-20" inputMode="numeric" value={days} invalid={!daysOk} onChange={(ev) => setDays(ev.target.value)} data-testid="audit-export-days" />
                days
              </label>
            )}
          </div>
        </Field>
        {current === null && (
          <>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Access key ID">
                <Input mono className="w-full" autoComplete="off" value={accessKeyId} onChange={(ev) => setAccessKeyId(ev.target.value)} data-testid="audit-export-key-id" />
              </Field>
              <Field label="Secret access key" hint="Sent once; never shown again.">
                <Input mono type="password" className="w-full" autoComplete="new-password" value={secret} onChange={(ev) => setSecret(ev.target.value)} data-testid="audit-export-secret" />
              </Field>
            </div>
            <Field label="Start from">
              <Segmented<"beginning" | "now">
                value={from}
                onChange={setFrom}
                aria-label="Start from"
                options={[
                  { value: "beginning", label: "The whole audit log", "data-testid": "audit-export-from-beginning" },
                  { value: "now", label: "Now", "data-testid": "audit-export-from-now" },
                ]}
              />
            </Field>
          </>
        )}
        {loosens && (
          <Callout tone="info" icon={<Fingerprint size={16} />} data-testid="audit-export-needs-approval">
            {destinationChanged ? "A new destination" : "A shorter or weaker retention"} needs your approval with a trusted passkey. Saving asks for it.
          </Callout>
        )}
        {checked && <CheckResult result={checked} />}
        {probe.error && <p className="text-sm text-deny" role="alert">{errorMessage(probe.error)}</p>}
        {save.error && (
          <p className="text-sm text-deny" role="alert" data-testid="audit-export-save-error">
            {errorMessage(save.error)}
          </p>
        )}
      </form>
    </Dialog>
  );
}

/** A new key for the live export: always an approval. */
function KeyDialog({ org, current, onClose }: { org: string; current: AuditExport; onClose: () => void }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const [accessKeyId, setAccessKeyId] = useState("");
  const [secret, setSecret] = useState("");
  const ready = accessKeyId.trim() !== "" && secret !== "";
  const save = useMutation({
    mutationFn: () => api.replaceAuditExportCredential(org, { expectedVersion: current.version, credential: { accessKeyId: accessKeyId.trim(), secretAccessKey: secret } }),
    onSuccess: async () => {
      setSecret("");
      await qc.invalidateQueries({ queryKey: auditExportKey(org) });
      toast.success("Audit export key replaced", { description: "Delivery continues with the new key." });
      onClose();
    },
  });
  return (
    <Dialog
      open
      onClose={onClose}
      size="sm"
      title="Replace the audit export's key"
      description="A wrong key stops delivery, so this needs your approval with a trusted passkey."
      data-testid="audit-export-key-dialog"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={save.isPending} disabled={!ready} onClick={() => save.mutate()} data-testid="audit-export-key-save">
            Approve and save…
          </Button>
        </>
      }
    >
      <form
        className="space-y-3"
        onSubmit={(ev) => {
          ev.preventDefault();
          if (ready) save.mutate();
        }}
      >
        <Field label="Access key ID">
          <Input mono className="w-full" autoComplete="off" value={accessKeyId} onChange={(ev) => setAccessKeyId(ev.target.value)} data-testid="audit-export-new-key-id" data-autofocus />
        </Field>
        <Field label="Secret access key" hint="Sent once; never shown again.">
          <Input mono type="password" className="w-full" autoComplete="new-password" value={secret} onChange={(ev) => setSecret(ev.target.value)} data-testid="audit-export-new-secret" />
        </Field>
        {save.error && (
          <p className="text-sm text-deny" role="alert" data-testid="audit-export-key-error">
            {errorMessage(save.error)}
          </p>
        )}
      </form>
    </Dialog>
  );
}
