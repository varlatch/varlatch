// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from "react";
import { Dices, Eye, EyeOff, Lock, RefreshCw } from "lucide-react";
import { Dialog } from "../../components/Dialog";
import { Button, Field, Input, Segmented, Select, cn } from "../../components/ui";
import { errorMessage } from "../../shell/Shell";
import { generateSecret, listNames } from "./model";

/**
 * Begin a dual-phase rotation: the new value goes live now, the previous
 * value stays valid for the grace window, finishing drops it. Consumers
 * switch over without an outage.
 */

const PRESETS = { "1h": 3600, "24h": 86_400, "7d": 604_800 } as const;
type Preset = keyof typeof PRESETS | "custom";
const MAX_GRACE = 2_592_000; // 30 days, the server's limit

function presetFor(seconds: number | undefined): Preset {
  if (seconds === undefined) return "24h";
  const hit = (Object.keys(PRESETS) as (keyof typeof PRESETS)[]).find((k) => PRESETS[k] === seconds);
  return hit ?? "custom";
}

export function RotateDialog({
  open,
  item,
  project,
  env,
  targets,
  defaultGraceSeconds,
  onClose,
  onRotate,
}: {
  open: boolean;
  item: string;
  project: string;
  env: string;
  /** Labels of the integrations that carry this item. */
  targets: string[];
  defaultGraceSeconds?: number | undefined;
  onClose: () => void;
  /** Throws to keep the dialog open with the error shown. */
  onRotate: (value: string, graceSeconds: number) => Promise<void>;
}) {
  const [value, setValue] = useState("");
  const [show, setShow] = useState(false);
  const [preset, setPreset] = useState<Preset>(() => presetFor(defaultGraceSeconds));
  const [customAmount, setCustomAmount] = useState(() =>
    defaultGraceSeconds && presetFor(defaultGraceSeconds) === "custom" ? String(Math.round(defaultGraceSeconds / 3600)) : "48",
  );
  const [customUnit, setCustomUnit] = useState<"hours" | "days">("hours");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) return;
    setValue("");
    setShow(false);
    setError("");
    setPreset(presetFor(defaultGraceSeconds));
  }, [open, defaultGraceSeconds]);

  const amount = Number(customAmount);
  const graceSeconds =
    preset === "custom" ? Math.round(amount * (customUnit === "days" ? 86_400 : 3600)) : PRESETS[preset];
  const graceValid = Number.isFinite(graceSeconds) && graceSeconds >= 60 && graceSeconds <= MAX_GRACE;
  const ready = value !== "" && graceValid && !busy;

  const submit = async () => {
    if (!ready) return;
    setBusy(true);
    setError("");
    try {
      await onRotate(value, graceSeconds);
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
      data-testid="rotate-dialog"
      icon={
        <span className="flex size-9 items-center justify-center rounded-lg border border-bd bg-inset text-muted">
          <Lock size={16} />
        </span>
      }
      title={
        <>
          Rotate <span className="font-mono">{item}</span>
        </>
      }
      description={
        <span className="font-mono text-[12.5px]">
          {project} / {env}
        </span>
      }
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" data-testid="confirm-rotate" disabled={!ready} loading={busy} onClick={() => void submit()}>
            Start rotation
          </Button>
        </>
      }
    >
      <form
        className="space-y-5"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <ol className="grid grid-cols-3 gap-2" aria-label="How rotation works">
          {[
            ["New value goes live", "Now"],
            ["Both values valid", "Grace window"],
            ["Old value dropped", "When you finish"],
          ].map(([title, sub], i) => (
            <li
              key={title}
              className={cn(
                "relative flex flex-col items-center rounded-lg px-2 pb-2.5 pt-1 text-center",
                i === 1 && "bg-accent/[0.07] ring-1 ring-accent/25",
              )}
            >
              <span className="relative z-10 flex w-full items-center justify-center py-1.5">
                {i > 0 && <span aria-hidden="true" className={cn("absolute right-1/2 top-1/2 h-px w-full", i === 1 ? "bg-accent/60" : "bg-bd-strong")} />}
                <span
                  className={cn(
                    "relative flex size-7 items-center justify-center rounded-full border-2 bg-raised text-xs font-semibold",
                    i < 2 ? "border-accent text-accent" : "border-bd-strong text-muted",
                  )}
                >
                  {i + 1}
                </span>
              </span>
              <span className="text-[13px] font-medium text-fg">{title}</span>
              <span className="text-xs text-muted">{sub}</span>
            </li>
          ))}
        </ol>
        <p className="text-[13px] text-muted">
          Consumers switch over without an outage. Revoke the old credential upstream after finishing.
        </p>

        <Field label="New value" htmlFor="rotate-value">
          <div className="flex gap-2">
            <div className="relative min-w-0 flex-1">
              <Input
                id="rotate-value"
                data-testid="rotate-value"
                data-autofocus
                mono
                type={show ? "text" : "password"}
                autoComplete="new-password"
                spellCheck={false}
                className="w-full pr-9"
                value={value}
                onChange={(e) => setValue(e.target.value)}
              />
              <button
                type="button"
                aria-label={show ? "Hide value" : "Show value"}
                title={show ? "Hide value" : "Show value"}
                onClick={() => setShow((v) => !v)}
                className="absolute right-1 top-1/2 flex size-7 -translate-y-1/2 cursor-pointer items-center justify-center rounded text-muted hover:text-fg"
              >
                {show ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
            </div>
            <Button
              icon={<Dices size={14} />}
              data-testid="rotate-generate"
              onClick={() => {
                setValue(generateSecret());
              }}
              title="32 random bytes, base64url"
            >
              Generate
            </Button>
          </div>
        </Field>

        <Field label="Grace window" hint="How long the previous value keeps working. Up to 30 days.">
          <div className="flex flex-wrap items-center gap-2">
            <Segmented
              value={preset}
              onChange={setPreset}
              aria-label="Grace window"
              options={[
                { value: "1h", label: "1 hour", "data-testid": "grace-1h" },
                { value: "24h", label: "24 hours", "data-testid": "grace-24h" },
                { value: "7d", label: "7 days", "data-testid": "grace-7d" },
                { value: "custom", label: "Custom", "data-testid": "grace-custom" },
              ]}
            />
            {preset === "custom" && (
              <span className="flex items-center gap-2">
                <Input
                  data-testid="rotate-grace"
                  aria-label="Grace window length"
                  inputMode="numeric"
                  className="w-20"
                  invalid={!graceValid}
                  value={customAmount}
                  onChange={(e) => setCustomAmount(e.target.value.replace(/[^0-9]/g, ""))}
                />
                <Select
                  className="w-28"
                  aria-label="Unit"
                  value={customUnit}
                  onChange={(v) => setCustomUnit(v as "hours" | "days")}
                  options={[
                    { value: "hours", label: "hours" },
                    { value: "days", label: "days" },
                  ]}
                />
              </span>
            )}
          </div>
        </Field>

        <div className="flex items-start gap-3 rounded-lg border border-bd bg-inset/50 px-4 py-3 text-[13px] text-muted">
          <RefreshCw size={15} className="mt-0.5 shrink-0" />
          {targets.length > 0 ? (
            <p>
              <span className="text-fg">{listNames(targets)}</span> {targets.length === 1 ? "receives" : "receive"} the
              new value on {targets.length === 1 ? "its" : "their"} next sync.
            </p>
          ) : (
            <p>No integration pushes this item. Running consumers pick up the new value on their next start.</p>
          )}
        </div>
        {error && (
          <p className="text-[13px] text-deny" data-testid="rotate-error">
            {error}
          </p>
        )}
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}
