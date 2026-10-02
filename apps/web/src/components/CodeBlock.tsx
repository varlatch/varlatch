// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useRef, useState } from "react";
import { Check, Copy } from "lucide-react";
import { IconButton, cn } from "./ui";

/** Copies `value` and briefly shows a check. */
export function CopyButton({
  value,
  label = "Copy",
  className,
  size = "sm",
  children,
  "data-testid": testId,
}: {
  value: string;
  label?: string | undefined;
  className?: string | undefined;
  size?: "sm" | "md" | undefined;
  /** Render as a labelled button instead of an icon. */
  children?: React.ReactNode | undefined;
  "data-testid"?: string | undefined;
}) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* Clipboard denied: nothing to do; the value stays selectable. */
    }
  };
  if (children) {
    return (
      <button
        type="button"
        data-testid={testId}
        onClick={() => void copy()}
        className={cn(
          "inline-flex h-8 cursor-pointer items-center gap-2 rounded-md border border-bd bg-raised px-3 text-sm text-fg transition-colors hover:border-bd-strong hover:bg-hover",
          className,
        )}
      >
        {copied ? <Check size={14} className="text-accent" /> : <Copy size={14} className="text-muted" />}
        {copied ? "Copied" : children}
      </button>
    );
  }
  return (
    <IconButton label={copied ? "Copied" : label} size={size} onClick={() => void copy()} className={className} data-testid={testId}>
      {copied ? <Check size={14} className="text-accent" /> : <Copy size={14} />}
    </IconButton>
  );
}

/** Multi-line command snippet with optional line numbers and a copy button. */
export function CodeBlock({
  lines,
  numbered = false,
  className,
  "data-testid": testId,
}: {
  lines: string[];
  numbered?: boolean | undefined;
  className?: string | undefined;
  "data-testid"?: string | undefined;
}) {
  return (
    <div className={cn("group relative rounded-lg border border-bd bg-inset", className)} data-testid={testId}>
      <pre className="overflow-x-auto py-3 pl-4 pr-12 font-mono text-[12.5px] leading-6 text-fg">
        {lines.map((line, i) => (
          <div key={i} className="whitespace-pre">
            {numbered && <span className="mr-4 inline-block w-3 select-none text-right text-subtle">{i + 1}</span>}
            <CommandLine text={line} />
          </div>
        ))}
      </pre>
      <CopyButton value={lines.join("\n")} label="Copy commands" className="absolute right-2 top-2" />
    </div>
  );
}

/** Light emphasis for the leading program name of a shell command. */
function CommandLine({ text }: { text: string }) {
  const m = /^(varlatch|printf|export|node)(\s.*)?$/.exec(text);
  if (!m) return <>{text}</>;
  return (
    <>
      <span className="text-accent">{m[1]}</span>
      {m[2]}
    </>
  );
}

/** One-line inline command chip with a copy button. */
export function InlineCommand({ command, className }: { command: string; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex max-w-full items-center gap-1 rounded-md border border-bd bg-inset py-0.5 pl-2.5 pr-0.5 align-middle font-mono text-[12.5px] text-fg",
        className,
      )}
    >
      <span className="truncate">{command}</span>
      <CopyButton value={command} label={`Copy ${command}`} />
    </span>
  );
}
