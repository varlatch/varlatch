// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useLayoutEffect, useRef, useState } from "react";
import { Check, Eye, EyeOff } from "lucide-react";
import { Popover } from "../../components/Popover";
import { cn } from "../../components/ui";

/**
 * In-place value editor for a grid cell or a list row. Enter keeps the
 * draft, Esc reverts, Tab moves on, leaving the field keeps the draft.
 * Nothing here saves: drafts go through review.
 *
 * - text: auto-growing, Shift+Enter for a new line;
 * - options: enum values or true/false, filtered as you type;
 * - secret: blind overwrite, never prefilled, with a show toggle.
 */

export type CommitHow = "enter" | "tab" | "shift-tab" | "blur" | "save";

type Props = {
  kind: "text" | "secret" | "options";
  options?: string[] | undefined;
  /** Starting text (ignored for secrets: never prefilled). */
  initial: string;
  placeholder?: string | undefined;
  onCommit: (value: string, how: CommitHow) => void;
  onCancel: () => void;
  className?: string | undefined;
  "aria-label"?: string | undefined;
};

const FIELD =
  "w-full rounded-md border border-accent bg-inset px-2 font-mono text-[13px] text-fg ring-2 ring-accent/20 placeholder:font-sans placeholder:text-subtle focus:outline-none";

export function ValueEditor(props: Props) {
  if (props.kind === "options") return <OptionsEditor {...props} options={props.options ?? []} />;
  if (props.kind === "secret") return <SecretEditor {...props} />;
  return <TextEditor {...props} />;
}

/** Shared key handling: returns true when handled. */
function useFinish(onCommit: Props["onCommit"], onCancel: Props["onCancel"]) {
  const done = useRef(false);
  const commit = (value: string, how: CommitHow) => {
    if (done.current) return;
    done.current = true;
    onCommit(value, how);
  };
  const cancel = () => {
    if (done.current) return;
    done.current = true;
    onCancel();
  };
  const keys = (e: React.KeyboardEvent, value: string): boolean => {
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      cancel();
      return true;
    }
    if (e.key === "Tab") {
      e.preventDefault();
      commit(value, e.shiftKey ? "shift-tab" : "tab");
      return true;
    }
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "s") {
      e.preventDefault();
      e.stopPropagation();
      commit(value, "save");
      return true;
    }
    return false;
  };
  return { commit, cancel, keys };
}

function TextEditor({ initial, placeholder, onCommit, onCancel, className, ...rest }: Props) {
  const [value, setValue] = useState(initial);
  const ref = useRef<HTMLTextAreaElement>(null);
  const { commit, keys } = useFinish(onCommit, onCancel);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    el.style.height = "0px";
    el.style.height = `${Math.min(el.scrollHeight, 160)}px`;
  }, [value]);
  useEffect(() => {
    ref.current?.focus();
    ref.current?.select();
  }, []);
  return (
    <textarea
      ref={ref}
      data-testid="cell-editor"
      aria-label={rest["aria-label"]}
      rows={1}
      spellCheck={false}
      value={value}
      placeholder={placeholder}
      onChange={(e) => setValue(e.target.value)}
      onBlur={() => commit(value, "blur")}
      onKeyDown={(e) => {
        if (keys(e, value)) return;
        if (e.key === "Enter" && !e.shiftKey) {
          e.preventDefault();
          commit(value, "enter");
        }
      }}
      className={cn(FIELD, "block min-h-8 resize-none py-[6px] leading-5", className)}
    />
  );
}

function SecretEditor({ placeholder, onCommit, onCancel, className, ...rest }: Props) {
  const [value, setValue] = useState("");
  const [show, setShow] = useState(false);
  const ref = useRef<HTMLInputElement>(null);
  const { commit, keys } = useFinish(onCommit, onCancel);
  useEffect(() => ref.current?.focus(), []);
  return (
    <div className={cn("relative", className)}>
      <input
        ref={ref}
        data-testid="cell-editor"
        aria-label={rest["aria-label"]}
        type={show ? "text" : "password"}
        autoComplete="new-password"
        spellCheck={false}
        value={value}
        placeholder={placeholder ?? "New secret value"}
        onChange={(e) => setValue(e.target.value)}
        onBlur={() => commit(value, "blur")}
        onKeyDown={(e) => {
          if (keys(e, value)) return;
          if (e.key === "Enter") {
            e.preventDefault();
            commit(value, "enter");
          }
        }}
        className={cn(FIELD, "h-8 pr-8")}
      />
      <button
        type="button"
        tabIndex={-1}
        aria-label={show ? "Hide what you typed" : "Show what you typed"}
        title={show ? "Hide what you typed" : "Show what you typed"}
        onMouseDown={(e) => e.preventDefault()}
        onClick={() => setShow((v) => !v)}
        className="absolute right-1 top-1/2 flex size-6 -translate-y-1/2 cursor-pointer items-center justify-center rounded text-muted hover:text-fg"
      >
        {show ? <EyeOff size={14} /> : <Eye size={14} />}
      </button>
    </div>
  );
}

function OptionsEditor({ initial, options, onCommit, onCancel, className, ...rest }: Props & { options: string[] }) {
  const [text, setText] = useState(initial);
  const [typed, setTyped] = useState(false);
  const shown = typed ? options.filter((o) => o.toLowerCase().includes(text.trim().toLowerCase())) : options;
  const [active, setActive] = useState(() => Math.max(0, options.indexOf(initial)));
  const ref = useRef<HTMLInputElement>(null);
  const { commit, cancel, keys } = useFinish(onCommit, onCancel);
  useEffect(() => {
    ref.current?.focus();
    ref.current?.select();
  }, []);
  useEffect(() => {
    if (typed) setActive(0);
  }, [text, typed]);
  const pick = (how: CommitHow) => {
    const choice = shown[active];
    if (choice !== undefined) commit(choice, how);
    else if (how !== "enter") cancel();
  };
  return (
    <div className={cn("relative", className)}>
      <input
        ref={ref}
        data-testid="cell-editor"
        aria-label={rest["aria-label"]}
        role="combobox"
        aria-expanded="true"
        aria-autocomplete="list"
        spellCheck={false}
        autoComplete="off"
        value={text}
        onChange={(e) => {
          setText(e.target.value);
          setTyped(true);
        }}
        onBlur={() => (options.includes(text) ? commit(text, "blur") : cancel())}
        onKeyDown={(e) => {
          if (e.key === "Tab") {
            e.preventDefault();
            pick(e.shiftKey ? "shift-tab" : "tab");
            return;
          }
          if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "s") {
            e.preventDefault();
            e.stopPropagation();
            pick("save");
            return;
          }
          if (keys(e, text)) return;
          if (e.key === "ArrowDown") {
            e.preventDefault();
            setActive((a) => Math.min(shown.length - 1, a + 1));
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            setActive((a) => Math.max(0, a - 1));
          } else if (e.key === "Enter") {
            e.preventDefault();
            pick("enter");
          }
        }}
        className={cn(FIELD, "h-8")}
      />
      <Popover anchor={ref} open>
        <ul
          role="listbox"
          className="min-w-40 animate-pop-in rounded-lg border border-bd bg-raised p-1 shadow-pop"
          onMouseDown={(e) => e.preventDefault()}
        >
          {shown.length === 0 && <li className="px-2 py-1.5 text-xs text-muted">No matching value</li>}
          {shown.map((o, i) => (
            <li
              key={o}
              role="option"
              aria-selected={i === active}
              onMouseMove={() => setActive(i)}
              onClick={() => commit(o, "enter")}
              className={cn(
                "flex cursor-pointer items-center justify-between gap-3 rounded-md px-2 py-1 font-mono text-[13px]",
                i === active ? "bg-accent-dim text-fg" : "text-fg/90",
              )}
            >
              {o}
              {o === initial && <Check size={13} className="text-accent" />}
            </li>
          ))}
        </ul>
      </Popover>
    </div>
  );
}
