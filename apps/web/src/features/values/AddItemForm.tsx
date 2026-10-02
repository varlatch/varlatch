// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useState } from "react";
import { Plus } from "lucide-react";
import type { Environment, Tier } from "@varlatch/protocol";
import { Button, Input, Select, TierDot, cn } from "../../components/ui";
import { ITEM_NAME_PATTERN } from "./model";

/**
 * "Add item" row: name, target environment (when there is a choice) and
 * value become a draft. Pasting several KEY=value lines into either field
 * opens the import preview instead.
 */
export function AddItemForm({
  environments,
  initialEnv,
  exists,
  onAdd,
  onPaste,
  nameRef,
  className,
}: {
  environments: Environment[];
  initialEnv: string;
  exists: (env: string, name: string) => boolean;
  onAdd: (env: string, name: string, value: string) => void;
  /** Returns true when the paste was taken as an import. */
  onPaste: (text: string, env: string) => boolean;
  nameRef?: React.Ref<HTMLInputElement> | undefined;
  className?: string | undefined;
}) {
  const [name, setName] = useState("");
  const [env, setEnv] = useState(initialEnv);
  const [value, setValue] = useState("");
  useEffect(() => {
    if (!environments.some((e) => e.name === env)) setEnv(initialEnv);
  }, [environments, env, initialEnv]);
  const taken = name !== "" && exists(env, name);
  const valid = ITEM_NAME_PATTERN.test(name) && !taken;
  const submit = () => {
    if (!valid) return;
    onAdd(env, name, value);
    setName("");
    setValue("");
    (document.querySelector('[data-testid="add-name"]') as HTMLInputElement | null)?.focus();
  };
  const paste = (e: React.ClipboardEvent) => {
    const text = e.clipboardData.getData("text");
    if (text.includes("\n") && onPaste(text, env)) e.preventDefault();
  };
  return (
    <form
      className={cn("flex flex-wrap items-center gap-2", className)}
      onSubmit={(e) => {
        e.preventDefault();
        submit();
      }}
    >
      <Input
        ref={nameRef}
        data-testid="add-name"
        aria-label="New item name"
        mono
        placeholder="NEW_ITEM"
        className="w-56"
        value={name}
        invalid={taken || (name !== "" && !ITEM_NAME_PATTERN.test(name))}
        title={taken ? `${name} already has a value or change in ${env}: edit its cell instead` : undefined}
        onChange={(e) => setName(e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, "_"))}
        onPaste={paste}
      />
      {environments.length > 1 && (
        <Select
          className="w-44"
          data-testid="add-env"
          aria-label="Environment"
          value={env}
          onChange={setEnv}
          options={environments.map((e) => ({ value: e.name, label: e.name, icon: <TierDot tier={e.tier as Tier} /> }))}
        />
      )}
      <Input
        data-testid="add-value"
        aria-label="Value"
        mono
        placeholder="value, or paste KEY=value lines"
        className="min-w-48 flex-1"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onPaste={paste}
      />
      <Button type="submit" variant="secondary" icon={<Plus size={14} />} data-testid="add-item" disabled={!valid}>
        Add
      </Button>
    </form>
  );
}
