// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useRef, useState } from "react";
import type { Environment } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { DisclosureDiscardedError, TailnetOnlyError, isTailnetOnly } from "../../lib/tailnet";
import { tailnetReadKey, useTailnetConnection } from "../../lib/tailnetConnection";
import { dotenvLine, type ServerItem } from "./model";

/**
 * What the export dialog shows and writes, for the environment as it is now:
 * the caller passes the current object, not the one the dialog opened with.
 * When the environment turns tailnet-only the loaded values are dropped, and
 * a load or an export started before is discarded when it lands, so no file
 * is written from values the dashboard may no longer show.
 *
 * A tailnet-only environment exports through the tailnet endpoint while
 * this tab is connected, never through the dashboard's origin (ADR-0046);
 * a change of connection counts as a change of protection.
 */
export function useExport(org: string, project: string, env: Environment | null) {
  const { api: ordinary } = useSession();
  const { connection, client: tailnetClient } = useTailnetConnection();
  const [items, setItems] = useState<ServerItem[] | null>(null);
  const [withheld, setWithheld] = useState<Set<string>>(new Set());
  const [includeSecrets, setIncludeSecrets] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const isProtected = isTailnetOnly(env ?? undefined);
  const api = isProtected ? tailnetClient : ordinary;
  const tailnetOnly = isProtected && !api;
  const tailnetNow = useRef(tailnetOnly);
  tailnetNow.current = tailnetOnly;
  // Bumped whenever the environment, its protection or the connection changes.
  const generation = useRef(0);
  const key = env ? `${env.id}\u0000${isProtected}\u0000${isProtected ? tailnetReadKey(connection) : ""}` : "";

  useEffect(() => {
    const mine = ++generation.current;
    setItems(null);
    setWithheld(new Set());
    setIncludeSecrets(false);
    setError(null);
    if (!env || !api) return;
    api
      .effectiveConfiguration(org, project, env.name, { includeValues: true })
      .then((r) => {
        if (generation.current !== mine) return;
        setItems(r.items ?? []);
        setWithheld(new Set((r.callerView?.withheld ?? []).map((w) => w.name)));
      })
      .catch((err) => generation.current === mine && setError(err));
    // The key carries the environment's identity and protection; a refetched
    // object with neither changed keeps what was loaded.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api, org, project, key]);

  const secrets = (items ?? []).filter((i) => i.sensitive);
  const plain = (items ?? []).filter((i) => !i.sensitive && !withheld.has(i.name) && i.value != null);

  /** The file to write, or an error; never a file built across a change of protection. */
  const build = useCallback(async (): Promise<{ text: string; filename: string }> => {
    if (!env || !items || !api || tailnetNow.current) throw new TailnetOnlyError();
    const mine = generation.current;
    let disclosed = new Map<string, string>();
    if (includeSecrets && secrets.length > 0) {
      const result = await api.discloseSecrets(org, project, env.name, { items: secrets.map((s) => s.name) });
      disclosed = new Map(result.items.map((i) => [i.name, i.value]));
    }
    if (generation.current !== mine) throw tailnetNow.current ? new TailnetOnlyError() : new DisclosureDiscardedError();
    const lines = [`# ${project} / ${env.name}, exported ${new Date().toISOString()}`];
    for (const item of [...items].sort((a, b) => a.name.localeCompare(b.name))) {
      if (item.sensitive) {
        const value = disclosed.get(item.name);
        lines.push(value !== undefined ? dotenvLine(item.name, value) : `# ${item.name}: secret, not exported`);
      } else if (withheld.has(item.name) || item.value == null) {
        lines.push(`# ${item.name}: not readable with your access`);
      } else {
        lines.push(dotenvLine(item.name, item.value));
      }
    }
    return { text: `${lines.join("\n")}\n`, filename: `${project}.${env.name.replace(/\//g, "-")}.env` };
  }, [api, org, project, env, items, withheld, includeSecrets, secrets]);

  return { items, withheld, secrets, plain, includeSecrets, setIncludeSecrets, error, tailnetOnly, build };
}
