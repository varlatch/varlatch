// SPDX-License-Identifier: Apache-2.0
import {
  ContextError,
  defaultServer,
  listCredentials,
  rememberServerIfUnset,
  resolveServer,
  setDefaultServer,
  storedServerKey,
  type ServerSource,
} from "@varlatch/context";

/**
 * The remembered default server (ADR-0058 Decision 1). `varlatch login`
 * sets it when none is set and never replaces it; `varlatch server use`
 * changes it; signing out of it forgets it. It applies outside a
 * repository only: a repository's varlatch.toml always names its server.
 */

export const SERVER_USAGE = [
  "Usage: varlatch server [--json]          the server commands here use, and the remembered default",
  "       varlatch server use <url>         make <url>, which you are signed in to, the default",
].join("\n");

/** How each source reads in a sentence. */
export const SERVER_SOURCE_WORDS: Record<ServerSource, string> = {
  flag: "from --server",
  "env-var": "from VARLATCH_SERVER",
  "local-override": "from .varlatch/local.json",
  repository: "from varlatch.toml",
  default: "the default server",
  "only-credential": "the only server you are signed in to",
};

/**
 * After a sign-in stored its credential: make the server the default when
 * none is set, and say so on stderr only, so a --json document on stdout
 * stays the only thing there. A failure to write the setting never fails
 * the sign-in, which already succeeded.
 */
export function noteDefaultServer(server: string, err: (line: string) => void, env: NodeJS.ProcessEnv = process.env): void {
  try {
    if (rememberServerIfUnset(server, env)) {
      err(`Default server: ${storedServerKey(server)}, for commands outside a repository. Change it with: varlatch server use <url>`);
    }
  } catch (error) {
    err(`varlatch: the default server was not saved (${error instanceof Error ? error.message : String(error)}); the sign-in is stored.`);
  }
}

export interface ServerIo {
  out: (line: string) => void;
  json: ((doc: Record<string, unknown>) => void) | null;
}

export class ServerCommandError extends Error {
  override name = "ServerCommandError";
}

/** `varlatch server`: what a command here would use, the default, and the servers signed in to. */
export function showServer(cwd: string, io: ServerIo, env: NodeJS.ProcessEnv = process.env): void {
  let resolved: ReturnType<typeof resolveServer>;
  let problem: string | null = null;
  try {
    resolved = resolveServer({ cwd, env });
  } catch (error) {
    if (!(error instanceof ContextError)) throw error;
    resolved = null;
    problem = error.message;
  }
  const remembered = defaultServer(env);
  const signedIn = listCredentials(env).map((c) => c.server);
  if (io.json) {
    io.json({
      version: 1,
      server: resolved?.server ?? null,
      serverSource: resolved?.source ?? null,
      defaultServer: remembered,
      signedIn,
    });
    return;
  }
  io.out(resolved ? `Server here: ${resolved.server} (${SERVER_SOURCE_WORDS[resolved.source]})` : `Server here: none${problem ? ` (${problem})` : ""}`);
  io.out(`Default server: ${remembered ?? "none"}`);
  io.out(`Signed in to: ${signedIn.length > 0 ? signedIn.join(", ") : "none"}`);
}

/** `varlatch server use <url>`: only a server with a stored credential, so the default always names one you can use. */
export function useServer(server: string, io: ServerIo, env: NodeJS.ProcessEnv = process.env): void {
  let key: string;
  try {
    key = storedServerKey(new URL(server).toString());
  } catch {
    throw new ServerCommandError(`varlatch server use: not a URL: ${server}`);
  }
  const signedIn = listCredentials(env).map((c) => c.server);
  if (!signedIn.includes(key) && !signedIn.includes(storedServerKey(server))) {
    throw new ServerCommandError(
      `varlatch server use: you are not signed in to ${key}. Sign in first: varlatch login --server ${key}` +
        (signedIn.length > 0 ? `\nSigned in to: ${signedIn.join(", ")}` : ""),
    );
  }
  const chosen = signedIn.includes(key) ? key : storedServerKey(server);
  setDefaultServer(chosen, env);
  if (io.json) io.json({ version: 1, defaultServer: chosen });
  else io.out(`Default server: ${chosen}`);
}
