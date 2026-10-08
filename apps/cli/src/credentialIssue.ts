// SPDX-License-Identifier: Apache-2.0
import { closeSync, constants, fchmodSync, fsyncSync, lstatSync, openSync, statSync, unlinkSync, writeSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { VarlatchApiError, type VarlatchClient } from "@varlatch/sdk";

/**
 * `varlatch credential issue` (capability identity.credentials.issue):
 * another service credential for an existing machine identity, such as one
 * per program sharing the identity's Grants, the first one after a
 * reactivation, or the new half of a rotation.
 *
 * The token goes to one place only: the --out file, created exclusively
 * with mode 0600 in a directory that already exists. It is never written to
 * stdout or stderr, in any mode or error, and never comes from or goes to
 * the command line, so the command works in assisted mode too (ADR-0043
 * Decision 2). The file is created before the credential is issued, so a
 * path that cannot be written never leaves a live credential nobody holds.
 */

export const ISSUE_CAPABILITY = "identity.credentials.issue";

/** A refusal or failure, said without the token. Nothing was issued unless the message says so. */
export class CredentialIssueError extends Error {
  override name = "CredentialIssueError";
}

export interface CredentialIssueOptions {
  organization: string;
  identityId: string;
  name: string;
  ttlSeconds?: number | undefined;
  maxUses?: number | undefined;
  out: string;
}

/** What the command reports: identifiers and limits, never the token. */
export interface IssuedToFile {
  id: string;
  kind: "service";
  name: string;
  expiresAt: string | null;
  maxUses: number | null;
  out: string;
}

export type CredentialIssueApi = Pick<VarlatchClient, "meta" | "issueMachineCredential" | "revokeIdentityCredential">;

const NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const PREFIX = "varlatch credential issue:";

/** The checks that need no request: the file must not exist, its directory must. */
export function checkOutPath(out: string): void {
  let exists = true;
  try {
    lstatSync(out);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw unwritable(out, err);
    exists = false;
  }
  if (exists) {
    throw new CredentialIssueError(
      `${PREFIX} ${out} already exists, and the command never replaces a file. Choose a new --out. Nothing was issued.`,
    );
  }
  const dir = dirname(resolve(out));
  let isDir = false;
  try {
    isDir = statSync(dir).isDirectory();
  } catch {
    // Reported below.
  }
  if (!isDir) {
    throw new CredentialIssueError(
      `${PREFIX} the directory ${dirname(out)} does not exist; the command creates the file only, never its directory. Nothing was issued.`,
    );
  }
}

function unwritable(out: string, err: unknown): CredentialIssueError {
  const code = (err as NodeJS.ErrnoException).code ?? "an error";
  return new CredentialIssueError(`${PREFIX} cannot create ${out} (${code}). Nothing was issued.`);
}

/** The file, created exclusively and readable by its owner only, whatever the umask. */
function createExclusive(out: string): number {
  let fd: number;
  try {
    fd = openSync(out, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW, 0o600);
  } catch (err) {
    // Created between the check and now: never written through.
    if ((err as NodeJS.ErrnoException).code === "EEXIST") checkOutPath(out);
    throw unwritable(out, err);
  }
  try {
    fchmodSync(fd, 0o600);
  } catch (err) {
    discard(fd, out);
    throw unwritable(out, err);
  }
  return fd;
}

/** Close and remove a file this command created. */
function discard(fd: number, out: string): void {
  try {
    closeSync(fd);
  } catch {
    // Already closed.
  }
  try {
    unlinkSync(out);
  } catch {
    // Already gone.
  }
}

export async function issueCredentialToFile(api: CredentialIssueApi, opts: CredentialIssueOptions): Promise<IssuedToFile> {
  checkOutPath(opts.out);
  const meta = await api.meta();
  if (!meta.capabilities.includes(ISSUE_CAPABILITY)) {
    throw new CredentialIssueError(
      `${PREFIX} this server (${meta.serverVersion}) cannot issue a credential for an existing machine identity ` +
        `(it lacks the ${ISSUE_CAPABILITY} capability); upgrade the server. Nothing was issued.`,
    );
  }
  const fd = createExclusive(opts.out);
  let issued: Awaited<ReturnType<CredentialIssueApi["issueMachineCredential"]>>;
  try {
    issued = await api.issueMachineCredential(opts.organization, opts.identityId, {
      name: opts.name,
      ...(opts.ttlSeconds !== undefined ? { ttlSeconds: opts.ttlSeconds } : {}),
      ...(opts.maxUses !== undefined ? { maxUses: opts.maxUses } : {}),
    });
  } catch (err) {
    discard(fd, opts.out);
    if (err instanceof VarlatchApiError && err.code === "RESOURCE_NOT_FOUND") {
      throw new CredentialIssueError(
        `${PREFIX} ${opts.organization} has no machine identity ${opts.identityId} that can hold a service credential ` +
          `(a service, workload, or broker identity that is not retired). Nothing was issued. (request ${err.requestId})`,
      );
    }
    throw err;
  }
  try {
    const bytes = Buffer.from(`${issued.token}\n`, "utf8");
    let written = 0;
    while (written < bytes.length) written += writeSync(fd, bytes, written);
    fsyncSync(fd);
    closeSync(fd);
  } catch (err) {
    discard(fd, opts.out);
    // A credential nobody holds is revoked, so a failed write leaves nothing live.
    const revoked = await api.revokeIdentityCredential(opts.organization, opts.identityId, issued.id).then(
      () => true,
      () => false,
    );
    const code = (err as NodeJS.ErrnoException).code ?? "an error";
    throw new CredentialIssueError(
      `${PREFIX} cannot write ${opts.out} (${code}). ` +
        (revoked
          ? `Credential ${issued.id} was issued and then revoked: nothing is live.`
          : `Credential ${issued.id} was issued, and revoking it failed: revoke it with varlatch credential revoke ${opts.identityId} ${issued.id}`),
    );
  }
  return { id: issued.id, kind: "service", name: issued.name, expiresAt: issued.expiresAt, maxUses: issued.maxUses, out: opts.out };
}
