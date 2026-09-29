// SPDX-License-Identifier: Apache-2.0
import { randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { basename, dirname, extname, join, resolve } from "node:path";
import type { ContractRevision } from "@varlatch/protocol";
import { VarlatchApiError } from "@varlatch/sdk";
import { TypesError, generateTypesModule } from "./typegen.js";
import { generatePythonModule } from "./typegenPython.js";

/**
 * `varlatch types --out <file>`: fetch one Contract Revision (the active one,
 * or `--revision <id>`), generate the module in the language the file's
 * extension names (TypeScript or Python), and write it only if its bytes
 * changed. The only network call is that one fetch, which needs
 * contract.read and returns no values.
 *
 * The file is never written through a symbolic link: a link at the output
 * path is refused, and the new content goes to a fresh file in the same
 * directory (created exclusively, so nothing planted there is followed) that
 * is then renamed over the old one. No shared temporary directory is used.
 *
 * `--check` generates in memory and compares bytes with the file, writing
 * nothing, and fails when the file is stale or missing.
 */

export interface TypesClient {
  getActiveContract(org: string, project: string): Promise<ContractRevision>;
  getContractRevision(org: string, project: string, revisionId: string): Promise<ContractRevision>;
}

export interface TypesOptions {
  organization: string;
  project: string;
  /** A specific revision; otherwise the active one. */
  revision?: string | undefined;
  out: string;
  check: boolean;
  generatorVersion: string;
}

export interface TypesIo {
  out(line: string): void;
  err(line: string): void;
}

/** The output file's extension selects the language (ADR-0041). */
const GENERATORS: Record<string, typeof generateTypesModule> = {
  ".ts": generateTypesModule,
  ".mts": generateTypesModule,
  ".cts": generateTypesModule,
  ".py": generatePythonModule,
};
const NOFOLLOW = constants.O_NOFOLLOW ?? 0;

async function fetchRevision(api: TypesClient, opts: TypesOptions): Promise<ContractRevision> {
  try {
    return opts.revision
      ? await api.getContractRevision(opts.organization, opts.project, opts.revision)
      : await api.getActiveContract(opts.organization, opts.project);
  } catch (err) {
    if (!(err instanceof VarlatchApiError)) throw err;
    if (err.status === 403) throw new TypesError("reading the Contract needs contract.read on the project");
    if (err.status === 404) {
      throw new TypesError(
        opts.revision
          ? `Contract Revision ${opts.revision} was not found in ${opts.organization}/${opts.project} (fetching a revision by ID needs Varlatch 0.11.0 or later)`
          : `${opts.organization}/${opts.project} has no active Contract visible to this identity`,
      );
    }
    throw err;
  }
}

/** The bytes at the output path, or null when there is no file. Refuses anything but a regular file. */
function readOutput(path: string): { bytes: Buffer; mode: number } | null {
  let stat;
  try {
    stat = lstatSync(path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
  if (stat.isSymbolicLink()) {
    throw new TypesError(`${path} is a symbolic link; varlatch types never writes through one, so point --out at the file itself`);
  }
  if (!stat.isFile()) throw new TypesError(`${path} is not a regular file`);
  const fd = openSync(path, constants.O_RDONLY | NOFOLLOW);
  try {
    return { bytes: readFileSync(fd), mode: stat.mode & 0o7777 };
  } finally {
    closeSync(fd);
  }
}

function writeReplacing(path: string, content: Buffer, mode: number | undefined): void {
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true });
  const temporary = join(dir, `.${basename(path)}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`);
  const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW, 0o644);
  try {
    try {
      writeSync(fd, content);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    if (mode !== undefined) chmodSync(temporary, mode);
    renameSync(temporary, path);
  } catch (err) {
    try {
      unlinkSync(temporary);
    } catch {
      // Already renamed or never created.
    }
    throw err;
  }
}

export async function runTypes(api: TypesClient, opts: TypesOptions, io: TypesIo): Promise<number> {
  const path = resolve(opts.out);
  const generate = Object.hasOwn(GENERATORS, extname(path)) ? GENERATORS[extname(path)] : undefined;
  if (!generate) {
    io.err(`varlatch types: --out must name a TypeScript file (.ts, .mts, .cts) or a Python file (.py): ${opts.out}`);
    return 1;
  }
  try {
    const revision = await fetchRevision(api, opts);
    const content = Buffer.from(
      generate(
        {
          id: revision.id,
          contentHash: revision.contentHash,
          semanticsVersion: revision.semanticsVersion,
          contract: revision.contract,
        },
        { generatorVersion: opts.generatorVersion },
      ),
      "utf8",
    );
    const source = `Contract Revision ${revision.id} (${revision.contentHash}, Contract Semantics version ${revision.semanticsVersion})`;
    const current = readOutput(path);
    const fresh = current !== null && current.bytes.equals(content);
    if (opts.check) {
      if (fresh) {
        io.out(`${opts.out} is current with ${source}.`);
        return 0;
      }
      io.err(
        `varlatch types --check: ${opts.out} ${current === null ? "does not exist" : "is stale"}: it does not match ${source}. Regenerate it with varlatch types --out ${opts.out}${opts.revision ? ` --revision ${opts.revision}` : ""}.`,
      );
      return 1;
    }
    if (fresh) {
      io.out(`${opts.out} is already current with ${source}; left unchanged.`);
      return 0;
    }
    writeReplacing(path, content, current?.mode);
    io.out(`Wrote ${opts.out} from ${source}.`);
    return 0;
  } catch (err) {
    if (err instanceof TypesError) {
      io.err(`varlatch types: ${err.message}. Nothing was written.`);
      return 1;
    }
    throw err;
  }
}
