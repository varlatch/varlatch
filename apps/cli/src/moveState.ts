// SPDX-License-Identifier: Apache-2.0
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Ingress, InstallConfig } from "./setup.js";

/**
 * Where an interrupted `varlatch move` (issue #103) stands, so a rerun
 * neither takes a second archive nor removes passkeys people enrolled at the
 * new address in between. Setup reads it too: a move in progress is finished
 * by `varlatch move`, never by a plain setup rerun.
 */
export const MOVE_STATE_FILE = "varlatch-move.json";

export interface MoveState {
  from: string;
  fromIngress: Ingress;
  to: string;
  toIngress: Ingress;
  archive: string;
  startedAt: string;
  /** Set once the old relying party's passkeys were removed. */
  passkeysRetiredAt?: string;
  /** Set once the re-enrollment links were issued. */
  linksIssuedAt?: string;
  /** The Installation Configuration before the move, for `varlatch move --abandon`. */
  previousConfig?: InstallConfig;
}

export function readMoveState(dir: string): MoveState | null {
  const path = join(dir, MOVE_STATE_FILE);
  return existsSync(path) ? (JSON.parse(readFileSync(path, "utf8")) as MoveState) : null;
}

export function writeMoveState(dir: string, state: MoveState): void {
  writeFileSync(join(dir, MOVE_STATE_FILE), JSON.stringify(state, null, 2) + "\n", { mode: 0o600 });
}

export function clearMoveState(dir: string): void {
  rmSync(join(dir, MOVE_STATE_FILE), { force: true });
}

