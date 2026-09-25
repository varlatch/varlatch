// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  ContractValidationError,
  LATEST_SEMANTICS_VERSION,
  contractHash,
  diffContracts,
  normalizeContract,
  semanticsVersionOf,
  type ConfigurationContract,
} from "@varlatch/contract";
import { recordAuditEvent } from "../audit/events.js";
import { newId } from "../db/ids.js";
import { withTx } from "../db/tx.js";
import type { AppCtx } from "./ctx.js";
import { DomainError, notFound } from "./errors.js";
import type { ProjectRow } from "./projects.js";

export interface ContractRevisionRow {
  id: string;
  project_id: string;
  content_hash: string;
  contract: ConfigurationContract;
  provenance: Record<string, string> | null;
  created_by: string | null;
  created_at: string;
}

function parseContract(row: ContractRevisionRow): ConfigurationContract {
  return typeof row.contract === "string"
    ? (JSON.parse(row.contract) as ConfigurationContract)
    : row.contract;
}

function normalizeOrReject(input: unknown): ConfigurationContract {
  try {
    return normalizeContract(input);
  } catch (err) {
    if (err instanceof ContractValidationError) {
      throw new DomainError("CONTRACT_INVALID", err.message, { issues: err.issues });
    }
    throw err;
  }
}

/** Whether the pushed Contract names its semantics version (a pin). */
function pinsSemanticsVersion(input: unknown): boolean {
  return (
    typeof input === "object" &&
    input !== null &&
    (input as { semanticsVersion?: unknown }).semanticsVersion !== undefined
  );
}

/**
 * Store a candidate revision (ADR-0013): server-side re-normalization and
 * hashing (client hashes are never trusted), content-hash deduplication,
 * never activates implicitly.
 *
 * Semantics version (ADR-0038 Decision 3): a Contract that names one pins
 * it. Otherwise the revision keeps the active revision's version, so an
 * edit never migrates validation rules, and a project with no active
 * revision gets the newest version.
 */
export async function pushRevision(
  ctx: AppCtx,
  organizationId: string,
  projectId: string,
  contractInput: unknown,
  provenance: Record<string, string> | undefined,
  actorIdentityId: string,
): Promise<ContractRevisionRow> {
  const pushed = normalizeOrReject(contractInput);
  const pinned = pinsSemanticsVersion(contractInput);
  return withTx(ctx.db, async (db) => {
    let contract = pushed;
    if (!pinned) {
      const active = await db.query(
        `SELECT r.contract FROM projects p
         JOIN contract_revisions r ON r.id = p.active_contract_revision_id
         WHERE p.id = $1`,
        [projectId],
      );
      const activeRow = active.rows[0] as Pick<ContractRevisionRow, "contract"> | undefined;
      const version = activeRow
        ? semanticsVersionOf(parseContract(activeRow as ContractRevisionRow))
        : LATEST_SEMANTICS_VERSION;
      contract = normalizeOrReject({ ...pushed, semanticsVersion: version });
    }
    const hash = contractHash(contract);
    const existing = await db.query(
      "SELECT * FROM contract_revisions WHERE project_id = $1 AND content_hash = $2",
      [projectId, hash],
    );
    if (existing.rows[0]) return existing.rows[0] as ContractRevisionRow;
    const id = newId("contractRevision");
    await db.query(
      `INSERT INTO contract_revisions (id, project_id, content_hash, contract, provenance, created_by)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [
        id,
        projectId,
        hash,
        JSON.stringify(contract),
        provenance ? JSON.stringify(provenance) : null,
        actorIdentityId,
      ],
    );
    await recordAuditEvent(db, {
      eventType: "contract.revision_pushed",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "contract.submit",
      resource: { projectId, contractRevisionId: id },
      metadata: {
        contentHash: hash,
        itemCount: contract.items.length,
        semanticsVersion: semanticsVersionOf(contract),
      },
    });
    const res = await db.query("SELECT * FROM contract_revisions WHERE id = $1", [id]);
    return res.rows[0] as ContractRevisionRow;
  });
}

/** Activation is a distinct, audited, security-relevant operation (ADR-0013). */
export async function activateRevision(
  ctx: AppCtx,
  organizationId: string,
  project: ProjectRow,
  revisionId: string,
  actorIdentityId: string,
): Promise<ContractRevisionRow> {
  return withTx(ctx.db, async (db) => {
    const res = await db.query(
      "SELECT * FROM contract_revisions WHERE id = $1 AND project_id = $2",
      [revisionId, project.id],
    );
    const revision = res.rows[0] as ContractRevisionRow | undefined;
    if (!revision) throw notFound("Contract revision");

    let diffSummary: Record<string, string | number | boolean> = { initial: true };
    if (project.active_contract_revision_id) {
      const prevRes = await db.query("SELECT * FROM contract_revisions WHERE id = $1", [
        project.active_contract_revision_id,
      ]);
      const prev = prevRes.rows[0] as ContractRevisionRow | undefined;
      if (prev) {
        const diff = diffContracts(parseContract(prev), parseContract(revision));
        diffSummary = {
          initial: false,
          securityRelevant: diff.securityRelevant,
          itemsAdded: diff.itemsAdded.length,
          itemsRemoved: diff.itemsRemoved.length,
          sensitivityChanged: diff.sensitivityChanged.map((c) => c.name).join(","),
          requirednessChanged: diff.requirednessChanged.map((c) => c.name).join(","),
          ...(diff.semanticsVersionChanged
            ? {
                semanticsVersionFrom: diff.semanticsVersionChanged.from,
                semanticsVersionTo: diff.semanticsVersionChanged.to,
              }
            : {}),
        };
      }
    }
    await db.query("UPDATE projects SET active_contract_revision_id = $1 WHERE id = $2", [
      revision.id,
      project.id,
    ]);
    await recordAuditEvent(db, {
      eventType: "contract.activated",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "contract.activate",
      resource: { projectId: project.id, contractRevisionId: revision.id },
      metadata: diffSummary,
    });
    return revision;
  });
}

export async function getRevision(
  ctx: AppCtx,
  projectId: string,
  revisionId: string,
): Promise<ContractRevisionRow> {
  const res = await ctx.db.query(
    "SELECT * FROM contract_revisions WHERE id = $1 AND project_id = $2",
    [revisionId, projectId],
  );
  const row = res.rows[0] as ContractRevisionRow | undefined;
  if (!row) throw notFound("Contract revision");
  return row;
}

export async function activeContractOf(
  ctx: AppCtx,
  project: ProjectRow,
): Promise<ConfigurationContract | null> {
  if (!project.active_contract_revision_id) return null;
  const row = await getRevision(ctx, project.id, project.active_contract_revision_id);
  return parseContract(row);
}

/**
 * Sensitivity classification from the effective Contract (ADR-0012): items
 * absent from the Contract default to sensitive — the safe classification.
 */
export function sensitivityOf(
  contract: ConfigurationContract | null,
  itemName: string,
): boolean {
  if (!contract) return true;
  const item = contract.items.find((i) => i.name === itemName);
  return item ? item.sensitive : true;
}

/** Default dual-phase rotation grace window (ADR-0027) when none is set. */
export const DEFAULT_ROTATION_GRACE_SECONDS = 24 * 60 * 60;
/** Hard ceiling on any rotation overlap window (ADR-0027). */
export const MAX_ROTATION_GRACE_SECONDS = 30 * 24 * 60 * 60;

/**
 * Grace window for rotating an item: the contract's advisory per-item hint
 * when present, else the default. Advisory only — never gates rotation.
 */
export function rotationGraceOf(
  contract: ConfigurationContract | null,
  itemName: string,
): number {
  const item = contract?.items.find((i) => i.name === itemName);
  return item?.rotationGraceSeconds ?? DEFAULT_ROTATION_GRACE_SECONDS;
}
