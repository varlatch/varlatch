// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Optional per-credential lifetime limits: expires_at already exists; this
 * adds an optional use budget. max_uses = NULL means unlimited (today's
 * behavior); use_count is only advanced for budgeted credentials so the
 * authentication hot path stays read-only for everything else.
 */
export const sql = /* sql */ `
ALTER TABLE credentials
  ADD COLUMN max_uses INTEGER CHECK (max_uses > 0),
  ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0;
`;
