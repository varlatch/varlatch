// SPDX-License-Identifier: AGPL-3.0-or-later
/** Commit-ordered audit positions. The transactional counter row is locked
 * until the inserting transaction commits, so no visible higher position
 * can overtake an uncommitted lower one. This deliberately serializes audit
 * writers; unlike a sequence, positions cannot be skipped by late commits.
 * The trigger covers every INSERT, not just the TypeScript helper. */
export const sql = /* sql */ `
ALTER TABLE audit_events ADD COLUMN event_order bigint;
WITH numbered AS (
  SELECT id, row_number() OVER (ORDER BY occurred_at, id) AS n FROM audit_events
)
UPDATE audit_events e SET event_order = numbered.n FROM numbered WHERE e.id = numbered.id;
ALTER TABLE audit_events ALTER COLUMN event_order SET NOT NULL;
CREATE UNIQUE INDEX audit_events_order_idx ON audit_events(event_order);
CREATE INDEX audit_events_org_order_idx ON audit_events(organization_id, event_order);
CREATE TABLE audit_position (singleton boolean PRIMARY KEY CHECK (singleton), value bigint NOT NULL);
INSERT INTO audit_position VALUES (true, (SELECT coalesce(max(event_order),0) FROM audit_events));
CREATE FUNCTION assign_audit_position() RETURNS trigger LANGUAGE plpgsql
SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  UPDATE public.audit_position SET value = value + 1 WHERE singleton RETURNING value INTO NEW.event_order;
  RETURN NEW;
END $$;
CREATE TRIGGER audit_position_insert BEFORE INSERT ON audit_events
FOR EACH ROW EXECUTE FUNCTION assign_audit_position();
ALTER TABLE webhooks ADD COLUMN cursor_order bigint NOT NULL DEFAULT 0;
UPDATE webhooks w SET cursor_order = e.event_order FROM audit_events e WHERE e.id = w.cursor_event_id;
ALTER TABLE sync_cursor ADD COLUMN cursor_order bigint NOT NULL DEFAULT 0;
-- Re-scan existing triggers once after migration; delivery is convergent.
-- Old unkeyed hashes expose low-entropy values. Invalidate this retry cache.
DELETE FROM idempotency_keys;
DO $$ BEGIN
  IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'varlatchd_runtime') THEN
    REVOKE ALL ON audit_position FROM varlatchd_runtime;
  END IF;
END $$;
`;
