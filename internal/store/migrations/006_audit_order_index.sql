-- The audit listing now orders by id, because a wall clock can step backwards
-- and reorder events that already happened. The composite index was built for
-- the previous ordering, so a filtered listing fell back to walking the primary
-- key backwards and discarding non-matching rows: measured on 400k rows, a
-- filter matching 0.5% of them went from 0.09ms to 1.57ms, and the cost grows
-- with the table and with how rare the filtered value is.
CREATE INDEX IF NOT EXISTS idx_audit_realm_event_id ON audit_events(realm_id, event_type, id DESC);

-- Superseded by the index above; nothing orders by occurred_at any more. The
-- separate idx_audit_occurred stays: the 365-day retention delete uses it.
DROP INDEX IF EXISTS idx_audit_realm_event;
