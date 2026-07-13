-- Runtime prerequisites owned by the privileged, checksummed migration path.
-- Application roles must never be responsible for installing database code.

CREATE EXTENSION IF NOT EXISTS vector;

COMMENT ON EXTENSION vector IS
    'PgVector support installed by Dash schema migration before runtime startup';
