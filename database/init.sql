CREATE TABLE IF NOT EXISTS operations (
    id uuid PRIMARY KEY,
    actor varchar(64) NOT NULL,
    action varchar(20) NOT NULL CHECK (action IN ('create','update','delete')),
    target varchar(100) NOT NULL,
    status varchar(20) NOT NULL CHECK (status IN ('pending','succeeded','failed','uncertain')),
    created_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz
);
CREATE INDEX IF NOT EXISTS operations_created_idx ON operations(created_at DESC);
