CREATE TABLE IF NOT EXISTS accounts (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    login text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    role text NOT NULL CHECK (role IN ('requester', 'specialist'))
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    account_id bigint NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_account_idx ON sessions(account_id);

CREATE TABLE IF NOT EXISTS tickets (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    author_id bigint NOT NULL REFERENCES accounts(id),
    title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    description text NOT NULL CHECK (char_length(description) BETWEEN 1 AND 4000),
    status text NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'in_progress', 'closed')),
    assignee_id bigint REFERENCES accounts(id),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    CHECK ((status = 'new' AND assignee_id IS NULL) OR
           (status IN ('in_progress', 'closed') AND assignee_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS tickets_author_idx ON tickets(author_id, id DESC);
CREATE INDEX IF NOT EXISTS tickets_assignee_idx ON tickets(assignee_id, id DESC);
