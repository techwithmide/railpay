ALTER TABLE merchants ADD COLUMN IF NOT EXISTS email_opt_out boolean NOT NULL DEFAULT false;
ALTER TABLE intents ADD COLUMN IF NOT EXISTS customer_email text NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS emails (
    id text PRIMARY KEY,
    key text NOT NULL UNIQUE,
    kind text NOT NULL,
    to_address text NOT NULL,
    merchant_id text NOT NULL REFERENCES merchants(id),
    intent_id text NOT NULL,
    data jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    attempts int NOT NULL DEFAULT 0,
    next_attempt timestamptz NOT NULL,
    sent_at timestamptz,
    dead boolean NOT NULL DEFAULT false,
    last_error text NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS emails_due ON emails (next_attempt) WHERE sent_at IS NULL AND NOT dead;
CREATE INDEX IF NOT EXISTS emails_merchant ON emails (merchant_id, created_at DESC);