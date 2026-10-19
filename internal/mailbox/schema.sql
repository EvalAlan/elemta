CREATE SEQUENCE IF NOT EXISTS mailbox_uidvalidity MINVALUE 1 MAXVALUE 4294967295 NO CYCLE;
CREATE TABLE IF NOT EXISTS mailbox_accounts (
 id TEXT PRIMARY KEY, address TEXT NOT NULL,
 quota_bytes BIGINT NOT NULL DEFAULT 0, used_bytes BIGINT NOT NULL DEFAULT 0,
 reserved_bytes BIGINT NOT NULL DEFAULT 0,
 writable BOOLEAN NOT NULL DEFAULT TRUE
);
ALTER TABLE mailbox_accounts DROP CONSTRAINT IF EXISTS mailbox_accounts_address_key;
ALTER TABLE mailbox_accounts ADD COLUMN IF NOT EXISTS reserved_bytes BIGINT NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS mailbox_folders (
 id BIGSERIAL PRIMARY KEY, account TEXT NOT NULL REFERENCES mailbox_accounts(id),
 name TEXT NOT NULL, uidvalidity BIGINT NOT NULL DEFAULT nextval('mailbox_uidvalidity'),
 next_uid BIGINT NOT NULL DEFAULT 1, modseq BIGINT NOT NULL DEFAULT 1,
 subscribed BOOLEAN NOT NULL DEFAULT TRUE, UNIQUE(account,name)
);
CREATE TABLE IF NOT EXISTS mailbox_bodies (
 key TEXT PRIMARY KEY, size BIGINT NOT NULL, checksum TEXT NOT NULL,
 store TEXT NOT NULL,
 state TEXT NOT NULL DEFAULT 'staging', expires TIMESTAMPTZ NOT NULL DEFAULT now()+interval '10 minutes'
);
ALTER TABLE mailbox_bodies ADD COLUMN IF NOT EXISTS store TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS mailbox_messages (
 folder BIGINT NOT NULL REFERENCES mailbox_folders(id) ON DELETE CASCADE,
 uid BIGINT NOT NULL, body TEXT NOT NULL REFERENCES mailbox_bodies(key),
 flags TEXT[] NOT NULL DEFAULT '{}', internal_date TIMESTAMPTZ NOT NULL,
 modseq BIGINT NOT NULL, PRIMARY KEY(folder,uid)
);
CREATE INDEX IF NOT EXISTS mailbox_messages_body ON mailbox_messages(body);
CREATE INDEX IF NOT EXISTS mailbox_bodies_expiry ON mailbox_bodies(state,expires);
CREATE TABLE IF NOT EXISTS mailbox_deliveries (
 account TEXT NOT NULL REFERENCES mailbox_accounts(id), token TEXT NOT NULL,
 checksum TEXT NOT NULL, uidvalidity BIGINT NOT NULL, uid BIGINT NOT NULL,
 PRIMARY KEY(account,token)
);
CREATE TABLE IF NOT EXISTS mailbox_changes (
 id BIGSERIAL PRIMARY KEY, folder BIGINT NOT NULL, modseq BIGINT NOT NULL,
 kind TEXT NOT NULL, uid BIGINT NOT NULL, created TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS mailbox_changes_folder ON mailbox_changes(folder,id);
CREATE TABLE IF NOT EXISTS mailbox_auth_failures (
 key TEXT PRIMARY KEY, attempts INTEGER NOT NULL DEFAULT 1,
 expires TIMESTAMPTZ NOT NULL DEFAULT now()+interval '15 minutes'
);
CREATE INDEX IF NOT EXISTS mailbox_auth_failures_expiry ON mailbox_auth_failures(expires);
CREATE TABLE IF NOT EXISTS mailbox_summaries (
 body TEXT PRIMARY KEY REFERENCES mailbox_bodies(key) ON DELETE CASCADE,
 version INTEGER NOT NULL, data BYTEA NOT NULL,
 base_subject TEXT NOT NULL DEFAULT '', sent TIMESTAMPTZ,
 sender TEXT NOT NULL DEFAULT '', recipient TEXT NOT NULL DEFAULT '', cc TEXT NOT NULL DEFAULT '',
 display_from TEXT NOT NULL DEFAULT '', display_to TEXT NOT NULL DEFAULT '',
 message_id TEXT NOT NULL DEFAULT '', refs TEXT[] NOT NULL DEFAULT '{}'
);
ALTER TABLE mailbox_folders ADD COLUMN IF NOT EXISTS journal_floor BIGINT NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS mailbox_changes_modseq ON mailbox_changes(folder,modseq);
ALTER TABLE mailbox_summaries ADD COLUMN IF NOT EXISTS reply BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE mailbox_summaries ADD COLUMN IF NOT EXISTS hdr_from TEXT NOT NULL DEFAULT '';
ALTER TABLE mailbox_summaries ADD COLUMN IF NOT EXISTS hdr_to TEXT NOT NULL DEFAULT '';
ALTER TABLE mailbox_summaries ADD COLUMN IF NOT EXISTS hdr_cc TEXT NOT NULL DEFAULT '';
ALTER TABLE mailbox_summaries ADD COLUMN IF NOT EXISTS hdr_bcc TEXT NOT NULL DEFAULT '';
ALTER TABLE mailbox_summaries ADD COLUMN IF NOT EXISTS hdr_subject TEXT NOT NULL DEFAULT '';
ALTER TABLE mailbox_summaries ADD COLUMN IF NOT EXISTS body_tsv TSVECTOR;
ALTER TABLE mailbox_summaries ADD COLUMN IF NOT EXISTS hdr_content_type TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS mailbox_summaries_body_tsv ON mailbox_summaries USING GIN (body_tsv);
CREATE TABLE IF NOT EXISTS mailbox_sieve_scripts (
 account TEXT NOT NULL REFERENCES mailbox_accounts(id), name TEXT NOT NULL,
 script TEXT NOT NULL, active BOOLEAN NOT NULL DEFAULT FALSE,
 updated TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(account,name)
);
CREATE UNIQUE INDEX IF NOT EXISTS mailbox_sieve_one_active ON mailbox_sieve_scripts(account) WHERE active;
CREATE TABLE IF NOT EXISTS mailbox_sieve_sent (
 account TEXT NOT NULL REFERENCES mailbox_accounts(id), key TEXT NOT NULL,
 expires TIMESTAMPTZ NOT NULL, PRIMARY KEY(account,key)
);
CREATE INDEX IF NOT EXISTS mailbox_sieve_sent_expiry ON mailbox_sieve_sent(expires);
ALTER TABLE mailbox_bodies ADD COLUMN IF NOT EXISTS orphaned_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS mailbox_pop3_leases (
 account text PRIMARY KEY REFERENCES mailbox_accounts(id) ON DELETE CASCADE,
 owner text NOT NULL,
 expires timestamptz NOT NULL
);

-- Account security (security.go): two-step verification and app passwords.
CREATE TABLE IF NOT EXISTS mailbox_security (
 account text PRIMARY KEY REFERENCES mailbox_accounts(id) ON DELETE CASCADE,
 totp_secret text, totp_pending text, totp_pending_at timestamptz,
 totp_last_step bigint NOT NULL DEFAULT 0,
 app_passwords_required boolean NOT NULL DEFAULT false,
 recovery_codes text[] NOT NULL DEFAULT '{}'
);
ALTER TABLE mailbox_security ADD COLUMN IF NOT EXISTS totp_pending_at timestamptz;
CREATE TABLE IF NOT EXISTS mailbox_app_passwords (
 id bigserial PRIMARY KEY,
 account text NOT NULL REFERENCES mailbox_accounts(id) ON DELETE CASCADE,
 name text NOT NULL, hash text NOT NULL UNIQUE,
 created timestamptz NOT NULL DEFAULT now(), last_used timestamptz
);
CREATE INDEX IF NOT EXISTS mailbox_app_passwords_account ON mailbox_app_passwords(account);

-- Classes of service and per-account policy (policy.go). Accounts are keyed
-- by primary address, which is what administrators name and what the
-- directory guarantees unique; the directory ID is created lazily here and
-- would not exist yet for an account that has never logged in or received
-- mail. A class in use can't be deleted (the foreign keys refuse it).
CREATE TABLE IF NOT EXISTS mailbox_classes (
 name text PRIMARY KEY, description text NOT NULL DEFAULT '',
 settings jsonb NOT NULL DEFAULT '{}', updated timestamptz NOT NULL DEFAULT now()
);
INSERT INTO mailbox_classes(name, description) VALUES ('default', 'Applies to every account unless its domain or the account names another class') ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS mailbox_domain_policy (
 domain text PRIMARY KEY, class text NOT NULL REFERENCES mailbox_classes(name),
 updated timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS mailbox_account_policy (
 address text PRIMARY KEY, class text REFERENCES mailbox_classes(name),
 settings jsonb NOT NULL DEFAULT '{}', updated timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS mailbox_account_policy_class ON mailbox_account_policy(class);
