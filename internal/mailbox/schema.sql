CREATE SEQUENCE IF NOT EXISTS mailbox_uidvalidity MINVALUE 1 MAXVALUE 4294967295 NO CYCLE;
CREATE TABLE IF NOT EXISTS mailbox_accounts (
 id TEXT PRIMARY KEY, address TEXT NOT NULL,
 quota_bytes BIGINT NOT NULL DEFAULT 0, used_bytes BIGINT NOT NULL DEFAULT 0,
 writable BOOLEAN NOT NULL DEFAULT TRUE
);
ALTER TABLE mailbox_accounts DROP CONSTRAINT IF EXISTS mailbox_accounts_address_key;
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
