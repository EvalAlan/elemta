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
-- A user's own maximum age for mail in this folder. Zero leaves the
-- administrator's class limits in effect, or keeps mail when there is none.
ALTER TABLE mailbox_folders ADD COLUMN IF NOT EXISTS retention_days INTEGER NOT NULL DEFAULT 0;
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
-- Protocols the account's owner turned off for themselves (security.go).
ALTER TABLE mailbox_security ADD COLUMN IF NOT EXISTS protocols_off text[] NOT NULL DEFAULT '{}';
CREATE TABLE IF NOT EXISTS mailbox_app_passwords (
 id bigserial PRIMARY KEY,
 account text NOT NULL REFERENCES mailbox_accounts(id) ON DELETE CASCADE,
 name text NOT NULL, hash text NOT NULL UNIQUE,
 created timestamptz NOT NULL DEFAULT now(), last_used timestamptz
);
CREATE INDEX IF NOT EXISTS mailbox_app_passwords_account ON mailbox_app_passwords(account);

-- Grants refer to immutable directory identities. Reusing an address must
-- not grant the new owner access to someone else's retained mailbox.
CREATE TABLE IF NOT EXISTS mailbox_shares (
 mailbox text NOT NULL REFERENCES mailbox_accounts(id) ON DELETE CASCADE,
 member text NOT NULL REFERENCES mailbox_accounts(id) ON DELETE CASCADE,
 can_send boolean NOT NULL DEFAULT false,
 PRIMARY KEY(mailbox,member),
 CHECK (mailbox <> member)
);
CREATE INDEX IF NOT EXISTS mailbox_shares_member ON mailbox_shares(member);

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

-- Addressing beyond directory accounts (addressing.go): domain aliases and
-- catch-alls, and distribution lists. List members are addresses, local or
-- external; mailbox_list_sent remembers which messages a list has already
-- sent on, so an LMTP retry doesn't send them again.
CREATE TABLE IF NOT EXISTS mailbox_domain_routes (
 domain text PRIMARY KEY, alias_of text, catch_all text,
 updated timestamptz NOT NULL DEFAULT now()
);
-- One row per message body key version ever used; a key is checked against its
-- fingerprint at start (body_crypto.go).
CREATE TABLE IF NOT EXISTS mailbox_body_keys (
 version text PRIMARY KEY, fingerprint text NOT NULL,
 added timestamptz NOT NULL DEFAULT now()
);
-- A domain that isn't active; no row means active (domain_status.go).
CREATE TABLE IF NOT EXISTS mailbox_domain_status (
 domain text PRIMARY KEY, status text NOT NULL CHECK (status IN ('suspended','disabled')),
 updated timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS mailbox_lists (
 address text PRIMARY KEY, name text NOT NULL DEFAULT '', description text NOT NULL DEFAULT '',
 owner text NOT NULL DEFAULT '', posting text NOT NULL DEFAULT 'anyone',
 updated timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS mailbox_list_members (
 list text NOT NULL REFERENCES mailbox_lists(address) ON DELETE CASCADE,
 member text NOT NULL, PRIMARY KEY(list, member)
);
CREATE INDEX IF NOT EXISTS mailbox_list_members_member ON mailbox_list_members(member);
CREATE TABLE IF NOT EXISTS mailbox_list_sent (
 list text NOT NULL, key text NOT NULL, expires timestamptz NOT NULL, PRIMARY KEY(list, key)
);
CREATE INDEX IF NOT EXISTS mailbox_list_sent_expiry ON mailbox_list_sent(expires);

-- Retention and legal hold (retention.go). added is when a message reached
-- its folder, which Trash and Junk retention count from. It is added
-- without a default and given one after: a volatile default on ADD COLUMN
-- rewrites the whole table under an exclusive lock, which on a large
-- mailbox store would stall delivery for the length of the upgrade. Rows
-- that predate it have no value, and retention uses their own date.
-- mailbox_held keeps what a user on legal hold deleted, out of sight of
-- every protocol, with its body kept alive (the body cleanup treats a held
-- body as referenced).
ALTER TABLE mailbox_messages ADD COLUMN IF NOT EXISTS added timestamptz;
ALTER TABLE mailbox_messages ALTER COLUMN added SET DEFAULT now();
CREATE TABLE IF NOT EXISTS mailbox_held (
 id bigserial PRIMARY KEY, account text NOT NULL, folder text NOT NULL,
 body text NOT NULL REFERENCES mailbox_bodies(key), flags text[] NOT NULL DEFAULT '{}',
 internal_date timestamptz NOT NULL, held_at timestamptz NOT NULL DEFAULT now(), reason text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS mailbox_held_account ON mailbox_held(account);
CREATE INDEX IF NOT EXISTS mailbox_held_body ON mailbox_held(body);

-- Administrative changes, append-only (mailpolicy.AuditEntry). Kept here
-- rather than in the dashboard's logs so that it survives restarts and log
-- rotation and every dashboard replica and the CLI write to one place.
CREATE TABLE IF NOT EXISTS mailbox_audit (
    id bigserial PRIMARY KEY,
    at timestamptz NOT NULL DEFAULT now(),
    actor text NOT NULL,
    source text NOT NULL DEFAULT '',
    client text NOT NULL DEFAULT '',
    action text NOT NULL,
    target text NOT NULL DEFAULT '',
    domain text NOT NULL DEFAULT '',
    detail text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS mailbox_audit_domain ON mailbox_audit(domain, id);

-- Each account's busy times, published by the webmail whenever its
-- calendar changes (freebusy.go), so colleagues scheduling a meeting can
-- see when someone is free without reading their calendar.
CREATE TABLE IF NOT EXISTS mailbox_freebusy (
    account text PRIMARY KEY,
    address text NOT NULL,
    window_from timestamptz NOT NULL,
    window_to timestamptz NOT NULL,
    busy jsonb NOT NULL,
    updated timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS mailbox_freebusy_address ON mailbox_freebusy(address);

-- Short-lived tokens that let an administrator open an account's mailbox in
-- the webmail without its password (admin_access.go). Only the hash is kept.
CREATE TABLE IF NOT EXISTS mailbox_admin_access (
    token_hash text PRIMARY KEY,
    account text NOT NULL,
    actor text NOT NULL,
    created timestamptz NOT NULL DEFAULT now(),
    expires timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS mailbox_admin_access_expires ON mailbox_admin_access(expires);
-- The highest quota warning threshold (percent) the account was last told
-- about (quota_warn.go); 0 when none.
ALTER TABLE mailbox_accounts ADD COLUMN IF NOT EXISTS quota_warned INTEGER NOT NULL DEFAULT 0;
-- Each user's allowed and blocked senders (sender_rules.go): an address,
-- or @domain.
CREATE TABLE IF NOT EXISTS mailbox_sender_rules (
    account text NOT NULL REFERENCES mailbox_accounts(id) ON DELETE CASCADE,
    entry text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('allow', 'block')),
    created timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account, entry)
);
-- Senders each user put in an inbox category (categories.go): an address,
-- or @domain, which covers its subdomains too.
CREATE TABLE IF NOT EXISTS mailbox_category_rules (
    account text NOT NULL REFERENCES mailbox_accounts(id) ON DELETE CASCADE,
    entry text NOT NULL,
    category text NOT NULL CHECK (category IN ('primary', 'social', 'promotions', 'updates', 'forums')),
    created timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account, entry)
);
-- Mail people moved in or out of Junk, waiting for Rspamd to learn from it
-- (spam_learn.go). Rows stay a day after learning, for the daily limit.
CREATE TABLE IF NOT EXISTS mailbox_spam_feedback (
    account text NOT NULL REFERENCES mailbox_accounts(id) ON DELETE CASCADE,
    body text NOT NULL,
    class text NOT NULL CHECK (class IN ('spam', 'ham')),
    created timestamptz NOT NULL DEFAULT now(),
    not_before timestamptz NOT NULL DEFAULT now(),
    learned timestamptz,
    PRIMARY KEY (account, body)
);
CREATE INDEX IF NOT EXISTS mailbox_spam_feedback_due ON mailbox_spam_feedback(not_before) WHERE learned IS NULL;
-- Who can see whose calendar (calendar_sharing.go).
CREATE TABLE IF NOT EXISTS mailbox_calendar_shares (
    owner text NOT NULL REFERENCES mailbox_accounts(id) ON DELETE CASCADE,
    member text NOT NULL REFERENCES mailbox_accounts(id) ON DELETE CASCADE,
    level text NOT NULL CHECK (level IN ('view', 'edit', 'delegate')),
    created timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (owner, member)
);
CREATE INDEX IF NOT EXISTS mailbox_calendar_shares_member ON mailbox_calendar_shares(member);

-- Rooms and equipment people book (booking.go). The account is an ordinary
-- one, so removing this row leaves its mail and calendar in place.
CREATE TABLE IF NOT EXISTS mailbox_resources (
    account text PRIMARY KEY REFERENCES mailbox_accounts(id) ON DELETE CASCADE,
    address text NOT NULL,
    name text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('room', 'equipment')),
    location text NOT NULL DEFAULT '',
    capacity integer NOT NULL DEFAULT 0,
    booking text NOT NULL CHECK (booking IN ('auto', 'manual'))
);
CREATE INDEX IF NOT EXISTS mailbox_resources_domain ON mailbox_resources(split_part(address, '@', 2));

-- Passkeys (passkey.go). The credential is the WebAuthn library's own record:
-- public key, counters and flags, and nothing that can sign.
CREATE TABLE IF NOT EXISTS mailbox_passkeys (
    id bigserial PRIMARY KEY,
    account text NOT NULL REFERENCES mailbox_accounts(id) ON DELETE CASCADE,
    credential_id bytea NOT NULL UNIQUE,
    credential jsonb NOT NULL,
    name text NOT NULL,
    host text NOT NULL,
    created timestamptz NOT NULL DEFAULT now(),
    last_used timestamptz
);
CREATE INDEX IF NOT EXISTS mailbox_passkeys_account ON mailbox_passkeys(account);
-- A ceremony between its two requests, which may reach different replicas. The
-- account is empty for a sign-in, which doesn't know whose it is yet.
CREATE TABLE IF NOT EXISTS mailbox_passkey_challenges (
    id text PRIMARY KEY,
    account text NOT NULL,
    session jsonb NOT NULL,
    expires timestamptz NOT NULL
);
-- What a passkey sign-in presents in place of a password. Only the hash is kept.
CREATE TABLE IF NOT EXISTS mailbox_session_tokens (
    token_hash text PRIMARY KEY,
    account text NOT NULL REFERENCES mailbox_accounts(id) ON DELETE CASCADE,
    passkey bigint NOT NULL REFERENCES mailbox_passkeys(id) ON DELETE CASCADE,
    expires timestamptz NOT NULL,
    absolute_expires timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS mailbox_session_tokens_account ON mailbox_session_tokens(account);

-- PGP keys (pgp.go). The private key is locked with a passphrase that never
-- reaches this server.
CREATE TABLE IF NOT EXISTS mailbox_pgp_keys (
    account text PRIMARY KEY REFERENCES mailbox_accounts(id) ON DELETE CASCADE,
    address text NOT NULL,
    domain text NOT NULL,
    wkd_hash text NOT NULL,
    fingerprint text NOT NULL,
    public_key text NOT NULL,
    private_key text NOT NULL,
    created timestamptz NOT NULL DEFAULT now()
);
-- Whether the key is in the public Web Key Directory. Colleagues find it either way.
ALTER TABLE mailbox_pgp_keys ADD COLUMN IF NOT EXISTS published boolean NOT NULL DEFAULT true;
CREATE INDEX IF NOT EXISTS mailbox_pgp_keys_address ON mailbox_pgp_keys(address);
CREATE INDEX IF NOT EXISTS mailbox_pgp_keys_wkd ON mailbox_pgp_keys(domain, wkd_hash);
CREATE TABLE IF NOT EXISTS mailbox_pgp_pins (
    account text NOT NULL REFERENCES mailbox_accounts(id) ON DELETE CASCADE,
    address text NOT NULL,
    fingerprint text NOT NULL,
    PRIMARY KEY (account, address)
);
-- Web Push (push.go). One VAPID key pair for the whole service, made by
-- whichever replica first needs it.
CREATE TABLE IF NOT EXISTS mailbox_push_keys (
    id integer PRIMARY KEY CHECK (id = 1),
    private_key text NOT NULL,
    public_key text NOT NULL,
    created timestamptz NOT NULL DEFAULT now()
);
-- A browser that asked to be notified. The endpoint belongs to one browser
-- profile, so signing in as someone else there moves it to them.
CREATE TABLE IF NOT EXISTS mailbox_push_subscriptions (
    id bigserial PRIMARY KEY,
    account text NOT NULL REFERENCES mailbox_accounts(id) ON DELETE CASCADE,
    endpoint text NOT NULL UNIQUE,
    p256dh text NOT NULL,
    auth text NOT NULL,
    label text NOT NULL DEFAULT '',
    mail text NOT NULL DEFAULT 'all',
    reminders boolean NOT NULL DEFAULT true,
    preview boolean NOT NULL DEFAULT true,
    contact text NOT NULL DEFAULT '',
    created timestamptz NOT NULL DEFAULT now(),
    last_sent timestamptz,
    failures integer NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS mailbox_push_subscriptions_account ON mailbox_push_subscriptions(account);
-- Upcoming event reminders, published by the webmail (which alone can read
-- and expand calendars) and sent from here when they come due.
CREATE TABLE IF NOT EXISTS mailbox_push_reminders (
    account text NOT NULL REFERENCES mailbox_accounts(id) ON DELETE CASCADE,
    key text NOT NULL,
    fire_at timestamptz NOT NULL,
    starts timestamptz NOT NULL,
    title text NOT NULL,
    body text NOT NULL DEFAULT '',
    url text NOT NULL DEFAULT '',
    sent boolean NOT NULL DEFAULT false,
    PRIMARY KEY (account, key)
);
CREATE INDEX IF NOT EXISTS mailbox_push_reminders_due ON mailbox_push_reminders(fire_at) WHERE NOT sent;
-- A folder's MODSEQ moves on every change to it. The notification wakes the
-- IMAP sessions idling on it, on every mailbox server (notify.go), instead
-- of each asking the database once a second.
CREATE OR REPLACE FUNCTION mailbox_folder_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_notify('elemta_folder', NEW.id::text);
  RETURN NULL;
END
$$;
CREATE OR REPLACE TRIGGER mailbox_folder_changed AFTER UPDATE OF modseq ON mailbox_folders
  FOR EACH ROW WHEN (NEW.modseq IS DISTINCT FROM OLD.modseq) EXECUTE FUNCTION mailbox_folder_changed();
-- Scheduled send and snooze (scheduled.go). Each row names a message by its
-- place, and the foreign key is the point: a move is an insert and a delete,
-- so deleting the message or moving it out of Scheduled or Snoozed, from any
-- client, removes the row and cancels it. claimed_until stops two mailbox
-- servers acting on the same row; a claim that outlives its server lapses.
CREATE TABLE IF NOT EXISTS mailbox_scheduled_sends (
    folder bigint NOT NULL,
    uid bigint NOT NULL,
    account text NOT NULL REFERENCES mailbox_accounts(id) ON DELETE CASCADE,
    send_at timestamptz NOT NULL,
    mail_from text NOT NULL,
    rcpts text[] NOT NULL,
    attempts integer NOT NULL DEFAULT 0,
    last_error text NOT NULL DEFAULT '',
    claimed_until timestamptz,
    PRIMARY KEY (folder, uid),
    FOREIGN KEY (folder, uid) REFERENCES mailbox_messages(folder, uid) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS mailbox_scheduled_sends_due ON mailbox_scheduled_sends(send_at);
CREATE INDEX IF NOT EXISTS mailbox_scheduled_sends_account ON mailbox_scheduled_sends(account);
CREATE TABLE IF NOT EXISTS mailbox_snoozes (
    folder bigint NOT NULL,
    uid bigint NOT NULL,
    account text NOT NULL REFERENCES mailbox_accounts(id) ON DELETE CASCADE,
    until timestamptz NOT NULL,
    return_to text NOT NULL,
    claimed_until timestamptz,
    PRIMARY KEY (folder, uid),
    FOREIGN KEY (folder, uid) REFERENCES mailbox_messages(folder, uid) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS mailbox_snoozes_due ON mailbox_snoozes(until);
CREATE INDEX IF NOT EXISTS mailbox_snoozes_account ON mailbox_snoozes(account);
