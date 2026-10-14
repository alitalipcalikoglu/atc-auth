import { Database as CoreDatabase } from '@atc-web/atc-service-core/db';

/** SQLite connection with schema migrations applied on open. */
export class Database extends CoreDatabase {
  static MIGRATIONS = [
    `
    CREATE TABLE users (
      id                  TEXT PRIMARY KEY,
      email               TEXT NOT NULL UNIQUE,
      name                TEXT,
      password_hash       TEXT NOT NULL,
      status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
      email_verified_at   INTEGER,
      failed_logins       INTEGER NOT NULL DEFAULT 0,
      locked_until        INTEGER,
      password_changed_at INTEGER NOT NULL,
      created_at          INTEGER NOT NULL,
      updated_at          INTEGER NOT NULL
    );

    CREATE TABLE sessions (
      id                  TEXT PRIMARY KEY,
      user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash          TEXT NOT NULL UNIQUE,
      previous_token_hash TEXT UNIQUE,
      created_at          INTEGER NOT NULL,
      last_used_at        INTEGER NOT NULL,
      expires_at          INTEGER NOT NULL,
      revoked_at          INTEGER,
      ip                  TEXT,
      user_agent          TEXT
    );
    CREATE INDEX sessions_user ON sessions (user_id, created_at DESC);
    CREATE INDEX sessions_expiry ON sessions (expires_at);

    CREATE TABLE action_tokens (
      token_hash  TEXT PRIMARY KEY,
      user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      purpose     TEXT NOT NULL CHECK (purpose IN ('verify_email', 'reset_password')),
      expires_at  INTEGER NOT NULL,
      used_at     INTEGER,
      created_at  INTEGER NOT NULL
    );
    CREATE INDEX action_tokens_user ON action_tokens (user_id, purpose);
    CREATE INDEX action_tokens_expiry ON action_tokens (expires_at);

    CREATE TABLE events (
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id  TEXT,
      type     TEXT NOT NULL,
      ip       TEXT,
      meta     TEXT,
      at       INTEGER NOT NULL
    );
    CREATE INDEX events_user ON events (user_id, at DESC);
    CREATE INDEX events_at ON events (at);
    `,
    `
    -- Transactional outbox (Stage 4): EventStore.record() inserts a row here in the same SQLite
    -- transaction as the security event it describes and whatever business mutation caused it, so
    -- the event can never be forwarded to the audit service before that transaction commits, and
    -- never exists here at all if it rolls back. "id" is a stable UUID generated once at insert and
    -- reused on every delivery attempt — audit's UNIQUE(source, client_id) makes a resend (e.g.
    -- after a crash between a successful send and "sent_at" being set) a safe no-op there, not a
    -- second record. See AuditClient's outbox mode (@atc-web/atc-service-core/audit).
    CREATE TABLE outbox (
      id       TEXT PRIMARY KEY,
      at       INTEGER NOT NULL,
      payload  TEXT NOT NULL,
      sent_at  INTEGER
    );
    CREATE INDEX outbox_pending ON outbox (at) WHERE sent_at IS NULL;
    CREATE INDEX outbox_sent ON outbox (sent_at) WHERE sent_at IS NOT NULL;
    `,
  ];
}
