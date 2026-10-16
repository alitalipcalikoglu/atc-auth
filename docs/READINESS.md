# auth readiness contract

## Purpose

Identity and session authority for end users of the platform's applications: registration and
email verification, scrypt password login, ES256 access tokens plus rotating refresh tokens with
reuse detection, password reset, and a per-user security-event history. Out of scope by design:
MFA/WebAuthn/OIDC federation, authorization/roles (callers own that).

## Dependencies

- notify (`NOTIFY_URL`/`NOTIFY_API_KEY`), required at startup. Verification/reset emails are sent
  synchronously inside the request; a failure does not fail registration (`verificationEmailSent:
  false` in the response, logged as a warning) but does fail `/ready` (notify's own `/health` is
  checked there).
- audit (`AUDIT_URL`/`AUDIT_API_KEY`), optional, both-or-neither: forwards every recorded security
  event as `auth.<type>` (Stage 0/on).
- `atc-webhook-out` (`WEBHOOK_OUT_URL` + `WEBHOOK_OUT_API_KEY`, a publish-role key): optional,
  both-or-neither. Account, session and MFA events are published best effort from a bounded in-memory queue (500
  events, three retries, an idempotency key each) in the background; the request path never waits
  on it, and events still queued at a restart are lost (atc-stack `docs/EVENTS.md`).
- Have I Been Pwned range API (`PASSWORD_BREACH_CHECK=true`, `PASSWORD_BREACH_URL`,
  `PASSWORD_BREACH_TIMEOUT_MS`): optional external lookup when a password is set or changed
  (k-anonymity, only the first 5 hex characters of the SHA-1 leave the host). A failed or slow
  lookup lets the password through, so it never gates a request. Default off.

## Persistence

SQLite (`DB_PATH`): `users` (email `UNIQUE`), `sessions` (refresh-token hash `UNIQUE`, previous-hash
`UNIQUE` for rotation), `action_tokens` (verify/reset, hashed, single-use), `events` (per-user
security log, append-only within this service; not the same table as the central `atc-audit` service),
`outbox` (Stage 4: `id`/`at`/`payload`/`sent_at` — every row `EventStore.record()` writes into
`events` gets a matching row here, in the same transaction; a background loop drains it to the audit
service, see "Audit events" in README.md). Standard migration mechanism (`user_version`, WAL); v2
(the `outbox` table) is this service's first real schema migration since the Stage 3 mechanism was
built, applied automatically on first start against a v1 database.

## Health endpoint

`GET /health`: static `{"status":"ok"}`.

## Readiness endpoint

`GET /ready`: `db.ping()` **and** a live call to notify's `GET /health` (5 s timeout). Cached 30 s.
`503` when either fails. Read-only.

## Graceful shutdown

SIGTERM/SIGINT → stop the hourly maintenance purge → `app.close()` → stop the outbox drain loop and
attempt one last drain → close the database → exit. Unlike a buffered forwarder, a drain that fails
or times out here loses nothing — every undelivered event is already durable in `outbox` and is
picked up again by the next process's drain loop on start. Force-exit 30 s; PM2 `kill_timeout`
35 000 ms.

## Resource limits

`BODY_LIMIT` (default from env). `max_memory_restart`: 300M.

## Timeouts

`NOTIFY_TIMEOUT_MS` (default 5000): the synchronous call to notify on registration/verification
resend/password-forgot. No other outbound timeouts besides the shared `AuditClient`'s (5 s per
attempt, see below).

## Retry policy

None for the notify call (one attempt; failure degrades gracefully as described above, it is not
retried within the request). The audit-forwarding outbox drain retries a batch up to 6 times with
backoff to 30 s per drain tick (same `AuditClient` retry policy every service uses), and — unlike a
buffered forwarder — an undelivered row is retried again on every future tick and every future
process start until it is acknowledged, not just within one drain attempt. Delivery is
at-least-once: a crash between a successful response and marking the row sent resends it, with the
same id, next tick; the audit service's `UNIQUE(source, client_id)` makes that resend a no-op there.

## Idempotency

Registration is guarded by the `users.email` `UNIQUE` constraint (a race between two concurrent
registrations for the same email is resolved by the database, not by an application-level check —
the TOCTOU check before hashing is a fast-path only). Refresh-token rotation is the safety-critical
idempotency case: presenting an already-rotated (previous) token is treated as **reuse**, not
retried as if idempotent — it revokes the whole session and is recorded as a
`session.reuse_detected` failure event. Action tokens (verify/reset) are single-use, enforced by a
conditional `UPDATE ... WHERE used_at IS NULL`.

`POST /v1/users` and `POST /v1/users/:id/anonymize` accept an optional `Idempotency-Key` header
(`@atc-web/atc-service-core/idempotency`, v1.30): a repeat with the same key, caller and body replays
the stored 2xx answer with `Idempotent-Replayed: true`; the same key with another body is
`409 IDEMPOTENCY_MISMATCH`. Routes that answer with tokens, TOTP secrets or recovery codes never
opt in, so a stored answer can never leak a secret.

## Backup

Users, sessions (for controlled revocation on restore — an old backup's sessions are still valid
tokens until their natural expiry), the per-user event history, and `outbox` (an in-flight backup
can catch undelivered rows mid-flight; restoring them just means they get (re-)delivered after
restore, which is safe — see "Audit events" in README.md for why a resend is a no-op on the audit
side).

## Restore

Restore the database and the JWT signing key files (`JWT_PRIVATE_KEY_PATH`, and
`JWT_PREVIOUS_PUBLIC_KEY_PATH` if a rotation was in progress) together — restoring the database with
a different signing key invalidates every outstanding access token immediately (all `kid`s become
unknown).

## Metrics

`GET /metrics`: `auth_users{status}` and `auth_sessions_active` are computed from the database at
request time (durable); process uptime is, unavoidably, process-local.

## Logging

Fastify's default request logging (`requestIdHeader: 'x-request-id'`, already accepted
unconditionally from any caller — see OBSERVABILITY.md's trust-boundary note: this is an internal
service, reached only from the gateway, console, or another backend). Redacts `authorization`.

## Tracing

Accepts an inbound `X-Request-Id` unconditionally and logs it on every line via Fastify's default
request logging. Also parses an inbound `traceparent` via `@atc-web/atc-service-core`'s
`registerRequestContext`, trust-gated on `TRUST_PROXY` (same boundary as `X-Forwarded-*`): trusted,
the caller's trace-id is continued with a fresh span-id; untrusted or malformed, a fresh trace is
started. Both `traceId`/`spanId` are logged on every request line. Its own call to `atc-notify`
(`src/domain/mailer.js`) explicitly propagates the active trace
(`RequestContext#propagationHeaders()`); this is the one internal call site that does — see
[OBSERVABILITY.md](../../atc-stack/docs/OBSERVABILITY.md). The audit events this service forwards do
**not** carry a request id — `EventStore`'s per-user security-event schema has no such column today
(`src/store/event-store.js`), so correlating a forwarded audit event back to the specific inbound
HTTP request that caused it is not yet possible; only auth's own log line for that request carries
the id.

## Security model

Passwords: scrypt, cost configurable (`SCRYPT_LOG_N`, default 15, min 14). Login against an unknown
email burns CPU at the **same** configured cost as a real check, since Stage 0
(`PasswordHasher.dummyHash(logN)`), closing a timing side-channel that previously used a hardcoded
lower cost regardless of configuration. Refresh tokens: opaque, only their SHA-256 hash stored,
rotated on every use, reuse of a superseded token revokes the whole session. Action tokens: hashed,
single-use, issuing a new one invalidates earlier ones of the same purpose. Account lockout after
`LOGIN_MAX_FAILURES` (default 10) within `LOGIN_LOCKOUT_MIN` (default 15). JWT: ES256, `kid` from
the key's own RFC 7638 thumbprint; `JWT_PREVIOUS_PUBLIC_KEY_PATH` lets a rotated signing key's
tokens keep verifying during the overlap window while new tokens are signed with the current key.
API keys (`id:secret[:role[:proxy]]`) compared in constant time. Stage 4 narrowed two things that
were previously unconditional for any valid key: a `role` (`read`/`write`/`readwrite`, default
`readwrite`) gates only `POST /v1/users`, `PATCH /v1/users/:id` and `DELETE /v1/users/:id` — every
other route needs no particular role, since it proxies an end user's own action rather than being
back-office administration; and `X-Client-IP` is now trusted only from a key carrying the `proxy`
flag (`ApiKeyAuth.isProxyTrusted`) — every other key gets the socket's own peer address regardless
of what it sends in that header, closing the "any caller with a valid key can assert an arbitrary
client IP" gap this section used to document as a known limitation. A key deployed before Stage 4
(plain `id:secret`) keeps its full `readwrite` access unchanged, but does *not* gain `proxy` trust
automatically — see README.md's upgrade note.

## Scaling model

**B — single-node stateful.** One process, one SQLite file; the audit-forwarding buffer and the
Fastify rate limiter are per-instance.

## Single-node / multi-node guarantees

One process per database file. `UNIQUE` constraints (email, token hashes) make the *data* correct
even under concurrent requests within that one process; running two processes against the same
file is not the supported or tested deployment model.

## Known failure modes

- notify down at registration time: the user account is still created, verification email is not
  sent, the response says so explicitly; `/ready` goes red so an operator notices notify is down
  even though auth itself is otherwise fine.
- audit down while forwarding is configured: security events queue in the in-memory buffer and are
  dropped, oldest first, past 5000 buffered; nothing about login/session behaviour itself degrades.
- Process killed without SIGTERM mid-transaction: SQLite's own transaction guarantee prevents a
  half-written row; any security event whose `onRecord` fired inside that same transaction (several
  domain methods record the event as part of the same `BEGIN IMMEDIATE` as the state change) is
  only in the in-memory forwarder buffer at that point and is lost if the process dies before the
  next flush — the local `events` table row itself, once the transaction committed, is durable.
- Signing-key file lost without a backup: every previously issued access token becomes
  unverifiable; refresh tokens still work once a new key is provisioned (they are opaque, not JWTs).
