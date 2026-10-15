# atc-auth

Authentication service for application backends: user accounts, scrypt passwords, short-lived ES256 access tokens, rotating refresh tokens with reuse detection, email verification and password reset, audit log. Talks to other services over HTTP only; sends email through the [atc-notify](https://github.com/alitalipcalikoglu/atc-notify) service.

Runtime dependencies: `fastify`, `@fastify/rate-limit`, `jose`. Storage is SQLite via `node:sqlite` (built into Node 22.13+). The folder is self-contained: copy it to any host with Node 22 and run.

## Run

```bash
cp .env.example .env        # fill in keys, issuer, notify settings
npm ci
npm run keygen              # writes keys/jwt-private.pem and keys/jwt-public.pem
npm run dev
```

Production with PM2 (reads `./.env` through Node's `--env-file`):

```bash
npm ci --omit=dev
pm2 start ecosystem.config.cjs
pm2 save && pm2 startup
```

Production with Docker (mount the database and key directories):

```bash
docker build -t atc-auth .
docker run -p 3002:3002 -v atc-auth-data:/data -v ./keys:/keys:ro --env-file .env atc-auth
```

Tests and type check:

```bash
npm test
npm run typecheck
```

## Model

- **Callers are trusted backends.** Every `/v1` request carries `Authorization: Bearer <API key>` from `AUTH_API_KEYS`. Browsers never talk to this service directly; your backend does. A key optionally carries a role (`read` | `write` | `readwrite`, default `readwrite`) — only `POST /v1/users`, `PATCH /v1/users/:id`, `DELETE /v1/users/:id`, `DELETE /v1/users/:id/sessions` and `DELETE /v1/users/:id/sessions/:sid` require `write`, everything else (login, refresh, password flows, …) is available to any valid key regardless of role, since those proxy an end user's own action rather than being back-office administration. Only a key carrying the `proxy` flag may forward the end user's address via `X-Client-IP` (and agent via `X-Client-User-Agent`) for the audit log; every other key gets the socket's own peer address regardless of what it sends in that header — a key minted before this option existed has neither flag nor role restriction, i.e. full `readwrite` access and no IP-forwarding trust, until you opt it in.
- **Access token**: JWT, ES256, `ACCESS_TOKEN_TTL_SEC` (default 15 min). Claims: `iss`, `aud`, `sub` (user id), `sid` (session id), `email`, `email_verified`, `iat`, `exp`, `jti`. Other services verify it locally with `GET /.well-known/jwks.json`, no call to auth needed. Use `POST /v1/auth/introspect` when you also need to know that the session has not been revoked.
- **Refresh token**: opaque 256-bit secret, stored hashed, `REFRESH_TOKEN_TTL_DAYS` absolute lifetime. Each refresh rotates it. Presenting an already-rotated token revokes the whole session (`TOKEN_REUSED`).
- **One-time links** for verification and reset are opaque tokens that expire and are single use. The service never builds pages; it puts `{token}` into `VERIFY_URL_TEMPLATE` / `RESET_URL_TEMPLATE`, which point at your frontend, and your backend forwards the token here.

## Boundaries

**Purpose:** the platform's identity provider — accounts, sessions, tokens, and the audit trail of who did what to them.

**Responsibilities:** user CRUD; password hashing and reset; session issuance and rotating refresh tokens; JWT signing and JWKS publication; email verification; per-key rate limiting on its own endpoints; forwarding auth security events to audit.

**Non-responsibilities:** auth ≠ general notification delivery — it triggers notify for verification/reset emails, it does not send them itself; auth does not decide what a caller may do once identified (that's each service's own API-key roles/scopes); it does not store business/profile data beyond what identity and session state require.

## API

Errors are JSON: `{ "error": { "code", "message", "details?" } }`. `423` and `429` carry `Retry-After`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/health`, `/ready`, `/v1/info` | Liveness; readiness (database + notify reachable, cached 30 s); service identity (version, API version, capabilities, schema version, service-core version). No auth. |
| GET | `/.well-known/jwks.json` | Public keys for local JWT verification. No auth. |
| POST | `/v1/users` | Register `{ email, password, name? }`. `201` with `user` and `verificationEmailSent`. |
| GET | `/v1/users` | List (`limit`, `cursor`) or look up `?email=`. |
| GET / PATCH / DELETE | `/v1/users/:id` | Read; update `{ name?, email?, status? }` (disabling revokes sessions; a new `email` is unverified until confirmed); hard delete. |
| GET | `/v1/users/:id/export` | Everything stored about the person (profile, sessions, events with addresses). |
| POST | `/v1/users/:id/anonymize` | Erase the person, keep the row and id. Irreversible. |
| GET / DELETE | `/v1/users/:id/sessions` | Active sessions; revoke all. |
| DELETE | `/v1/users/:id/sessions/:sid` | Revoke one session. |
| GET | `/v1/users/:id/events` | Audit log, newest first (`limit`, `before`). |
| POST | `/v1/auth/login` | `{ email, password }` → `{ user, tokens }`. With MFA on: `401 MFA_REQUIRED` with `details.mfaToken`. |
| POST | `/v1/auth/login/mfa` | `{ mfaToken, code }` (TOTP or recovery code) → `{ user, tokens }`. |
| POST | `/v1/auth/refresh` | `{ refreshToken }` → new `{ user, tokens }`. |
| POST | `/v1/auth/logout` | `{ refreshToken }` → `204`. Idempotent. |
| POST | `/v1/auth/introspect` | `{ accessToken }` → `{ active, claims?, reason? }`. |
| POST | `/v1/auth/verify-email` | `{ token }` → `{ user }`. |
| POST | `/v1/auth/verify-email/resend` | `{ email }` → `202`. Silent for unknown or verified emails and inside the per-user cooldown. |
| POST | `/v1/auth/email/change` | `{ email, password, newEmail }` → `202`. The link goes to the new address. |
| POST | `/v1/auth/email/confirm` | `{ token }` → `{ user }`. The address changes and counts as verified; the old address is told. |
| POST | `/v1/auth/password/forgot` | `{ email }` → `202`. Always accepted; silent for unknown, disabled or throttled accounts. |
| POST | `/v1/auth/password/reset` | `{ token, password }` → `{ user }`. Revokes all sessions, marks email verified. |
| POST | `/v1/auth/password/change` | Header `X-Access-Token: <jwt>`, body `{ currentPassword, newPassword }` → `204`. Keeps the current session, revokes the others. |
| POST | `/v1/auth/mfa/setup` | Header `X-Access-Token`. → `{ secret, otpauthUrl }`; MFA stays off until enabled. |
| POST | `/v1/auth/mfa/enable` | Header `X-Access-Token`, `{ code }` → `{ recoveryCodes }` (ten, shown once). |
| POST | `/v1/auth/mfa/disable` | Header `X-Access-Token`, `{ password, code }` → `204`. |
| POST | `/v1/auth/mfa/recovery-codes` | Header `X-Access-Token`, `{ code }` → new `{ recoveryCodes }`. |
| DELETE | `/v1/users/:id/mfa` | Administration: remove a user's MFA (lost device). The user is mailed. |
| GET | `/metrics` | Prometheus text: users by status, active sessions, uptime. API key required. |

Error codes: `EMAIL_TAKEN`, `WEAK_PASSWORD`, `INVALID_CREDENTIALS`, `ACCOUNT_LOCKED`, `ACCOUNT_DISABLED`, `EMAIL_NOT_VERIFIED`, `INVALID_TOKEN`, `TOKEN_REUSED`, `USER_NOT_FOUND`, `SESSION_NOT_FOUND`, `MFA_REQUIRED`, `INVALID_MFA_CODE`, `MFA_ALREADY_ENABLED`, `MFA_NOT_ENABLED`, `MFA_SETUP_REQUIRED`, `MFA_UNAVAILABLE`, `RATE_LIMITED`, `VALIDATION_FAILED`, `UNAUTHORIZED`.

### Typical flow from your backend

1. `POST /v1/users` with the sign-up form. Show "check your inbox".
2. User clicks the link in the email, lands on your frontend, which posts the token to your backend; your backend calls `POST /v1/auth/verify-email`.
3. `POST /v1/auth/login`; hand the access token to the client, keep the refresh token in an httpOnly cookie or secure storage.
4. Verify access tokens locally with the JWKS on every request. Refresh through `POST /v1/auth/refresh` before expiry.
5. On logout call `POST /v1/auth/logout` with the refresh token.

### Verifying tokens in another Node service

```js
import { createRemoteJWKSet, jwtVerify } from 'jose';
const jwks = createRemoteJWKSet(new URL('https://auth.example.com/.well-known/jwks.json'));
const { payload } = await jwtVerify(token, jwks, { issuer: 'https://auth.example.com', audience: 'shop' });
```

## Examples

Scenario walkthroughs for every feature live in [examples/](examples/README.md).

## Configuration

All settings come from environment variables and are validated at startup. See [.env.example](.env.example).

Required: `AUTH_API_KEYS`, `JWT_PRIVATE_KEY_PATH`, `JWT_ISSUER`, `JWT_AUDIENCE`, `NOTIFY_URL`, `NOTIFY_API_KEY`, `APP_NAME`, `VERIFY_URL_TEMPLATE`, `RESET_URL_TEMPLATE`.

Key rotation: run `npm run keygen -- keys/jwt-2027`, point `JWT_PRIVATE_KEY_PATH` at the new private key and `JWT_PREVIOUS_PUBLIC_KEY_PATH` at the old public key, restart. Tokens signed by the old key stay valid until they expire; JWKS publishes both. Remove the previous key after `ACCESS_TOKEN_TTL_SEC` has passed.

## Security notes

- Passwords: scrypt (`SCRYPT_LOG_N`, default 2^15, r=8, p=1), 32-byte salt, NFKC normalised. Hashes are upgraded transparently at next login when the cost is raised. Policy: minimum length, common-password denylist including "word + digits" variants, no email-derived passwords, none of the last `PASSWORD_HISTORY` passwords (default 5, current included). With `PASSWORD_BREACH_CHECK=true` new passwords are also checked against the Have I Been Pwned range API (`PASSWORD_BREACH_URL`): only the first five hex characters of the SHA-1 leave the process, the response is padded, and a network failure lets the password through.
- Login: constant-time hash comparison; unknown emails cost the same as a wrong password; lockout per account **and client address** after `LOGIN_MAX_FAILURES` for `LOGIN_LOCKOUT_MIN`, doubling for every repeat of the same address (up to a day), so one address cannot lock the owner out elsewhere; `LOGIN_MAX_FAILURES_TOTAL` over all addresses together is the backstop. `MAX_SESSIONS` caps active sessions per user (the least recently used is signed out); `NEW_DEVICE_EMAIL` mails the user when a sign-in comes from a device not seen before. Optional `LOGIN_REQUIRES_VERIFIED_EMAIL`.
- MFA (end users): TOTP (RFC 6238, 30 s, ±1 step), each code accepted once; ten one-time recovery codes stored as SHA-256. Secrets are sealed with AES-256-GCM under `MFA_SECRETS_KEY` (64 hex; without it the MFA routes answer `503 MFA_UNAVAILABLE`). The sign-in challenge lives `MFA_CHALLENGE_TTL_SEC` and allows five codes; wrong codes count toward the same address lockout as wrong passwords. Turning MFA off needs the password and a code; enabling, disabling and an administrator reset are mailed to the user.
- Tokens: only SHA-256 hashes of refresh, verification and reset tokens are stored. Reset validates the new password before spending the link. Reset revokes all sessions; password change revokes all other sessions.
- API keys compared in constant time; per-key rate limit; request bodies capped at `BODY_LIMIT`; unknown fields rejected; `Cache-Control: no-store` on every response except JWKS.
- **Upgrading to a role-aware `AUTH_API_KEYS`:** a key already deployed without a role keeps full `readwrite` access — no `write` route starts rejecting it. It does *not* keep `X-Client-IP` trust automatically, though: that requires the explicit `proxy` flag (`id:secret:readwrite:proxy`). If your backend forwarded the end user's real address and you relied on it appearing in the audit log, add `proxy` to that key when you upgrade — otherwise every session/event records the socket's own peer address (your backend's, not the end user's) instead.
- Enumeration resistance: `forgot` and `resend` always return `202`. Unknown, verified, disabled and throttled cases are silent no-ops, so neither status nor error code reveals whether an account exists.
- Audit log: registration, verification, login success/failure with reason, lockout, refresh, reuse detection, logout, password events, session and account changes. Retained `EVENT_RETENTION_DAYS`.
- Container runs as the unprivileged `node` user; keys mounted read-only.

## Code layout

Class-based; dependencies are injected through constructors, `src/application.js` is the composition root.

| Class | File | Role |
|---|---|---|
| `Application` | `src/application.js` | Wiring, startup, graceful shutdown |
| `Config` | `src/config.js` | Validated environment |
| `Database` | `src/db.js` | SQLite connection, migrations, transactions |
| `PasswordHasher`, `OpaqueToken`, `JwtSigner` | `src/crypto/` | Hashing, random secrets, ES256 JWT + JWKS |
| `UserStore`, `SessionStore`, `ActionTokenStore`, `EventStore` | `src/store/` | Persistence |
| `AuthService` | `src/domain/auth-service.js` | All use-cases |
| `PasswordPolicy`, `AuthError`, `Mailer` → `NotifyMailer` | `src/domain/` | Rules, errors, outbound mail |
| `AuthApi`, `ApiKeyAuth`, `Schemas`, `Views` | `src/http/` | Fastify routes and shapes |
| `Maintenance` | `src/maintenance.js` | Hourly retention purge |
| `KeyGenerator` | `scripts/keygen.js` | Signing key pair |

## Out of scope by design

- Social login (OAuth/OIDC providers), WebAuthn/passkeys, **end-user** roles and permissions: add as separate modules when a product needs them; the session and audit model already supports them. (The `read`/`write`/`readwrite` role on an *API key* is a different, narrower thing — it gates which backend integration may call which route, not what an end user of your product can do.)
- Multi-tenant user pools: one deployment serves one user pool. Run another instance for another product.
- Multiple processes on one SQLite file: intended deployment is one instance per database.

## Events

With `WEBHOOK_OUT_URL` set, the service publishes `auth.user.created`, `auth.user.disabled`, `auth.user.enabled`, `auth.user.anonymized` and `auth.user.deleted` with the user id only (no e-mail address). Best effort; see [examples/events.md](examples/events.md).

## Audit events

With `AUDIT_URL` and `AUDIT_API_KEY` set, every security event this service records per user (registration, verification, login success and failure with the reason, lockout, refresh, logout, session revocation, password reset and change, account disable/enable/delete) is also forwarded to the audit service as `auth.<event type>` with the user as actor and target, the client IP and the event's metadata. Attempts that did not succeed carry `outcome: "failure"`. Details: [examples/audit-events.md](examples/audit-events.md).

**Durability:** unlike every other service here, forwarding is not an in-memory buffer — it is a transactional outbox. `EventStore.record()` writes the event into this service's own `events` table *and* a row in `outbox` in the same SQLite transaction as whatever business mutation the event describes (password change, login, …): the two commit or roll back together, so an event is never forwarded before its mutation has durably committed, and never exists at all if that mutation's transaction rolled back. A background loop drains `outbox` and posts to the audit service, marking each row sent only after a successful response; a crash at any point before that (including a crash *after* a successful response but before the row is marked) is safe, not silent data loss or a duplicate audit record — delivery resumes on the next start from whatever is still unmarked, using the same row id every attempt, and the audit service's own `UNIQUE(source, client_id)` on that id makes a resend a no-op there. Delivery is at-least-once, never zero-times and never (from audit's perspective) more than once. Sent rows are kept `AUDIT_OUTBOX_RETENTION_DAYS` (default 7) before being purged; undelivered rows are never purged regardless of age. None of this touches the response time or success of the business request itself — an unreachable audit service delays only when its event is *eventually* forwarded, never whether `POST /v1/auth/login` (etc.) succeeds.

## Scaling model

**B — single-node stateful.** One process, one SQLite file. `UNIQUE` constraints (email, token hashes) keep
the data correct under concurrent requests within that process; two processes against the same
file is not the supported or tested deployment model.

## Observability

Accepts an inbound `X-Request-Id` unconditionally and logs it via Fastify's default request
logging. Also parses an inbound `traceparent`, trusted only when `TRUST_PROXY=true` — the caller's
trace-id is continued with a fresh span-id for this hop, both logged as `traceId`/`spanId` via
`@atc-web/atc-service-core`'s `registerRequestContext`. Its own call to `atc-notify`
(`src/domain/mailer.js`) explicitly propagates the active trace (`RequestContext#propagationHeaders()`);
no other outbound call does. The security events this service forwards to
audit do not yet carry a request id of their own — only auth's own log line for the causing request
does. See [OBSERVABILITY.md](../atc-stack/docs/OBSERVABILITY.md).

Event publishing is observable as `events_publish_enabled`, `events_publish_total{result="published|sent|dropped|failed"}` and `events_publish_pending`.

Audit forwarding is observable too: `audit_forward_enabled`, `audit_forward_events_total{result="recorded|sent|dropped|failed"}` and `audit_forward_pending`. A rising `dropped`, or a `pending` that does not drain, means audit events are being lost or delayed; alert on it.

## Backup / restore

Back up the database and the JWT signing key files (`keys/`) together; restoring the database with
a different signing key invalidates every outstanding access token immediately. `stack backup`/
`stack restore` from the workspace root (see `atc-stack/docs/UPGRADE.md`) captures the database and
`keys/` together for exactly this reason. On every start, before applying a pending migration to an
existing database, the service itself also snapshots the database file to
`DB_PATH.pre-v<N>-<timestamp>` (directory overridable with `DB_BACKUP_DIR`) — a manual last resort
that still needs `keys/` restored alongside it.

**Rollback limitations:** none of the migrations are reversible; to roll back, restore the database
and `keys/` from the same `stack backup` snapshot (or the pre-migration database copy plus a
same-time copy of `keys/`) and run the previous version of this service against it.

See [docs/READINESS.md](docs/READINESS.md) for the full contract.

## License

MIT, see [LICENSE](LICENSE).
