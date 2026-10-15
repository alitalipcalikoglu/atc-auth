# Lockout and password policy

## Brute-force lockout

After `LOGIN_MAX_FAILURES` (default 10) wrong passwords the account is locked for `LOGIN_LOCKOUT_MIN` (default 15):

```bash
for i in $(seq 1 10); do authcurl -X POST $AUTH/v1/auth/login -d '{"email":"ali@example.com","password":"nope"}' -o /dev/null -w '%{http_code} '; done
# 401 401 401 401 401 401 401 401 401 401
authcurl -X POST $AUTH/v1/auth/login -d '{"email":"ali@example.com","password":"correct horse battery staple"}' -i
```

```
HTTP/1.1 423 Locked
Retry-After: 897
{ "error": { "code": "ACCOUNT_LOCKED", "message": "too many failed attempts, try again later", "details": { "retryAfterSec": 897 } } }
```

The correct password is refused too while locked. A successful login after the window resets the counter. `lockedUntil` is visible on `GET /v1/users/:id`. Audit log: `login.failed` with `reason: bad_password` and `failures`, then `account.locked`.

Unknown emails are never locked (there is nothing to lock) but cost the same CPU as a real check.

## Password policy

Checked on registration, reset and change. Configurable minimum: `PASSWORD_MIN_LENGTH` (default 10). Fixed rules:

| Rejected | Example | Message |
|---|---|---|
| too short | `abc123` | `must be at least 10 characters` |
| too long | > 256 chars | `must be at most 256 characters` |
| common password, also with digits/symbols appended | `password1234`, `Qwerty2024!` | `is too common` |
| one repeated character | `aaaaaaaaaaaa` | `must not repeat a single character` |
| contains the email or its local part | `alitalip2024!` for `alitalip@…` | `must not contain your email address` |
| leading/trailing whitespace | `" secret words "` | `must not start or end with whitespace` |

All problems are returned at once:

```json
{ "error": { "code": "WEAK_PASSWORD", "message": "password must be at least 10 characters; is too common",
  "details": { "problems": ["must be at least 10 characters", "is too common"] } } }
```

Passwords are NFKC-normalised before hashing, so `ﬁsh` and `fish` are the same password.

### Reuse and breached passwords

On reset and change (not registration, there is no history yet) the new password must differ from the current one and from the ones before it, `PASSWORD_HISTORY` in total (default 5, `0` turns it off): `must not be one of your last 5 passwords`. The check runs only after the fixed rules pass and costs one hash verification per remembered password.

With `PASSWORD_BREACH_CHECK=true`, every new password (registration included) is also looked up in Have I Been Pwned: the service sends the first five hex characters of its SHA-1 to `PASSWORD_BREACH_URL/range/<prefix>` with padding on, compares the suffixes locally and rejects a hit with `appears in known data breaches; choose another`. If the lookup fails or times out (`PASSWORD_BREACH_TIMEOUT_MS`, default 2000) the password is accepted and a warning is logged, so an outage never blocks sign-ups.

## Hash cost

scrypt with `N = 2^SCRYPT_LOG_N` (default 15, about 100 ms per check). Raising the value later is safe: existing users are re-hashed transparently on their next successful login.

## Lockout is per address, with backoff

Failures count per account **and client address** (the address the calling backend forwards as `X-Client-IP`). After `LOGIN_MAX_FAILURES` the address is locked for `LOGIN_LOCKOUT_MIN`; every repeat of the same address doubles the lock, up to a day. The owner signing in from another address is not affected, so a stranger who knows an email cannot lock it out for everyone. `LOGIN_MAX_FAILURES_TOTAL` (default 50) counts across all addresses and locks the account itself against a distributed attack. A successful sign-in clears the address's counter. `423 ACCOUNT_LOCKED` carries `Retry-After`.

## Session cap and new-device notice

`MAX_SESSIONS` (default 10) limits active sessions per user; a new sign-in beyond it signs out the least recently used one (event `session.revoked`, reason `session_limit`). With `NEW_DEVICE_EMAIL=true` a sign-in from a user agent not seen before mails the user (event `login.new_device`); the very first device is not announced.
