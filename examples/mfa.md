# Two-step sign-in (MFA)

End users can protect their account with a TOTP app (Google Authenticator, 1Password, Authy, …) and ten one-time recovery codes. The server needs `MFA_SECRETS_KEY` (64 hex characters, `openssl rand -hex 32`); it seals every secret with AES-256-GCM. Without it the MFA routes answer `503 MFA_UNAVAILABLE`.

The enrolment and management routes act for the signed-in user: your backend passes the user's access token in `X-Access-Token` next to its own API key, as for a password change. Every one of them also takes the current password: an access token that leaked (a script on the page, a shared device) must not be enough to bind another authenticator or take the recovery codes. A wrong password or code counts toward the same lockout as a failed sign-in.

## Enrol

```bash
authcurl -X POST $AUTH/v1/auth/mfa/setup -H "X-Access-Token: $ACCESS" -d '{"password":"correct horse battery staple"}'
```

```json
{ "secret": "JBSWY3DPEHPK3PXP…", "otpauthUrl": "otpauth://totp/Shop%3Aada%40example.com?secret=JBSW…&issuer=Shop&algorithm=SHA1&digits=6&period=30" }
```

Render `otpauthUrl` as a QR code (and show `secret` for manual entry). MFA is still off. Confirm with the first code from the app:

```bash
authcurl -X POST $AUTH/v1/auth/mfa/enable -H "X-Access-Token: $ACCESS" -d '{"password":"correct horse battery staple","code":"492039"}'
```

```json
{ "recoveryCodes": ["K7Q2M-X9DPA", "…ten in total…"] }
```

Show the codes once and ask the user to store them; they are kept only as hashes. The user gets a "two-step verification on" mail.

## Sign in

The password step now answers `401 MFA_REQUIRED` instead of tokens:

```bash
authcurl -X POST $AUTH/v1/auth/login -d '{"email":"ada@example.com","password":"correct horse battery staple"}'
```

```json
{ "error": { "code": "MFA_REQUIRED", "message": "enter the code from your authenticator app or a recovery code", "details": { "mfaToken": "q3V…", "mfaTokenExpiresAt": "2026-10-16T10:05:00.000Z" } } }
```

Ask for the code and finish:

```bash
authcurl -X POST $AUTH/v1/auth/login/mfa -d '{"mfaToken":"q3V…","code":"731564"}'
```

`200` with `{ user, tokens }`, exactly like a password-only login. A recovery code works in place of the six digits (`k7q2m x9dpa` is fine: case, spaces and the dash are ignored) and only once.

What to expect:

- Each TOTP code is accepted once; the previous and next 30-second step are accepted for clock drift.
- A challenge lives `MFA_CHALLENGE_TTL_SEC` (default 300) and allows five codes; after that `401 INVALID_TOKEN`, start again with the password.
- Wrong codes count toward the same per-address lockout as wrong passwords (`423 ACCOUNT_LOCKED` with `Retry-After`).

## New recovery codes, turning off

```bash
authcurl -X POST $AUTH/v1/auth/mfa/recovery-codes -H "X-Access-Token: $ACCESS" -d '{"password":"correct horse battery staple","code":"118204"}'
authcurl -X POST $AUTH/v1/auth/mfa/disable -H "X-Access-Token: $ACCESS" -d '{"password":"correct horse battery staple","code":"K7Q2M-X9DPA"}'
```

New codes replace all old ones. Turning off needs the password (same lockout as sign-in) and a code or a recovery code; the user is mailed.

## Lost device (administration)

```bash
authcurl -X DELETE $AUTH/v1/users/$USER_ID/mfa
```

`204`; needs a `write` key. The secret, recovery codes and open challenges are removed, the user is mailed and signs in with the password alone until they enrol again. The admin console has a "Reset MFA" action on the user page. `GET /v1/users/:id` shows `mfaEnabled` and `mfaEnabledAt`.

## Pitfalls

- Do not store `secret` or the recovery codes in your backend; show them and forget them.
- `MFA_REQUIRED` is a `401`: check `error.code` before treating a `401` as a wrong password.
- Changing `MFA_SECRETS_KEY` makes every enrolled secret unreadable; those users then need an admin reset.
- Security events: `login.mfa_required`, `login.mfa_failed`, `mfa.enabled`, `mfa.disabled`, `mfa.reset`, `mfa.recovery_code_used`, `mfa.recovery_codes_replaced` (all forwarded to atc-audit).
