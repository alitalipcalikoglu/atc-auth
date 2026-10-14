# auth examples

Scenario-driven walkthroughs of every feature. Requests to `/v1/*` need `Authorization: Bearer <secret>` from `AUTH_API_KEYS`; the caller is your application backend, never the browser. Base URL below is `http://localhost:3002`.

| Example | Shows |
|---|---|
| [Registration and email verification](registration-and-verification.md) | Create a user, verification mail through notify, verify, resend |
| [Login and tokens](login-and-tokens.md) | Password login, what the access and refresh tokens contain, verifying JWTs locally with JWKS, introspection |
| [Refresh, logout and reuse detection](refresh-and-logout.md) | Rotating refresh tokens, what happens when a stolen token is replayed |
| [Forgot and reset password](password-reset.md) | Reset link by email, single-use token, sessions revoked |
| [Change password](password-change.md) | Authenticated change with `X-Access-Token`, keeps the current session |
| [Lockout and password policy](lockout-and-policy.md) | Brute-force lockout, `Retry-After`, what passwords are rejected |
| [User administration](user-administration.md) | List, look up, disable, delete users; sessions; audit log |
| [Signing key rotation](key-rotation.md) | Rotate the ES256 key pair without logging anyone out |
| [Operations](operations.md) | Health, readiness, metrics, environment, PM2, Docker |
| [Events](events.md) | `auth.user.*` lifecycle events through atc-webhook-out |
| [Email change, personal data](email-and-personal-data.md) | Changing an address, exporting and anonymizing a person |
| [Audit events](audit-events.md) | Which security events are forwarded to the audit service and how |

Set up once for the examples:

```bash
export AUTH=http://localhost:3002
export KEY=<your secret from AUTH_API_KEYS>
```

Forward the end user's address and agent so the audit log is useful:

```bash
alias authcurl='curl -s -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" -H "X-Client-IP: 203.0.113.9" -H "X-Client-User-Agent: Mozilla/5.0"'
```
