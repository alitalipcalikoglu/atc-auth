# Registration and email verification

Scenario: a visitor fills in the sign-up form on your site. Your backend calls auth; auth stores the account and asks notify to send the verification link.

## 1. Register

```bash
authcurl -X POST $AUTH/v1/users -d '{ "email": "Ali@Example.com", "password": "correct horse battery staple", "name": "Ali" }'
```

`201 Created`, `Location: /v1/users/<id>`:

```json
{ "user": { "id": "usr_mgx1k2ab…", "email": "ali@example.com", "name": "Ali", "status": "active",
            "emailVerified": false, "emailVerifiedAt": null, "lockedUntil": null,
            "passwordChangedAt": "2026-09-16T04:08:28.791Z", "createdAt": "2026-09-16T04:08:28.791Z", "updatedAt": "2026-09-16T04:08:28.791Z" },
  "verificationEmailSent": true }
```

Emails are lower-cased and trimmed. `verificationEmailSent: false` means notify could not be reached; the account exists, offer a "resend" button.

The email contains `VERIFY_URL_TEMPLATE` with `{token}` replaced, e.g. `https://shop.example.com/verify-email?token=Qm5…`. That page belongs to your frontend.

## 2. Verify

Your frontend posts the token from the URL to your backend, which calls:

```bash
authcurl -X POST $AUTH/v1/auth/verify-email -d '{ "token": "Qm5…" }'
```

`200` with the user, now `emailVerified: true`. A second call with the same token: `401 INVALID_TOKEN` (single use). Tokens expire after `VERIFY_TOKEN_TTL_MIN` (default 24 h).

## 3. Resend

```bash
authcurl -X POST $AUTH/v1/auth/verify-email/resend -d '{ "email": "ali@example.com" }'
```

Always `202 {"accepted":true}`: for unknown addresses, already-verified addresses and repeats within `RESEND_COOLDOWN_SEC` (default 60) nothing is sent, but the response is identical, so it cannot be used to discover accounts. Issuing a new link invalidates the previous one.

## Errors on registration

| Status | Code | When |
|---|---|---|
| 409 | `EMAIL_TAKEN` | Address already registered |
| 400 | `WEAK_PASSWORD` | See `details.problems`, e.g. `["must be at least 10 characters"]` |
| 400 | `VALIDATION_FAILED` | Malformed email, missing field, unknown field |

## Requiring verification before login

Default: users can log in before verifying; the access token carries `email_verified: false` so your app can restrict features. Set `LOGIN_REQUIRES_VERIFIED_EMAIL=true` to refuse login with `403 EMAIL_NOT_VERIFIED` until the link is clicked.

## Audit trail

```bash
authcurl $AUTH/v1/users/usr_mgx1k2ab…/events
```

shows `user.registered`, `email.verified`, `email.verification_resent` with the forwarded `X-Client-IP`.
