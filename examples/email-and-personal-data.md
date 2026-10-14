# Email change and personal data

## A user changes their email address

```bash
curl -s -X POST $AUTH/v1/auth/email/change -H "authorization: Bearer $KEY" -H 'content-type: application/json' \
  -d '{ "email": "ali@example.com", "password": "the current password", "newEmail": "ali@new.example" }'   # 202
```

A mail with a link (`CHANGE_EMAIL_URL_TEMPLATE`, default `VERIFY_URL_TEMPLATE`) goes to the **new** address; nothing changes yet. Your frontend posts the token it finds in the link:

```bash
curl -s -X POST $AUTH/v1/auth/email/confirm -H "authorization: Bearer $KEY" -H 'content-type: application/json' -d '{ "token": "<token>" }'
```

The address changes and counts as verified (the mailbox was proven), the old address gets a notice, sessions stay. Always `202` for the request, also when the new address belongs to someone else: no hint, no mail. Wrong password: `401 INVALID_CREDENTIALS`; the same address: `400 INVALID_ARGUMENT`; the link is single use and expires after `VERIFY_TOKEN_TTL_MIN`.

An operator can set it directly: `PATCH /v1/users/:id { "email": "..." }` (a `write` key). The address starts unverified and a verification mail goes to it; `409 EMAIL_TAKEN` if it is in use.

## A data-subject request

```bash
curl -s -H "authorization: Bearer $KEY" $AUTH/v1/users/$ID/export      # profile, sessions, events with their addresses
curl -s -X POST -H "authorization: Bearer $KEY" $AUTH/v1/users/$ID/anonymize   # 204, irreversible
```

Anonymizing keeps the row and its id (events and other services still resolve it) but removes the person: the address becomes `anonymized-<id>@anonymized.invalid`, the name, password, sessions and tokens go, the account is disabled and the addresses in its events are cleared. It publishes `auth.user.anonymized` (see [events](events.md)). `DELETE /v1/users/:id` removes the row entirely.

Pitfalls:
- Anonymizing does not reach other services (orders, payments, support tools): subscribe to `auth.user.anonymized` and erase there too. atc-payments has its own anonymize endpoint for customer data.
- Copies in the audit service are not rewritten: that log is append-only by design and the events carry the user id, not the address.
