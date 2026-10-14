# Events

```bash
WEBHOOK_OUT_URL=http://webhook-out.internal:3009
WEBHOOK_OUT_API_KEY=<a webhook-out key with the publish role>
```

| Event | When | Data |
|---|---|---|
| `auth.user.created` | A user registered | `id` |
| `auth.user.disabled` | An admin disabled an account (sessions are revoked) | `id` |
| `auth.user.enabled` | An admin enabled a disabled account | `id` |
| `auth.user.deleted` | An admin deleted an account | `id` |
| `auth.user.anonymized` | A person was erased, the account row kept | `id` |

The payload is the user id and nothing else: no e-mail address, name or IP, so a webhook subscriber never receives personal data it does not need. Look the user up with `GET /v1/users/:id` and an admin key if more is needed (not possible after `deleted`).

An update that does not change the status (a rename, or setting the status the account already has) publishes nothing. Events are best effort (in-memory queue, retries, lost on a restart); the audit log, not this feed, is the record.
