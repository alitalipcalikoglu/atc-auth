# User administration

All under `/v1/users`, API key required. Intended for your backend's admin features and support tooling.

## Look up

```bash
authcurl "$AUTH/v1/users?email=ali@example.com"      # {"items":[{…}],"nextCursor":null}
authcurl $AUTH/v1/users/usr_mgx1k2ab…                     # {"user":{…}}
```

## List, newest first

```bash
authcurl "$AUTH/v1/users?limit=50"
authcurl "$AUTH/v1/users?limit=50&cursor=<nextCursor>"
```

## Rename or disable

```bash
authcurl -X PATCH $AUTH/v1/users/usr_mgx1k2ab… -d '{ "name": "Ali T." }'
authcurl -X PATCH $AUTH/v1/users/usr_mgx1k2ab… -d '{ "status": "disabled" }'
```

Disabling revokes every session at once; further logins answer `403 ACCOUNT_DISABLED`, refreshes fail, introspection reports `ACCOUNT_DISABLED`. `{ "status": "active" }` re-enables. An empty patch is `400`.

## Delete

```bash
authcurl -X DELETE $AUTH/v1/users/usr_mgx1k2ab…
```

`204`. Hard delete: sessions and pending tokens go with the user; the audit events keep the user id for the retention period.

## Sessions

```bash
authcurl $AUTH/v1/users/usr_mgx1k2ab…/sessions
```

```json
{ "items": [ { "id": "9b6f…", "createdAt": "…", "lastUsedAt": "…", "expiresAt": "…", "ip": "203.0.113.9", "userAgent": "Mozilla/5.0" } ] }
```

Revoke one device or all:

```bash
authcurl -X DELETE $AUTH/v1/users/usr_mgx1k2ab…/sessions/9b6f…    # 204
authcurl -X DELETE $AUTH/v1/users/usr_mgx1k2ab…/sessions          # {"revoked":3}
```

## Audit log

```bash
authcurl "$AUTH/v1/users/usr_mgx1k2ab…/events?limit=20"
```

```json
{ "items": [
    { "seq": 812, "type": "login.succeeded", "ip": "203.0.113.9", "meta": { "sessionId": "ses_mgx1k3cd…" }, "at": "…" },
    { "seq": 811, "type": "login.failed", "ip": "198.51.100.4", "meta": { "reason": "bad_password", "failures": 1 }, "at": "…" } ],
  "nextCursor": "811" }
```

Older page: `?cursor=811` (opaque: pass `nextCursor` back as it is). Event types: `user.registered`, `email.verified`, `email.verification_resent`, `login.succeeded`, `login.failed`, `account.locked`, `session.refreshed`, `session.reuse_detected`, `session.revoked`, `sessions.revoked_all`, `logout`, `password.reset_requested`, `password.reset`, `password.changed`, `password.change_failed`, `account.disabled`, `account.enabled`, `account.deleted`. Events older than `EVENT_RETENTION_DAYS` (default 90) are purged hourly.
