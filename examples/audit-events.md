# Audit events

Set both variables to forward events to the audit service (repository `atc-audit`); leave both empty to keep the service silent:

```
AUDIT_URL=http://10.0.0.5:3005
AUDIT_API_KEY=<the auth key from AUDIT_API_KEYS, role write>
```

Every event stored in the per-user security log (`GET /v1/users/:id/events`) is durably queued for forwarding in the same database transaction as the change it describes (see "Audit events" in README.md for the transactional-outbox durability contract), so the audit service ends up with the same history across every service, in one hash chain. The key id becomes the event `source`. A background loop drains the queue every 2 seconds in batches, retried with backoff and stable, idempotent ids; a request is never slowed down or failed by auditing, and a crash before delivery never loses the event — it is retried on the next drain or the next process start.

## Actions

| Action | When | Outcome |
|---|---|---|
| `atc-auth.user.registered` | Registration | success |
| `atc-auth.email.verified`, `atc-auth.email.verification_resent` | Verification flow | success |
| `atc-auth.login.succeeded` | Login (meta: `sessionId`) | success |
| `atc-auth.login.failed` | Wrong password, unknown email, locked, disabled or unverified account (meta: `reason`, `failures`) | failure |
| `atc-auth.account.locked` | Too many failures | failure |
| `atc-auth.session.refreshed`, `atc-auth.logout` | Token refresh, logout | success |
| `atc-auth.session.reuse_detected` | A rotated refresh token was presented again (all sessions of the user revoked) | failure |
| `atc-auth.session.revoked`, `atc-auth.sessions.revoked_all` | Admin or user revocation | success |
| `atc-auth.password.reset_requested`, `atc-auth.password.reset`, `atc-auth.password.changed` | Password flows | success |
| `atc-auth.password.change_failed` | Wrong current password | failure |
| `atc-auth.account.disabled`, `atc-auth.account.enabled`, `atc-auth.account.deleted` | Admin actions on the account | success |

`actor` and `target` are `{ "type": "user", "id": "<user id>" }` when the user is known; `atc-auth.login.failed` for an unknown email has neither, only the IP.

## Query examples on the audit side

```bash
curl -s -H "Authorization: Bearer $AUDIT_KEY" "$AUDIT/v1/events?source=atc-auth&action=atc-auth.login.failed&limit=50"
curl -s -H "Authorization: Bearer $AUDIT_KEY" "$AUDIT/v1/events?targetType=user&targetId=<user id>"
```
