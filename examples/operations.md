# Operations

## Probes

```bash
curl -s $AUTH/health   # {"status":"ok"}
curl -s $AUTH/ready    # {"status":"ok"} when SQLite answers and notify's /health responds; 503 otherwise (cached 30 s)
```

## Metrics

```bash
curl -s $AUTH/metrics -H "Authorization: Bearer $KEY"
```

```
auth_users{status="active"} 1204
auth_users{status="disabled"} 3
auth_sessions_active 857
auth_process_uptime_seconds 86400
```

## Environment

Required: `AUTH_API_KEYS`, `JWT_PRIVATE_KEY_PATH`, `JWT_ISSUER`, `JWT_AUDIENCE`, `NOTIFY_URL`, `NOTIFY_API_KEY`, `APP_NAME`, `VERIFY_URL_TEMPLATE`, `RESET_URL_TEMPLATE`. Full list: [.env.example](../.env.example).

- `JWT_ISSUER` is the public URL clients see, e.g. the gateway (`https://api.example.com`), not the internal address.
- `NOTIFY_API_KEY` must be one of notify's `NOTIFY_API_KEYS` secrets, ideally an entry named `atc-auth`.
- One `AUTH_API_KEYS` entry per caller (`gateway:…`, `admin-panel:…`).

## Process manager

```bash
npm run keygen
pm2 start ecosystem.config.cjs
pm2 reload auth
```

`kill_timeout` is 35 s: SIGTERM stops accepting connections, finishes in-flight requests, closes the database.

## Docker

```bash
docker build -t atc-auth .
docker run -d -p 3002:3002 -v atc-auth-data:/data -v $PWD/keys:/keys:ro --env-file .env atc-auth
```

`JWT_PRIVATE_KEY_PATH` defaults to `/keys/jwt-private.pem` inside the image.

## Logs

JSON lines. `Authorization` and `X-Access-Token` headers are redacted. Security-relevant lines: `refresh token reuse detected, session revoked` (warn), `verification email failed` / `password reset email failed` (error, notify unreachable).

## Backups

```bash
sqlite3 data/auth.db ".backup 'auth-$(date +%F).db'"
```

Back up the private key separately and offline; losing it only forces a re-login of every user, leaking it lets anyone mint tokens.
