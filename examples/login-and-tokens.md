# Login and tokens

## 1. Login

```bash
authcurl -X POST $AUTH/v1/auth/login -d '{ "email": "ali@example.com", "password": "correct horse battery staple" }'
```

```json
{ "user": { "id": "usr_mgx1k2ab…", "email": "ali@example.com", "emailVerified": true, "...": "…" },
  "tokens": {
    "tokenType": "Bearer",
    "accessToken": "eyJhbGciOiJFUzI1NiIsImtpZCI6InBES09…",
    "accessTokenExpiresAt": "2026-09-16T04:23:28.000Z",
    "refreshToken": "c1Yt8bZ…43 url-safe chars",
    "refreshTokenExpiresAt": "2026-10-16T04:08:28.791Z",
    "sessionId": "ses_mgx1k3cd…"
  } }
```

Wrong password or unknown email: `401 INVALID_CREDENTIALS`, same message for both, same response time (a dummy hash is computed for unknown emails).

## 2. Where to keep the tokens

- **Access token**: short-lived (`ACCESS_TOKEN_TTL_SEC`, default 15 min). Give it to the browser; send it as `Authorization: Bearer …` to your API or the gateway.
- **Refresh token**: long-lived, opaque, shown once. Keep it server-side in the user's session or in an `httpOnly; Secure; SameSite=Strict` cookie. Never expose it to JavaScript.

## 3. What is inside the access token

```json
{ "alg": "ES256", "kid": "pDKOoa3NEDgl-…", "typ": "JWT" }
{ "iss": "https://auth.example.com", "aud": "shop", "sub": "usr_mgx1k2ab…", "sid": "ses_mgx1k3cd…",
  "email": "ali@example.com", "email_verified": true, "jti": "d3a0…", "iat": 1758000508, "exp": 1758001408 }
```

`sub` is the user id, `sid` the session (refresh-token family) id.

## 4. Verify tokens locally, without calling auth

Any service can validate with the public keys:

```bash
curl -s $AUTH/.well-known/jwks.json
```

```js
import { createRemoteJWKSet, jwtVerify } from 'jose';
const jwks = createRemoteJWKSet(new URL('https://auth.example.com/.well-known/jwks.json'));
const { payload } = await jwtVerify(token, jwks, { issuer: 'https://auth.example.com', audience: 'shop' });
console.log(payload.sub, payload.email_verified);
```

Local verification cannot know that a session was revoked in the last 15 minutes. If that matters (admin panel, money), use introspection.

## 5. Introspect

```bash
authcurl -X POST $AUTH/v1/auth/introspect -d '{ "accessToken": "eyJ…" }'
```

Live: `{ "active": true, "claims": { "sub": "…", "sid": "…", "...": "…" } }`.
Not live: `{ "active": false, "reason": "SESSION_REVOKED" }` (also `EXPIRED`, `INVALID`, `UNKNOWN_KEY`, `ACCOUNT_DISABLED`). Always `200`.

## Errors

| Status | Code | When |
|---|---|---|
| 401 | `INVALID_CREDENTIALS` | Bad email or password |
| 423 | `ACCOUNT_LOCKED` | Too many failures; `details.retryAfterSec`, `Retry-After` header |
| 403 | `ACCOUNT_DISABLED` | Disabled by an administrator |
| 403 | `EMAIL_NOT_VERIFIED` | Only with `LOGIN_REQUIRES_VERIFIED_EMAIL=true` |
