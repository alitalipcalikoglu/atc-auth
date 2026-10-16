import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { after, before, test } from 'node:test';
import { AuthApi } from '../src/http/auth-api.js';
import { API_KEY, ctx, GOOD_PASSWORD, OTHER_KEY, READ_KEY, silentLog, testAuthService } from './helpers.js';

/** @type {Awaited<ReturnType<typeof testAuthService>>} */
let t;
/** @type {import('fastify').FastifyInstance} */
let app;
const auth = { authorization: `Bearer ${API_KEY}`, 'x-client-ip': '198.51.100.7', 'x-client-user-agent': 'TestBrowser/1.0' };
void ctx;

/** @param {string} method @param {string} url @param {object} [payload] @param {Record<string,string>} [headers] */
const call = (method, url, payload, headers = {}) => app.inject({ method: /** @type {any} */ (method), url, payload, headers: { ...auth, ...headers } });

before(async () => {
  t = await testAuthService({ RATE_LIMIT_MAX: '200', RESEND_COOLDOWN_SEC: '0' });
  app = await new AuthApi({ config: t.config, service: t.service, jwt: t.signer, db: t.db, mailer: t.mailer, users: t.users, sessions: t.sessions, events: t.events, version: '1.0.0', logger: silentLog }).build();
  await app.ready();
});
after(() => app.close());

test('GET /v1/info reports service identity and capabilities', async () => {
  const res = await call('GET', '/v1/info');
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.equal(body.service, 'atc-auth');
  assert.equal(body.version, '1.0.0');
  assert.equal(body.apiVersion, 'v1');
  assert.deepEqual(body.capabilities, ['jwks', 'email-verification', 'password-reset', 'refresh-tokens', 'mfa-totp', 'password-history']);
  assert.equal(typeof body.schemaVersion, 'number');
  assert.equal(typeof body.serviceCore, 'string');
});

test('public endpoints: health, ready, jwks; everything else needs an API key', async () => {
  assert.equal((await app.inject('/health')).statusCode, 200);
  assert.equal((await app.inject('/ready')).statusCode, 200);
  const spec = await app.inject('/openapi.yaml');
  assert.equal(spec.body, readFileSync(new URL('../openapi.yaml', import.meta.url), 'utf8'));
  assert.match(String(spec.headers['content-type']), /^text\/yaml/);
  const jwks = await app.inject('/.well-known/jwks.json');
  assert.equal(jwks.statusCode, 200);
  assert.equal(jwks.json().keys[0].kid, t.signer.kid);
  assert.match(String(jwks.headers['cache-control']), /max-age/);
  for (const url of ['/v1/users', '/metrics']) {
    const res = await app.inject({ url });
    assert.equal(res.statusCode, 401, url);
    assert.equal(res.json().error.code, 'UNAUTHORIZED');
  }
  assert.equal((await app.inject({ url: '/nope', headers: auth })).statusCode, 404);
  assert.equal((await call('GET', '/v1/users')).headers['cache-control'], 'no-store');
});

test('register, list, get, verify, login, refresh, logout over HTTP', async () => {
  let res = await call('POST', '/v1/users', { email: 'Ali@Example.com', password: GOOD_PASSWORD, name: 'Ali' });
  assert.equal(res.statusCode, 201);
  const { user, verificationEmailSent } = res.json();
  assert.equal(user.email, 'ali@example.com');
  assert.equal(user.emailVerified, false);
  assert.equal(verificationEmailSent, true);
  assert.equal('password_hash' in user, false);
  assert.equal(res.headers.location, `/v1/users/${user.id}`);

  res = await call('POST', '/v1/users', { email: 'ali@example.com', password: GOOD_PASSWORD });
  assert.equal(res.statusCode, 409);
  assert.equal(res.json().error.code, 'EMAIL_TAKEN');
  res = await call('POST', '/v1/users', { email: 'x@example.com', password: 'short' });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error.code, 'WEAK_PASSWORD');
  assert.ok(res.json().error.details.problems.length);
  res = await call('POST', '/v1/users', { email: 'not-an-email', password: GOOD_PASSWORD });
  assert.equal(res.json().error.code, 'VALIDATION_FAILED');
  res = await call('POST', '/v1/users', { email: 'x@example.com', password: GOOD_PASSWORD, extra: 1 });
  assert.equal(res.statusCode, 400, 'unknown fields rejected');

  res = await call('GET', '/v1/users?email=ALI@example.com');
  assert.equal(res.json().items[0].id, user.id);
  res = await call('GET', `/v1/users/${user.id}`);
  assert.equal(res.json().user.id, user.id);
  assert.equal((await call('GET', '/v1/users/usr_mgx1k2ab0123456789abcdef')).statusCode, 404);
  assert.equal((await call('GET', '/v1/users/not-uuid')).statusCode, 400);

  res = await call('POST', '/v1/auth/verify-email', { token: 'wrong-token' });
  assert.equal(res.statusCode, 401);
  assert.equal(res.json().error.code, 'INVALID_TOKEN');
  res = await call('POST', '/v1/auth/verify-email', { token: t.mailer.lastToken('verify') });
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().user.emailVerified, true);

  res = await call('POST', '/v1/auth/login', { email: 'ali@example.com', password: 'wrong password' });
  assert.equal(res.statusCode, 401);
  res = await call('POST', '/v1/auth/login', { email: 'ali@example.com', password: GOOD_PASSWORD });
  assert.equal(res.statusCode, 200);
  const { tokens } = res.json();
  assert.equal(tokens.tokenType, 'Bearer');
  assert.ok(Date.parse(tokens.accessTokenExpiresAt) > Date.now());

  res = await call('POST', '/v1/auth/introspect', { accessToken: tokens.accessToken });
  assert.equal(res.json().active, true);
  assert.equal(res.json().claims.sub, user.id);

  res = await call('POST', '/v1/auth/refresh', { refreshToken: tokens.refreshToken });
  assert.equal(res.statusCode, 200);
  const rotated = res.json().tokens;
  res = await call('POST', '/v1/auth/refresh', { refreshToken: tokens.refreshToken });
  assert.equal(res.statusCode, 401);
  assert.equal(res.json().error.code, 'TOKEN_REUSED');
  res = await call('POST', '/v1/auth/introspect', { accessToken: rotated.accessToken });
  assert.deepEqual({ active: res.json().active, reason: res.json().reason }, { active: false, reason: 'SESSION_REVOKED' });

  res = await call('POST', '/v1/auth/login', { email: 'ali@example.com', password: GOOD_PASSWORD });
  const live = res.json().tokens;
  res = await call('GET', `/v1/users/${user.id}/sessions`);
  assert.equal(res.json().items.length, 1);
  assert.equal(res.json().items[0].ip, '198.51.100.7', 'X-Client-IP recorded');
  assert.equal(res.json().items[0].userAgent, 'TestBrowser/1.0');
  assert.equal((await call('POST', '/v1/auth/logout', { refreshToken: live.refreshToken })).statusCode, 204);
  assert.equal((await call('GET', `/v1/users/${user.id}/sessions`)).json().items.length, 0);

  res = await call('GET', `/v1/users/${user.id}/events?limit=3`);
  assert.equal(res.json().items.length, 3);
  assert.ok(res.json().nextCursor);
  assert.equal(res.json().items[0].type, 'logout');
  assert.equal(res.json().items[0].ip, '198.51.100.7');
});

test('password flows: forgot, reset, change with X-Access-Token', async () => {
  let res = await call('POST', '/v1/users', { email: 'p@example.com', password: GOOD_PASSWORD });
  const userId = res.json().user.id;
  assert.equal((await call('POST', '/v1/auth/password/forgot', { email: 'nobody@example.com' })).statusCode, 202);
  assert.equal((await call('POST', '/v1/auth/password/forgot', { email: 'p@example.com' })).statusCode, 202);
  res = await call('POST', '/v1/auth/password/reset', { token: t.mailer.lastToken('reset'), password: 'a brand new strong password' });
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().user.emailVerified, true);

  res = await call('POST', '/v1/auth/login', { email: 'p@example.com', password: 'a brand new strong password' });
  const { accessToken } = res.json().tokens;
  res = await call('POST', '/v1/auth/password/change', { currentPassword: 'a brand new strong password', newPassword: 'yet another strong one' });
  assert.equal(res.statusCode, 401, 'missing X-Access-Token');
  res = await call('POST', '/v1/auth/password/change', { currentPassword: 'wrong', newPassword: 'yet another strong one' }, { 'x-access-token': accessToken });
  assert.equal(res.statusCode, 401);
  assert.equal(res.json().error.code, 'INVALID_CREDENTIALS');
  res = await call('POST', '/v1/auth/password/change', { currentPassword: 'a brand new strong password', newPassword: 'yet another strong one' }, { 'x-access-token': accessToken });
  assert.equal(res.statusCode, 204);
  assert.equal((await call('POST', '/v1/auth/login', { email: 'p@example.com', password: 'yet another strong one' })).statusCode, 200);

  res = await call('PATCH', `/v1/users/${userId}`, { status: 'disabled' });
  assert.equal(res.json().user.status, 'disabled');
  res = await call('POST', '/v1/auth/login', { email: 'p@example.com', password: 'yet another strong one' });
  assert.equal(res.statusCode, 403);
  assert.equal((await call('PATCH', `/v1/users/${userId}`, {})).statusCode, 400, 'empty patch rejected');
  assert.equal((await call('DELETE', `/v1/users/${userId}`)).statusCode, 204);
  assert.equal((await call('GET', `/v1/users/${userId}`)).statusCode, 404);
});

test('lockout returns 423 with Retry-After; metrics and user paging work', async () => {
  const locked = await testAuthService({ LOGIN_MAX_FAILURES: '3' });
  const lockedApp = await new AuthApi({ config: locked.config, service: locked.service, jwt: locked.signer, db: locked.db, mailer: locked.mailer, users: locked.users, sessions: locked.sessions, events: locked.events, version: '1.0.0', logger: silentLog }).build();
  await lockedApp.inject({ method: 'POST', url: '/v1/users', headers: auth, payload: { email: 'l@example.com', password: GOOD_PASSWORD } });
  for (let i = 0; i < 3; i++) await lockedApp.inject({ method: 'POST', url: '/v1/auth/login', headers: auth, payload: { email: 'l@example.com', password: 'nope' } });
  const res = await lockedApp.inject({ method: 'POST', url: '/v1/auth/login', headers: auth, payload: { email: 'l@example.com', password: GOOD_PASSWORD } });
  assert.equal(res.statusCode, 423);
  assert.ok(Number(res.headers['retry-after']) > 0);
  await lockedApp.close();

  for (let i = 0; i < 3; i++) await call('POST', '/v1/users', { email: `page${i}@example.com`, password: GOOD_PASSWORD });
  let page = await call('GET', '/v1/users?limit=2');
  assert.equal(page.json().items.length, 2);
  assert.ok(page.json().nextCursor);
  page = await call('GET', `/v1/users?limit=2&cursor=${page.json().nextCursor}`);
  assert.ok(page.json().items.length >= 1);
  assert.equal((await call('GET', '/v1/users?cursor=garbage')).json().error.code, 'INVALID_CURSOR');

  const metrics = await call('GET', '/metrics');
  assert.match(metrics.body, /auth_users\{status="active"\} \d+/);
  assert.match(metrics.body, /auth_sessions_active \d+/);

  const other = await app.inject({ url: '/v1/users', headers: { authorization: `Bearer ${OTHER_KEY}` } });
  assert.equal(other.statusCode, 200, 'second key works');
});

test('Stage 4: a key without the proxy flag cannot spoof X-Client-IP -- request.ip is used instead', async () => {
  const email = `proxytest-${Date.now()}@example.com`;
  let res = await call('POST', '/v1/users', { email, password: GOOD_PASSWORD }, {}); // "test" key: proxy-trusted
  const user = res.json().user;
  res = await call('POST', '/v1/auth/login', { email, password: GOOD_PASSWORD });
  const tokens = res.json().tokens;

  // Same X-Client-IP header, but presented with the non-proxy "other" key instead.
  res = await app.inject({
    method: 'POST', url: '/v1/auth/logout', payload: { refreshToken: tokens.refreshToken },
    headers: { authorization: `Bearer ${OTHER_KEY}`, 'x-client-ip': '198.51.100.7' },
  });
  assert.equal(res.statusCode, 204);

  res = await call('POST', '/v1/auth/login', { email, password: GOOD_PASSWORD }); // fresh session via the trusted "test" key
  const live = res.json().tokens;
  res = await app.inject({
    method: 'POST', url: '/v1/auth/refresh', payload: { refreshToken: live.refreshToken },
    headers: { authorization: `Bearer ${OTHER_KEY}`, 'x-client-ip': '198.51.100.7' }, // non-proxy key, same spoof attempt
  });
  assert.equal(res.statusCode, 200);
  const events = await call('GET', `/v1/users/${user.id}/events?limit=1`);
  assert.notEqual(events.json().items[0].ip, '198.51.100.7', 'the non-proxy key\'s X-Client-IP was not trusted');
  assert.equal(events.json().items[0].ip, '127.0.0.1', 'the socket peer address was used instead');
});

test('Stage 4: a read-only key cannot register, update or delete a user, but can still read', async () => {
  const readAuth = { authorization: `Bearer ${READ_KEY}` };
  let res = await app.inject({ method: 'POST', url: '/v1/users', payload: { email: `reader-${Date.now()}@example.com`, password: GOOD_PASSWORD }, headers: readAuth });
  assert.equal(res.statusCode, 403);
  assert.equal(res.json().error.code, 'FORBIDDEN');

  res = await call('POST', '/v1/users', { email: `writer-${Date.now()}@example.com`, password: GOOD_PASSWORD }); // create with the readwrite key
  const user = res.json().user;

  res = await app.inject({ method: 'PATCH', url: `/v1/users/${user.id}`, payload: { name: 'Blocked' }, headers: readAuth });
  assert.equal(res.statusCode, 403);
  res = await app.inject({ method: 'DELETE', url: `/v1/users/${user.id}`, headers: readAuth });
  assert.equal(res.statusCode, 403);
  res = await app.inject({ method: 'DELETE', url: `/v1/users/${user.id}/sessions`, headers: readAuth });
  assert.equal(res.statusCode, 403, 'a read-only key cannot revoke every session');
  res = await app.inject({ method: 'DELETE', url: `/v1/users/${user.id}/sessions/ses_mgx1k2ab0123456789abcdef`, headers: readAuth });
  assert.equal(res.statusCode, 403, 'a read-only key cannot revoke a session');

  res = await app.inject({ method: 'GET', url: `/v1/users/${user.id}`, headers: readAuth });
  assert.equal(res.statusCode, 200, 'reading is still allowed');
});

test('MFA over HTTP: setup and enable with X-Access-Token, MFA_REQUIRED at login, second step, admin reset', async () => {
  const email = 'mfa-http@example.com';
  await call('POST', '/v1/users', { email, password: GOOD_PASSWORD });
  t.users.markVerified(/** @type {any} */ (t.users.byEmail(email)).id, Date.now());
  let res = await call('POST', '/v1/auth/login', { email, password: GOOD_PASSWORD });
  const access = { 'x-access-token': res.json().tokens.accessToken };
  assert.equal((await call('POST', '/v1/auth/mfa/setup', { password: GOOD_PASSWORD })).statusCode, 401, 'needs the end user token');
  assert.equal((await call('POST', '/v1/auth/mfa/setup', { password: 'not the password' }, access)).statusCode, 401, 'the password is checked');
  res = await call('POST', '/v1/auth/mfa/setup', { password: GOOD_PASSWORD }, access);
  assert.equal(res.statusCode, 200);
  const { secret } = res.json();
  const { Totp } = await import('../src/crypto/totp.js');
  const now = (/** @type {number} */ d = 0) => Totp.code(secret, Math.floor(t.clock.now / 30_000) + d);
  res = await call('POST', '/v1/auth/mfa/enable', { password: GOOD_PASSWORD, code: now() }, access);
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().recoveryCodes.length, 10);
  res = await call('POST', '/v1/auth/login', { email, password: GOOD_PASSWORD });
  assert.equal(res.statusCode, 401);
  assert.equal(res.json().error.code, 'MFA_REQUIRED');
  const { mfaToken } = res.json().error.details;
  res = await call('POST', '/v1/auth/login/mfa', { mfaToken, code: '000000' });
  assert.equal(res.json().error.code, 'INVALID_MFA_CODE');
  res = await call('POST', '/v1/auth/login/mfa', { mfaToken, code: now(1) });
  assert.equal(res.statusCode, 200, res.body);
  assert.equal(res.json().user.mfaEnabled, true);
  const id = res.json().user.id;
  assert.equal((await call('DELETE', `/v1/users/${id}/mfa`, undefined, { authorization: `Bearer ${READ_KEY}` })).statusCode, 403);
  assert.equal((await call('DELETE', `/v1/users/${id}/mfa`)).statusCode, 204);
  assert.equal((await call('GET', `/v1/users/${id}`)).json().user.mfaEnabled, false);
});

test('Idempotency-Key: opt-in on admin create routes only; MFA secrets are never cached; identities never share replays', async () => {
  const body = { email: 'idem@example.com', password: GOOD_PASSWORD };
  const first = await call('POST', '/v1/users', body, { 'idempotency-key': 'create-idem-1' });
  const again = await call('POST', '/v1/users', body, { 'idempotency-key': 'create-idem-1' });
  assert.equal(first.statusCode, 201, first.body);
  assert.deepEqual([again.statusCode, again.headers['idempotent-replayed'], again.json().user.id], [201, 'true', first.json().user.id]);
  assert.match(first.json().user.id, /^usr_[0-9a-z]{6,12}[0-9a-f]{16}$/);
  const other = await call('POST', '/v1/users', body, { 'idempotency-key': 'create-idem-1', 'x-actor': 'someone-else' });
  assert.equal(other.headers['idempotent-replayed'], undefined, 'another identity is not served the stored answer');
  assert.equal(other.statusCode, 409, 'it runs for real (the address exists)');
  t.users.markVerified(first.json().user.id, Date.now());
  const login = await call('POST', '/v1/auth/login', body, { 'idempotency-key': 'login-idem-1' });
  const access = { 'x-access-token': login.json().tokens.accessToken, 'idempotency-key': 'mfa-setup-idem-1' };
  const s1 = await call('POST', '/v1/auth/mfa/setup', { password: GOOD_PASSWORD }, access);
  const s2 = await call('POST', '/v1/auth/mfa/setup', { password: GOOD_PASSWORD }, access);
  assert.equal(s1.statusCode, 200, s1.body);
  assert.notEqual(s1.json().secret, s2.json().secret, 'each setup returns a new secret, never a replay');
  assert.equal(s2.headers['idempotent-replayed'], undefined);
  const stored = /** @type {any} */ (t.db.raw.prepare("SELECT COUNT(*) AS n FROM service_idempotency WHERE idem_key IN ('login-idem-1', 'mfa-setup-idem-1')").get());
  assert.equal(stored.n, 0);
});
