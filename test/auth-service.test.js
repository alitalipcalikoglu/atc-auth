import assert from 'node:assert/strict';
import { test } from 'node:test';
import { PasswordHasher } from '../src/crypto/password.js';
import { AuthError } from '../src/domain/errors.js';
import { PasswordPolicy } from '../src/domain/password-policy.js';
import { ctx, GOOD_PASSWORD, testAuthService } from './helpers.js';

/** @param {Promise<unknown>} p @param {string} code */
const rejectsWith = (p, code) => assert.rejects(p, (e) => e instanceof AuthError && e.code === code ? true : (console.error(e), false));
/** @param {() => unknown} fn @param {string} code */
const throwsWith = (fn, code) => assert.throws(fn, (e) => e instanceof AuthError && e.code === code);

test('PasswordPolicy rejects short, common, repetitive and email-derived passwords', () => {
  const p = new PasswordPolicy({ minLength: 10 });
  assert.deepEqual(p.problems(GOOD_PASSWORD, { email: 'ali@example.com' }), []);
  assert.ok(p.problems('short').length);
  assert.ok(p.problems('password1234').some((s) => /common/.test(s)));
  assert.ok(p.problems('P@ssw0rd!!').some((s) => /common/.test(s)));
  assert.ok(p.problems('aaaaaaaaaaaa').some((s) => /repeat/.test(s)));
  assert.ok(p.problems(' padded password ').some((s) => /whitespace/.test(s)));
  assert.ok(p.problems('alitalip2024!', { email: 'alitalip@example.com' }).some((s) => /email/.test(s)));
  assert.ok(p.problems('x'.repeat(300)).some((s) => /at most/.test(s)));
});

test('register → verify email → login issues a token pair and audit events', async () => {
  const t = await testAuthService();
  const { user, verificationEmailSent } = await t.service.register({ email: 'Ali@Example.com', password: GOOD_PASSWORD, name: 'Ali' }, ctx);
  assert.equal(user.email, 'ali@example.com');
  assert.equal(user.email_verified_at, null);
  assert.equal(verificationEmailSent, true);
  assert.equal(t.mailer.sent[0].to, 'ali@example.com');
  assert.match(t.mailer.sent[0].url, /^https:\/\/shop\.test\.local\/verify\?token=/);

  await rejectsWith(t.service.register({ email: 'ali@example.com', password: GOOD_PASSWORD }, ctx), 'EMAIL_TAKEN');
  await rejectsWith(t.service.register({ email: 'b@example.com', password: 'short' }, ctx), 'WEAK_PASSWORD');

  const verified = t.service.verifyEmail(t.mailer.lastToken('verify'), ctx);
  assert.ok(verified.email_verified_at);
  throwsWith(() => t.service.verifyEmail(t.mailer.lastToken('verify'), ctx), 'INVALID_TOKEN');
  const before = t.mailer.sent.length;
  await t.service.resendVerification('ali@example.com', ctx); // silent: already verified
  assert.equal(t.mailer.sent.length, before, 'no mail for an already-verified address');
  await t.service.resendVerification('nobody@example.com', ctx); // silent

  const { tokens, user: loggedIn } = await t.service.login({ email: 'ALI@example.com', password: GOOD_PASSWORD }, ctx);
  assert.equal(loggedIn.id, user.id);
  assert.ok(tokens.accessToken.split('.').length === 3);
  const accessTtl = tokens.accessTokenExpiresAt - t.clock.now;
  assert.ok(accessTtl > 899_000 && accessTtl <= 900_000, `access ttl ${accessTtl}`);
  assert.equal(tokens.refreshTokenExpiresAt - t.clock.now, 30 * 86_400_000);
  const claims = await t.signer.verify(tokens.accessToken);
  assert.equal(claims.sub, user.id);
  assert.equal(claims.sid, tokens.sessionId);
  assert.equal(claims.email_verified, true);

  const types = t.events.forUser(user.id, { limit: 20 }).map((e) => e.type);
  assert.deepEqual(types, ['login.succeeded', 'email.verified', 'user.registered']);
});

test('registration succeeds when the mailer fails and resend is throttled', async () => {
  const t = await testAuthService({ RESEND_COOLDOWN_SEC: '60' });
  t.mailer.fail = new Error('notify down');
  const { verificationEmailSent } = await t.service.register({ email: 'a@example.com', password: GOOD_PASSWORD }, ctx);
  assert.equal(verificationEmailSent, false);
  t.mailer.fail = null;
  await t.service.resendVerification('a@example.com', ctx); // silent: inside the cooldown
  assert.equal(t.mailer.sent.length, 0, 'throttled resend sends nothing');
  t.clock.now += 61_000;
  await t.service.resendVerification('a@example.com', ctx);
  assert.equal(t.mailer.sent.length, 1);
  t.service.verifyEmail(t.mailer.lastToken('verify'), ctx);
});

test('an unknown e-mail burns CPU at the configured scrypt cost, not a hardcoded one', async () => {
  const t = await testAuthService({ SCRYPT_LOG_N: '16' });
  /** @type {string[]} */
  const verifiedAgainst = [];
  const realVerify = t.service.hasher.verify.bind(t.service.hasher);
  t.service.hasher.verify = (password, stored) => { verifiedAgainst.push(stored); return realVerify(password, stored); };
  await rejectsWith(t.service.login({ email: 'nobody@example.com', password: 'x' }, ctx), 'INVALID_CREDENTIALS');
  assert.equal(verifiedAgainst.length, 1);
  const parsed = PasswordHasher.parse(verifiedAgainst[0]);
  assert.equal(parsed?.logN, 16, 'the dummy hash used for an unknown account matches the configured SCRYPT_LOG_N, not a fixed logN 14');
});

test('login failures lock the account, disabled accounts and unverified emails are refused', async () => {
  const t = await testAuthService({ LOGIN_MAX_FAILURES: '3', LOGIN_LOCKOUT_MIN: '15' });
  const { user } = await t.service.register({ email: 'a@example.com', password: GOOD_PASSWORD }, ctx);
  await rejectsWith(t.service.login({ email: 'nobody@example.com', password: 'x' }, ctx), 'INVALID_CREDENTIALS');
  for (let i = 0; i < 3; i++) await rejectsWith(t.service.login({ email: 'a@example.com', password: 'wrong' }, ctx), 'INVALID_CREDENTIALS');
  const locked = await t.service.login({ email: 'a@example.com', password: GOOD_PASSWORD }, ctx).catch((e) => e);
  assert.equal(locked.code, 'ACCOUNT_LOCKED');
  assert.ok(locked.details.retryAfterSec > 0 && locked.details.retryAfterSec <= 900);
  t.clock.now += 15 * 60_000 + 1;
  await t.service.login({ email: 'a@example.com', password: GOOD_PASSWORD }, ctx);
  assert.equal(t.users.byId(user.id)?.failed_logins, 0);

  t.service.updateUser(user.id, { status: 'disabled' }, ctx);
  await rejectsWith(t.service.login({ email: 'a@example.com', password: GOOD_PASSWORD }, ctx), 'ACCOUNT_DISABLED');
  assert.equal(t.sessions.activeForUser(user.id, t.clock.now).length, 0, 'disabling revokes sessions');
  t.service.updateUser(user.id, { status: 'active', name: 'Renamed' }, ctx);
  assert.equal(t.users.byId(user.id)?.name, 'Renamed');

  const strict = await testAuthService({ LOGIN_REQUIRES_VERIFIED_EMAIL: 'true' });
  await strict.service.register({ email: 'u@example.com', password: GOOD_PASSWORD }, ctx);
  await rejectsWith(strict.service.login({ email: 'u@example.com', password: GOOD_PASSWORD }, ctx), 'EMAIL_NOT_VERIFIED');
  strict.service.verifyEmail(strict.mailer.lastToken('verify'), ctx);
  await strict.service.login({ email: 'u@example.com', password: GOOD_PASSWORD }, ctx);
});

test('refresh rotates tokens, replay revokes the session, logout and introspection work', async () => {
  const t = await testAuthService();
  await t.service.register({ email: 'a@example.com', password: GOOD_PASSWORD }, ctx);
  const first = await t.service.login({ email: 'a@example.com', password: GOOD_PASSWORD }, ctx);
  t.clock.now += 1000;
  const second = await t.service.refresh(first.tokens.refreshToken, ctx);
  assert.equal(second.tokens.sessionId, first.tokens.sessionId);
  assert.notEqual(second.tokens.refreshToken, first.tokens.refreshToken);
  assert.notEqual(second.tokens.accessToken, first.tokens.accessToken);
  assert.deepEqual(await t.service.introspect(second.tokens.accessToken).then((r) => r.active), true);

  await rejectsWith(t.service.refresh(first.tokens.refreshToken, ctx), 'TOKEN_REUSED');
  await rejectsWith(t.service.refresh(second.tokens.refreshToken, ctx), 'INVALID_TOKEN');
  const intro = await t.service.introspect(second.tokens.accessToken);
  assert.deepEqual({ active: intro.active, reason: intro.reason }, { active: false, reason: 'SESSION_REVOKED' });
  assert.ok(t.events.forUser(second.user.id, { limit: 20 }).some((e) => e.type === 'session.reuse_detected'));

  await rejectsWith(t.service.refresh('not-a-token', ctx), 'INVALID_TOKEN');
  assert.equal((await t.service.introspect('garbage')).active, false);

  const third = await t.service.login({ email: 'a@example.com', password: GOOD_PASSWORD }, ctx);
  t.clock.now += 31 * 86_400_000;
  await rejectsWith(t.service.refresh(third.tokens.refreshToken, ctx), 'INVALID_TOKEN');

  const fourth = await t.service.login({ email: 'a@example.com', password: GOOD_PASSWORD }, ctx);
  t.service.logout(fourth.tokens.refreshToken, ctx);
  t.service.logout(fourth.tokens.refreshToken, ctx); // idempotent
  await rejectsWith(t.service.refresh(fourth.tokens.refreshToken, ctx), 'INVALID_TOKEN');
});

test('forgot/reset password revokes sessions and verifies the mailbox; change password keeps the current session', async () => {
  const t = await testAuthService({ RESEND_COOLDOWN_SEC: '0' });
  const { user } = await t.service.register({ email: 'a@example.com', password: GOOD_PASSWORD }, ctx);
  const s1 = await t.service.login({ email: 'a@example.com', password: GOOD_PASSWORD }, ctx);
  await t.service.forgotPassword('nobody@example.com', ctx);
  assert.equal(t.mailer.sent.filter((m) => m.kind === 'reset').length, 0);
  await t.service.forgotPassword('a@example.com', ctx);
  const resetToken = t.mailer.lastToken('reset');
  await rejectsWith(t.service.resetPassword({ token: resetToken, password: 'short' }, ctx), 'WEAK_PASSWORD');
  const after = await t.service.resetPassword({ token: resetToken, password: 'another very good password' }, ctx);
  assert.ok(after.email_verified_at, 'reset proves mailbox ownership');
  await rejectsWith(t.service.resetPassword({ token: resetToken, password: 'another very good password' }, ctx), 'INVALID_TOKEN');
  await rejectsWith(t.service.refresh(s1.tokens.refreshToken, ctx), 'INVALID_TOKEN');
  await rejectsWith(t.service.login({ email: 'a@example.com', password: GOOD_PASSWORD }, ctx), 'INVALID_CREDENTIALS');

  const a = await t.service.login({ email: 'a@example.com', password: 'another very good password' }, ctx);
  const b = await t.service.login({ email: 'a@example.com', password: 'another very good password' }, ctx);
  await rejectsWith(t.service.changePassword({ userId: user.id, sessionId: a.tokens.sessionId, currentPassword: 'wrong', newPassword: 'third strong password!' }, ctx), 'INVALID_CREDENTIALS');
  await t.service.changePassword({ userId: user.id, sessionId: a.tokens.sessionId, currentPassword: 'another very good password', newPassword: 'third strong password!' }, ctx);
  await t.service.refresh(a.tokens.refreshToken, ctx);
  await rejectsWith(t.service.refresh(b.tokens.refreshToken, ctx), 'INVALID_TOKEN');

  assert.equal(t.service.listSessions(user.id).length, 1);
  throwsWith(() => t.service.revokeSession(user.id, 'nope', ctx), 'SESSION_NOT_FOUND');
  assert.equal(t.service.revokeAllSessions(user.id, ctx), 1);
  t.service.deleteUser(user.id, ctx);
  throwsWith(() => t.service.listSessions(user.id), 'USER_NOT_FOUND');
});

test('forgot-password inside the cooldown is a silent no-op, not an error', async () => {
  const t = await testAuthService({ RESEND_COOLDOWN_SEC: '60' });
  await t.service.register({ email: 'f@example.com', password: GOOD_PASSWORD }, ctx);
  const before = t.mailer.sent.length;
  await t.service.forgotPassword('f@example.com', ctx);
  await t.service.forgotPassword('f@example.com', ctx); // silent: inside the cooldown
  assert.equal(t.mailer.sent.length, before + 1, 'only the first request sends a mail');
});

test('events: user lifecycle is published with ids only, never e-mail addresses', async () => {
  /** @type {[string, any][]} */ const out = [];
  const t = await testAuthService({}, { publish: (/** @type {string} */ type, /** @type {any} */ data) => out.push([type, data]) });
  const { user } = await t.service.register({ email: 'ev@example.com', password: GOOD_PASSWORD }, ctx);
  t.service.updateUser(user.id, { name: 'No status change' }, ctx);
  t.service.updateUser(user.id, { status: 'disabled' }, ctx);
  t.service.updateUser(user.id, { status: 'disabled' }, ctx);
  t.service.updateUser(user.id, { status: 'active' }, ctx);
  t.service.deleteUser(user.id, ctx);
  assert.deepEqual(out.map(([type]) => type), ['auth.user.created', 'auth.user.disabled', 'auth.user.enabled', 'auth.user.deleted']);
  assert.ok(out.every(([, d]) => Object.keys(d).join() === 'id' && d.id === user.id));
});
