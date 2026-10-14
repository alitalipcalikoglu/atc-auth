import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ctx, GOOD_PASSWORD, testAuthService } from './helpers.js';

const code = (/** @type {string} */ c) => (/** @type {any} */ e) => e.code === c;
const at = (/** @type {string} */ ip, /** @type {string} */ ua = 'agent-1') => ({ ip, userAgent: ua });

test('lockout is per account and client address with backoff; one address cannot lock the owner out elsewhere', async () => {
  const t = await testAuthService({ LOGIN_MAX_FAILURES: '3', LOGIN_LOCKOUT_MIN: '10', LOGIN_REQUIRES_VERIFIED_EMAIL: 'false' });
  await t.service.register({ email: 'a@example.com', password: GOOD_PASSWORD }, ctx);
  const bad = (/** @type {string} */ ip) => t.service.login({ email: 'a@example.com', password: 'wrong password here' }, at(ip));
  for (let i = 0; i < 3; i += 1) await assert.rejects(bad('203.0.113.1'), code('INVALID_CREDENTIALS'));
  await assert.rejects(bad('203.0.113.1'), code('ACCOUNT_LOCKED'), 'the attacking address is locked');
  await assert.rejects(t.service.login({ email: 'a@example.com', password: GOOD_PASSWORD }, at('203.0.113.1')), code('ACCOUNT_LOCKED'), 'even with the right password while locked');
  const ok = await t.service.login({ email: 'a@example.com', password: GOOD_PASSWORD }, at('198.51.100.7'));
  assert.ok(ok.tokens.accessToken, 'the owner signs in from another address');
  t.clock.now += 11 * 60_000;
  for (let i = 0; i < 3; i += 1) await assert.rejects(bad('203.0.113.1'), code('INVALID_CREDENTIALS'));
  await assert.rejects(bad('203.0.113.1'), (/** @type {any} */ e) => e.code === 'ACCOUNT_LOCKED' && e.details.retryAfterSec > 15 * 60, 'the second lockout of the same address lasts twice as long');
  t.clock.now += 25 * 60_000;
  assert.ok((await t.service.login({ email: 'a@example.com', password: GOOD_PASSWORD }, at('203.0.113.1'))).tokens.accessToken, 'and ends');
});

test('lockout backstop: many addresses together still lock the account', async () => {
  const t = await testAuthService({ LOGIN_MAX_FAILURES: '3', LOGIN_MAX_FAILURES_TOTAL: '5', LOGIN_REQUIRES_VERIFIED_EMAIL: 'false' });
  await t.service.register({ email: 'b@example.com', password: GOOD_PASSWORD }, ctx);
  for (let i = 0; i < 5; i += 1) await assert.rejects(t.service.login({ email: 'b@example.com', password: 'nope nope nope nope' }, at(`192.0.2.${i + 1}`)), code('INVALID_CREDENTIALS'));
  await assert.rejects(t.service.login({ email: 'b@example.com', password: GOOD_PASSWORD }, at('192.0.2.200')), code('ACCOUNT_LOCKED'));
});

test('sessions are capped per user: the least recently used one is signed out; a new device gets a notice, the first one does not', async () => {
  const t = await testAuthService({ MAX_SESSIONS: '2', LOGIN_REQUIRES_VERIFIED_EMAIL: 'false' });
  const { user } = await t.service.register({ email: 'c@example.com', password: GOOD_PASSWORD }, ctx);
  const login = async (/** @type {string} */ ua) => { t.clock.now += 1_000; return t.service.login({ email: 'c@example.com', password: GOOD_PASSWORD }, at('203.0.113.9', ua)); };
  const first = await login('laptop');
  assert.equal(t.mailer.notices.length, 0, 'the very first device is not announced');
  await login('laptop');
  assert.equal(t.mailer.notices.length, 0, 'a known device is not announced');
  await login('phone');
  assert.deepEqual(t.mailer.notices.map((n) => [n.kind, n.to, n.details.userAgent]), [['new_device', 'c@example.com', 'phone']]);
  assert.equal(t.service.listSessions(user.id).length, 2, 'cap of two');
  assert.equal(t.sessions.byId(first.tokens.sessionId)?.revoked_at !== null, true, 'the oldest session was revoked');
  const off = await testAuthService({ NEW_DEVICE_EMAIL: 'false', LOGIN_REQUIRES_VERIFIED_EMAIL: 'false' });
  await off.service.register({ email: 'd@example.com', password: GOOD_PASSWORD }, ctx);
  await off.service.login({ email: 'd@example.com', password: GOOD_PASSWORD }, at('1.1.1.1', 'a'));
  await off.service.login({ email: 'd@example.com', password: GOOD_PASSWORD }, at('1.1.1.1', 'b'));
  assert.equal(off.mailer.notices.length, 0, 'switched off');
});

test('email change: proven with the password, confirmed from the new mailbox, old address told; taken addresses leak nothing', async () => {
  const t = await testAuthService({ LOGIN_REQUIRES_VERIFIED_EMAIL: 'false' });
  const { user } = await t.service.register({ email: 'old@example.com', password: GOOD_PASSWORD }, ctx);
  await t.service.register({ email: 'taken@example.com', password: GOOD_PASSWORD }, ctx);
  await assert.rejects(t.service.requestEmailChange({ email: 'old@example.com', password: 'wrong wrong wrong', newEmail: 'new@example.com' }, ctx), code('INVALID_CREDENTIALS'));
  await assert.rejects(t.service.requestEmailChange({ email: 'old@example.com', password: GOOD_PASSWORD, newEmail: 'OLD@example.com' }, ctx), code('INVALID_ARGUMENT'));
  const before = t.mailer.sent.length;
  await t.service.requestEmailChange({ email: 'old@example.com', password: GOOD_PASSWORD, newEmail: 'taken@example.com' }, ctx);
  assert.equal(t.mailer.sent.length, before, 'no mail and no error for an address in use');
  await t.service.requestEmailChange({ email: 'old@example.com', password: GOOD_PASSWORD, newEmail: 'New@Example.com' }, ctx);
  const mail = t.mailer.sent.at(-1);
  assert.deepEqual([mail?.kind, mail?.to], ['change', 'new@example.com']);
  assert.equal(t.users.byId(user.id)?.email, 'old@example.com', 'nothing changes before the link is used');
  const done = await t.service.confirmEmailChange(t.mailer.lastToken('change'), ctx);
  assert.deepEqual([done.email, done.email_verified_at !== null], ['new@example.com', true]);
  assert.deepEqual(t.mailer.notices.map((n) => [n.kind, n.to]), [['email_changed', 'old@example.com']]);
  await assert.rejects(t.service.confirmEmailChange(t.mailer.lastToken('change'), ctx), code('INVALID_TOKEN'), 'single use');
  assert.ok((await t.service.login({ email: 'new@example.com', password: GOOD_PASSWORD }, ctx)).tokens.accessToken);
  await assert.rejects(t.service.login({ email: 'old@example.com', password: GOOD_PASSWORD }, ctx), code('INVALID_CREDENTIALS'));
  const admin = await t.service.adminSetEmail(user.id, 'admin-set@example.com', ctx);
  assert.deepEqual([admin.email, admin.email_verified_at], ['admin-set@example.com', null]);
  assert.equal(t.mailer.sent.at(-1)?.kind, 'verify');
  await assert.rejects(t.service.adminSetEmail(user.id, 'taken@example.com', ctx), code('EMAIL_TAKEN'));
});

test('personal data: export lists what is stored; anonymize erases the person but keeps the row and its id', async () => {
  const published = /** @type {any[]} */ ([]);
  const t = await testAuthService({ LOGIN_REQUIRES_VERIFIED_EMAIL: 'false' }, { publish: (/** @type {string} */ ty, /** @type {any} */ d) => published.push([ty, d]) });
  const { user } = await t.service.register({ email: 'gdpr@example.com', password: GOOD_PASSWORD, name: 'Ada' }, ctx);
  await t.service.login({ email: 'gdpr@example.com', password: GOOD_PASSWORD }, at('203.0.113.50'));
  const dump = t.service.exportUser(user.id);
  assert.deepEqual([dump.user.email, dump.user.name, dump.sessions.length, dump.events.map((e) => e.type).sort().includes('login.succeeded')], ['gdpr@example.com', 'Ada', 1, true]);
  assert.equal(dump.events.some((e) => e.ip === '203.0.113.50'), true);
  assert.equal(JSON.stringify(dump).includes('password_hash'), false);
  await t.service.anonymize(user.id, ctx);
  const after = t.users.byId(user.id);
  assert.deepEqual([after?.email.endsWith('@anonymized.invalid'), after?.name, after?.status], [true, null, 'disabled']);
  assert.equal(t.service.listSessions(user.id).length, 0);
  const scrubbed = t.service.exportUser(user.id);
  assert.equal(scrubbed.events.some((e) => e.ip === '203.0.113.50'), false, 'recorded addresses are gone');
  assert.equal(scrubbed.events[0].type, 'account.anonymized');
  await assert.rejects(t.service.login({ email: 'gdpr@example.com', password: GOOD_PASSWORD }, ctx), code('INVALID_CREDENTIALS'));
  assert.deepEqual(published.at(-1), ['auth.user.anonymized', { id: user.id }]);
});
