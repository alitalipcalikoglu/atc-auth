import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Totp } from '../src/crypto/totp.js';
import { BreachCheck } from '../src/domain/breach-check.js';
import { GOOD_PASSWORD, testAuthService } from './helpers.js';

const code = (/** @type {string} */ c) => (/** @type {any} */ e) => e.code === c;
const at = (/** @type {string} */ ip) => ({ ip, userAgent: 'agent' });
const ctx = at('203.0.113.5');

/** A user with MFA on; returns the secret and the recovery codes. */
async function enrolled(/** @type {Record<string, string>} */ env = {}) {
  const t = await testAuthService({ LOGIN_REQUIRES_VERIFIED_EMAIL: 'false', ...env });
  const { user } = await t.service.register({ email: 'm@example.com', password: GOOD_PASSWORD }, ctx);
  const { secret, otpauthUrl } = t.service.mfaSetup(user.id, ctx);
  assert.match(otpauthUrl, /^otpauth:\/\/totp\/Shop%3Am%40example\.com\?secret=/);
  await assert.rejects(t.service.mfaEnable(user.id, '000000', ctx), code('INVALID_MFA_CODE'));
  const totp = (/** @type {number} */ offsetSec = 0) => Totp.code(secret, Math.floor((t.clock.now / 1000 + offsetSec) / 30));
  const recovery = await t.service.mfaEnable(user.id, totp(), ctx);
  t.clock.now += 30_000; // the enrolment code's step is used up
  return { t, user, secret, totp, recovery };
}

/** The challenge token from the password step. @param {any} t */
async function passwordStep(t, ip = '203.0.113.5') {
  const err = await t.service.login({ email: 'm@example.com', password: GOOD_PASSWORD }, at(ip)).then(() => null, (/** @type {any} */ e) => e);
  assert.equal(err?.code, 'MFA_REQUIRED');
  return /** @type {string} */ (err.details.mfaToken);
}

test('MFA enrolment, sign-in in two steps, each code once, recovery codes once', async () => {
  const { t, user, totp, recovery } = await enrolled();
  assert.equal(recovery.length, 10);
  assert.match(recovery[0], /^[A-Z2-9]{5}-[A-Z2-9]{5}$/);
  assert.equal(t.users.byId(user.id)?.mfa_enabled_at !== null, true);
  assert.deepEqual(t.mailer.notices.map((n) => n.kind), ['mfa_enabled']);
  assert.throws(() => t.service.mfaSetup(user.id, ctx), code('MFA_ALREADY_ENABLED'));

  const challenge = await passwordStep(t);
  const c = totp();
  const ok = await t.service.loginMfa({ mfaToken: challenge, code: c }, ctx);
  assert.ok(ok.tokens.accessToken);
  await assert.rejects(t.service.loginMfa({ mfaToken: challenge, code: c }, ctx), code('INVALID_TOKEN'), 'a challenge is used once');
  await assert.rejects(t.service.loginMfa({ mfaToken: await passwordStep(t), code: c }, ctx), code('INVALID_MFA_CODE'), 'the same code is not accepted twice');

  const viaRecovery = await t.service.loginMfa({ mfaToken: await passwordStep(t), code: recovery[0].toLowerCase().replace('-', ' ') }, ctx);
  assert.ok(viaRecovery.tokens.accessToken, 'a recovery code works, in any case and spacing');
  await assert.rejects(t.service.loginMfa({ mfaToken: await passwordStep(t), code: recovery[0] }, ctx), code('INVALID_MFA_CODE'), 'and only once');
  assert.equal(t.service.mfa.recoveryCodesLeft(user.id), 9);

  const expired = await passwordStep(t);
  t.clock.now += 301_000;
  await assert.rejects(t.service.loginMfa({ mfaToken: expired, code: totp() }, ctx), code('INVALID_TOKEN'), 'the challenge expires');
});

test('MFA: wrong codes count toward the lockout; a challenge allows five tries', async () => {
  const { t, totp } = await enrolled({ LOGIN_MAX_FAILURES: '3' });
  const challenge = await passwordStep(t, '198.51.100.1');
  for (let i = 0; i < 3; i += 1) await assert.rejects(t.service.loginMfa({ mfaToken: challenge, code: '111111' }, at('198.51.100.1')), code('INVALID_MFA_CODE'));
  await assert.rejects(t.service.loginMfa({ mfaToken: challenge, code: totp() }, at('198.51.100.1')), code('ACCOUNT_LOCKED'), 'locked even with a right code');
  const other = await passwordStep(t, '192.0.2.10');
  for (let i = 0; i < 5; i += 1) await t.service.loginMfa({ mfaToken: other, code: '222222' }, at(`192.0.2.${20 + i}`)).catch(() => {});
  await assert.rejects(t.service.loginMfa({ mfaToken: other, code: totp() }, at('192.0.2.99')), code('INVALID_TOKEN'), 'five wrong codes spend the challenge');
});

test('MFA: disable needs the password and a code; new recovery codes; admin reset; unavailable without a key', async () => {
  const { t, user, totp, recovery } = await enrolled();
  await assert.rejects(t.service.mfaDisable(user.id, { password: 'wrong wrong wrong', code: totp() }, ctx), code('INVALID_CREDENTIALS'));
  await assert.rejects(t.service.mfaDisable(user.id, { password: GOOD_PASSWORD, code: '123456' }, ctx), code('INVALID_MFA_CODE'));
  const fresh = t.service.mfaRecoveryCodes(user.id, totp(), ctx);
  assert.equal(fresh.length, 10);
  await assert.rejects(t.service.loginMfa({ mfaToken: await passwordStep(t), code: recovery[1] }, ctx), code('INVALID_MFA_CODE'), 'old recovery codes stop working');
  await t.service.mfaDisable(user.id, { password: GOOD_PASSWORD, code: fresh[0] }, ctx);
  assert.equal(t.users.byId(user.id)?.mfa_enabled_at, null);
  assert.ok((await t.service.login({ email: 'm@example.com', password: GOOD_PASSWORD }, ctx)).tokens.accessToken, 'one step again');

  const again = await enrolled();
  await again.t.service.adminResetMfa(again.user.id, ctx);
  assert.equal(again.t.users.byId(again.user.id)?.mfa_enabled_at, null);
  assert.equal(again.t.mailer.notices.at(-1)?.kind, 'mfa_reset');
  await assert.rejects(again.t.service.adminResetMfa(again.user.id, ctx), code('MFA_NOT_ENABLED'));
  assert.ok(again.t.events.forUser(again.user.id, { limit: 50 }).some((e) => e.type === 'mfa.reset'));

  const off = await testAuthService({ MFA_SECRETS_KEY: '' });
  const { user: u } = await off.service.register({ email: 'n@example.com', password: GOOD_PASSWORD }, ctx);
  assert.throws(() => off.service.mfaSetup(u.id, ctx), code('MFA_UNAVAILABLE'));
});

test('password history: the current and the last N passwords cannot come back', async () => {
  const t = await testAuthService({ PASSWORD_HISTORY: '3', LOGIN_REQUIRES_VERIFIED_EMAIL: 'false' });
  const { user } = await t.service.register({ email: 'h@example.com', password: GOOD_PASSWORD }, ctx);
  const session = (await t.service.login({ email: 'h@example.com', password: GOOD_PASSWORD }, ctx)).tokens.sessionId;
  const change = (/** @type {string} */ from, /** @type {string} */ to) => t.service.changePassword({ userId: user.id, sessionId: session, currentPassword: from, newPassword: to }, ctx);
  await assert.rejects(change(GOOD_PASSWORD, GOOD_PASSWORD), (/** @type {any} */ e) => e.code === 'WEAK_PASSWORD' && /last 3 passwords/.test(e.message));
  await change(GOOD_PASSWORD, 'second horse battery staple');
  await change('second horse battery staple', 'third horse battery staple');
  await assert.rejects(change('third horse battery staple', GOOD_PASSWORD), code('WEAK_PASSWORD'), 'two back is still remembered');
  await change('third horse battery staple', 'fourth horse battery staple');
  await change('fourth horse battery staple', GOOD_PASSWORD); // four back: allowed with a history of 3
  const off = await testAuthService({ PASSWORD_HISTORY: '0', LOGIN_REQUIRES_VERIFIED_EMAIL: 'false' });
  const { user: u } = await off.service.register({ email: 'o@example.com', password: GOOD_PASSWORD }, ctx);
  await off.service.changePassword({ userId: u.id, sessionId: 'x', currentPassword: GOOD_PASSWORD, newPassword: GOOD_PASSWORD }, ctx);
});

test('breach check: k-anonymity range lookup, a hit is refused, an outage lets the password through', async () => {
  /** @type {string[]} */ const asked = [];
  const breach = new BreachCheck({
    url: 'https://range.test', timeoutMs: 500,
    fetch: /** @type {any} */ (async (/** @type {string} */ url) => {
      asked.push(url);
      // SHA-1 of "correct horse battery staple" starts with ABF7A; its suffix is listed with a count.
      return new Response('AD6438836DBE526AA231ABDE2D0EEF74D42:42\r\n0000000000000000000000000000000000A:0\r\n');
    }),
  });
  assert.equal(await breach.count(GOOD_PASSWORD), 42);
  assert.deepEqual(asked, ['https://range.test/range/ABF7A'], 'only five characters of the hash leave');
  assert.equal(await breach.count('another long passphrase here'), 0);
  const t = await testAuthService({}, undefined, { breach });
  await assert.rejects(t.service.register({ email: 'b@example.com', password: GOOD_PASSWORD }, ctx), (/** @type {any} */ e) => e.code === 'WEAK_PASSWORD' && /breach/.test(e.message));
  const down = new BreachCheck({ url: 'https://range.test', timeoutMs: 500, fetch: /** @type {any} */ (async () => { throw new Error('offline'); }) });
  assert.equal(await down.count(GOOD_PASSWORD), null);
  const t2 = await testAuthService({}, undefined, { breach: down });
  assert.ok((await t2.service.register({ email: 'c@example.com', password: GOOD_PASSWORD }, ctx)).user.id);
});
