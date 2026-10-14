import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Config, ConfigError } from '../src/config.js';
import { fullEnv, testConfig } from './helpers.js';

test('defaults apply and required values are enforced', () => {
  const c = testConfig();
  assert.equal(c.port, 3002);
  assert.equal(c.accessTokenTtlSec, 900);
  assert.equal(c.emailLocale, 'tr');
  assert.equal(c.notifyUrl, 'http://127.0.0.1:1', 'trailing slash stripped');
  assert.deepEqual(c.apiKeys.map((k) => k.id), ['test', 'other', 'reader']);
  assert.deepEqual(c.apiKeys.map((k) => [k.role, k.scopes]), [['readwrite', ['proxy']], ['readwrite', null], ['read', null]], 'a key with no role (the "other" key) defaults to readwrite, same access as before Stage 4');
  for (const missing of ['AUTH_API_KEYS', 'JWT_PRIVATE_KEY_PATH', 'JWT_ISSUER', 'JWT_AUDIENCE', 'NOTIFY_URL', 'NOTIFY_API_KEY', 'APP_NAME', 'VERIFY_URL_TEMPLATE', 'RESET_URL_TEMPLATE']) {
    assert.throws(() => Config.fromEnv({ ...fullEnv(), [missing]: '' }), ConfigError, missing);
  }
});

test('rejects malformed values', () => {
  const bad = [
    { AUTH_API_KEYS: 'a:short' }, { JWT_ISSUER: 'auth.local' }, { NOTIFY_URL: 'ftp://x' }, { NOTIFY_API_KEY: 'short' },
    { EMAIL_LOCALE: 'de' }, { VERIFY_URL_TEMPLATE: 'https://x/verify' }, { RESET_URL_TEMPLATE: 'http://x/reset?t={token}' },
    { ACCESS_TOKEN_TTL_SEC: '10' }, { SCRYPT_LOG_N: '12' }, { TLS_CERT_PATH: '/c.pem' }, { PASSWORD_MIN_LENGTH: '4' },
  ];
  for (const o of bad) assert.throws(() => Config.fromEnv({ ...fullEnv(), ...o }), ConfigError, JSON.stringify(o));
});

test('Config: WEBHOOK_OUT_URL and WEBHOOK_OUT_API_KEY come together', () => {
  assert.equal(testConfig().webhookOut, null);
  assert.equal(testConfig({ WEBHOOK_OUT_URL: 'http://h:3009/', WEBHOOK_OUT_API_KEY: 'k' }).webhookOut?.url, 'http://h:3009');
  assert.throws(() => testConfig({ WEBHOOK_OUT_URL: 'http://h' }), ConfigError);
});
