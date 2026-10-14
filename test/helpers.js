import { generateKeyPairSync } from 'node:crypto';
import { Config } from '../src/config.js';
import { JwtSigner } from '../src/crypto/jwt.js';
import { Database } from '../src/db.js';
import { AuditEvents } from '../src/domain/audit-events.js';

export const API_KEY = 'k'.repeat(40);
export const OTHER_KEY = 'o'.repeat(40);
export const READ_KEY = 'r'.repeat(40);

/** Fresh ES256 key pair as PEM strings. */
export function testKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    privatePem: /** @type {string} */ (privateKey.export({ type: 'pkcs8', format: 'pem' })),
    publicPem: /** @type {string} */ (publicKey.export({ type: 'spki', format: 'pem' })),
  };
}

/** Full valid environment; tests override single values. */
export function fullEnv() {
  return {
    // "test" is readwrite + proxy-trusted (most tests forward X-Client-IP through it); "other" is
    // plain (no role, no proxy) so it doubles as the "cannot spoof IP" negative-test key; "reader"
    // is read-only, for the "cannot register" negative test.
    AUTH_API_KEYS: `test:${API_KEY}:readwrite:proxy,other:${OTHER_KEY},reader:${READ_KEY}:read`,
    JWT_PRIVATE_KEY_PATH: '/keys/jwt-private.pem',
    JWT_ISSUER: 'https://auth.test.local',
    JWT_AUDIENCE: 'test-app',
    NOTIFY_URL: 'http://127.0.0.1:1/',
    NOTIFY_API_KEY: 'n'.repeat(40),
    APP_NAME: 'Shop',
    VERIFY_URL_TEMPLATE: 'https://shop.test.local/verify?token={token}',
    RESET_URL_TEMPLATE: 'https://shop.test.local/reset?token={token}',
    DB_PATH: ':memory:',
    SCRYPT_LOG_N: '14',
    LOG_LEVEL: 'silent',
  };
}

/** @param {Record<string, string>} [overrides] */
export function testConfig(overrides = {}) {
  return Config.fromEnv({ ...fullEnv(), ...overrides });
}

/**
 * Initialised signer with an in-memory key pair.
 * @param {{ previousPublicPem?: string|null, ttlSec?: number }} [opts]
 */
export async function testSigner({ previousPublicPem = null, ttlSec = 900 } = {}) {
  const pair = testKeyPair();
  const signer = new JwtSigner({ privateKeyPem: pair.privatePem, previousPublicKeyPem: previousPublicPem, issuer: 'https://auth.test.local', audience: 'test-app', ttlSec });
  await signer.init();
  return { signer, pair };
}

export function testDb() {
  return new Database(':memory:');
}

/** Silent pino-compatible logger. */
export const silentLog = /** @type {any} */ (new Proxy({}, {
  get: (_t, prop) => (prop === 'child' ? () => silentLog : () => {}),
}));

/** Recording {@link Mailer}; set `fail` to make sends throw. */
export class FakeMailer {
  constructor() {
    /** @type {{ kind: 'verify'|'reset'|'change', to: string, url: string, token: string, name: string|null }[]} */
    this.sent = [];
    /** @type {Error|null} */
    this.fail = null;
    /** @type {{ to: string, kind: string, details: Record<string, string> }[]} */
    this.notices = [];
  }

  /** @param {{ to: string, name: string|null, url: string }} m */
  async sendEmailVerification(m) {
    this.#push('verify', m);
  }

  /** @param {{ to: string, name: string|null, url: string }} m */
  async sendPasswordReset(m) {
    this.#push('reset', m);
  }

  /** @param {{ to: string, name: string|null, url: string }} m */
  async sendEmailChange(m) {
    this.#push('change', m);
  }

  /** @param {{ to: string, name: string|null, kind: string, details: Record<string, string> }} m */
  async sendNotice(m) {
    this.notices.push(m);
  }

  async verify() {}

  /**
   * @param {'verify'|'reset'|'change'} kind
   * @param {{ to: string, name: string|null, url: string }} m
   */
  #push(kind, m) {
    if (this.fail) throw this.fail;
    const token = decodeURIComponent(new URL(m.url).searchParams.get('token') ?? '');
    this.sent.push({ kind, to: m.to, url: m.url, token, name: m.name });
  }

  /** Last token of a kind, for tests that follow the emailed link. */
  lastToken(/** @type {'verify'|'reset'|'change'} */ kind) {
    return this.sent.filter((s) => s.kind === kind).at(-1)?.token ?? '';
  }
}

/**
 * Fully wired AuthService on an in-memory database with a fake mailer and controllable clock.
 * @param {Record<string, string>} [envOverrides]
 * @param {any} [publisher]
 */
export async function testAuthService(envOverrides = {}, publisher = undefined) {
  const { AuthService } = await import('../src/domain/auth-service.js');
  const { PasswordPolicy } = await import('../src/domain/password-policy.js');
  const { PasswordHasher } = await import('../src/crypto/password.js');
  const { UserStore } = await import('../src/store/user-store.js');
  const { SessionStore } = await import('../src/store/session-store.js');
  const { ActionTokenStore } = await import('../src/store/action-token-store.js');
  const { EventStore } = await import('../src/store/event-store.js');
  const { GuardStore } = await import('../src/store/guard-store.js');
  const config = testConfig(envOverrides);
  const db = testDb();
  const { signer } = await testSigner({ ttlSec: config.accessTokenTtlSec });
  const mailer = new FakeMailer();
  const clock = { now: Date.now() };
  const users = new UserStore(db);
  const sessions = new SessionStore(db);
  const tokens = new ActionTokenStore(db);
  const events = new EventStore(db, AuditEvents.fromSecurityEvent);
  const guard = new GuardStore(db);
  const service = new AuthService({
    db, users, sessions, tokens, events, guard, publisher,
    hasher: new PasswordHasher({ logN: config.scryptLogN }),
    policy: new PasswordPolicy({ minLength: config.passwordMinLength }),
    jwt: signer, mailer, log: silentLog,
    options: {
      refreshTtlMs: config.refreshTokenTtlDays * 86_400_000,
      verifyTtlMs: config.verifyTokenTtlMin * 60_000,
      resetTtlMs: config.resetTokenTtlMin * 60_000,
      loginMaxFailures: config.loginMaxFailures,
      loginMaxFailuresTotal: config.loginMaxFailuresTotal,
      maxSessions: config.maxSessions,
      newDeviceEmail: config.newDeviceEmail,
      changeEmailUrlTemplate: config.changeEmailUrlTemplate,
      lockoutMs: config.loginLockoutMin * 60_000,
      loginRequiresVerifiedEmail: config.loginRequiresVerifiedEmail,
      resendCooldownMs: config.resendCooldownSec * 1000,
      verifyUrlTemplate: config.verifyUrlTemplate,
      resetUrlTemplate: config.resetUrlTemplate,
    },
    now: () => clock.now,
  });
  return { service, config, db, signer, mailer, clock, users, sessions, tokens, events, guard };
}

export const ctx = { ip: '203.0.113.9', userAgent: 'test-agent' };
export const GOOD_PASSWORD = 'correct horse battery staple';
