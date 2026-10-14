import { ConfigError, EnvReader, parseApiKeys, parseAudit } from '@atc-web/atc-service-core/config';
import { EventPublisher } from './events/event-publisher.js';

/** @typedef {import('./types.js').ApiKey} ApiKey */

export { ConfigError };

/** Validated service configuration. Build with {@link Config.fromEnv}. */
export class Config {
  static MIN_SECRET_LENGTH = 32;

  /** @param {import('./types.js').ConfigValues} v */
  constructor(v) {
    this.port = v.port;
    this.host = v.host;
    this.logLevel = v.logLevel;
    this.trustProxy = v.trustProxy;
    this.tls = v.tls;
    this.audit = v.audit;
    this.webhookOut = v.webhookOut;
    this.bodyLimit = v.bodyLimit;
    this.dbPath = v.dbPath;
    this.dbBackupDir = v.dbBackupDir;
    this.apiKeys = v.apiKeys;
    this.rateLimitMax = v.rateLimitMax;
    this.jwtPrivateKeyPath = v.jwtPrivateKeyPath;
    this.jwtPreviousPublicKeyPath = v.jwtPreviousPublicKeyPath;
    this.jwtIssuer = v.jwtIssuer;
    this.jwtAudience = v.jwtAudience;
    this.accessTokenTtlSec = v.accessTokenTtlSec;
    this.refreshTokenTtlDays = v.refreshTokenTtlDays;
    this.verifyTokenTtlMin = v.verifyTokenTtlMin;
    this.resetTokenTtlMin = v.resetTokenTtlMin;
    this.passwordMinLength = v.passwordMinLength;
    this.scryptLogN = v.scryptLogN;
    this.loginMaxFailures = v.loginMaxFailures;
    this.loginMaxFailuresTotal = v.loginMaxFailuresTotal;
    this.maxSessions = v.maxSessions;
    this.newDeviceEmail = v.newDeviceEmail;
    this.loginLockoutMin = v.loginLockoutMin;
    this.loginRequiresVerifiedEmail = v.loginRequiresVerifiedEmail;
    this.resendCooldownSec = v.resendCooldownSec;
    this.notifyUrl = v.notifyUrl;
    this.notifyApiKey = v.notifyApiKey;
    this.notifyTimeoutMs = v.notifyTimeoutMs;
    this.appName = v.appName;
    this.emailLocale = v.emailLocale;
    this.verifyUrlTemplate = v.verifyUrlTemplate;
    this.resetUrlTemplate = v.resetUrlTemplate;
    this.changeEmailUrlTemplate = v.changeEmailUrlTemplate;
    this.eventRetentionDays = v.eventRetentionDays;
    this.auditOutboxRetentionDays = v.auditOutboxRetentionDays;
    Object.freeze(this);
  }

  /**
   * @param {NodeJS.ProcessEnv} [env]
   * @returns {Config}
   */
  static fromEnv(env = process.env) {
    const r = new EnvReader(env);

    const certPath = r.optional('TLS_CERT_PATH');
    const keyPath = r.optional('TLS_KEY_PATH');
    if (Boolean(certPath) !== Boolean(keyPath)) throw new ConfigError('TLS_CERT_PATH and TLS_KEY_PATH must be set together');

    const jwtIssuer = r.required('JWT_ISSUER');
    if (!/^https?:\/\/[^\s]+$/.test(jwtIssuer)) throw new ConfigError('JWT_ISSUER must be an absolute http(s) URL');

    const notifyUrl = r.required('NOTIFY_URL').replace(/\/+$/, '');
    if (!/^https?:\/\/[^\s]+$/.test(notifyUrl)) throw new ConfigError('NOTIFY_URL must be an absolute http(s) URL');
    const notifyApiKey = r.required('NOTIFY_API_KEY');
    if (notifyApiKey.length < Config.MIN_SECRET_LENGTH) throw new ConfigError(`NOTIFY_API_KEY must be at least ${Config.MIN_SECRET_LENGTH} characters`);

    const emailLocale = r.optional('EMAIL_LOCALE') || 'tr';
    if (emailLocale !== 'tr' && emailLocale !== 'en') throw new ConfigError('EMAIL_LOCALE must be tr or en');

    return new Config({
      port: r.integer('PORT', 3002, { min: 1, max: 65535 }),
      host: r.optional('HOST') || '0.0.0.0',
      logLevel: r.optional('LOG_LEVEL') || 'info',
      trustProxy: r.boolean('TRUST_PROXY', false),
      tls: certPath ? { certPath, keyPath } : null,
      audit: parseAudit(r),
      webhookOut: EventPublisher.parseEnv(r, ConfigError),
      bodyLimit: r.integer('BODY_LIMIT', 16_384, { min: 1_024 }),
      dbPath: r.optional('DB_PATH') || './data/auth.db',
      dbBackupDir: r.optional('DB_BACKUP_DIR') || undefined,
      apiKeys: Config.#parseApiKeys(r.required('AUTH_API_KEYS')),
      rateLimitMax: r.integer('RATE_LIMIT_MAX', 600, { min: 1 }),
      jwtPrivateKeyPath: r.required('JWT_PRIVATE_KEY_PATH'),
      jwtPreviousPublicKeyPath: r.optional('JWT_PREVIOUS_PUBLIC_KEY_PATH') || null,
      jwtIssuer,
      jwtAudience: r.required('JWT_AUDIENCE'),
      accessTokenTtlSec: r.integer('ACCESS_TOKEN_TTL_SEC', 900, { min: 60, max: 86_400 }),
      refreshTokenTtlDays: r.integer('REFRESH_TOKEN_TTL_DAYS', 30, { min: 1, max: 365 }),
      verifyTokenTtlMin: r.integer('VERIFY_TOKEN_TTL_MIN', 1_440, { min: 5 }),
      resetTokenTtlMin: r.integer('RESET_TOKEN_TTL_MIN', 60, { min: 5, max: 1_440 }),
      passwordMinLength: r.integer('PASSWORD_MIN_LENGTH', 10, { min: 8, max: 128 }),
      scryptLogN: r.integer('SCRYPT_LOG_N', 15, { min: 14, max: 20 }),
      loginMaxFailures: r.integer('LOGIN_MAX_FAILURES', 10, { min: 3, max: 100 }),
      loginMaxFailuresTotal: r.integer('LOGIN_MAX_FAILURES_TOTAL', 50, { min: 3, max: 10_000 }),
      maxSessions: r.integer('MAX_SESSIONS', 10, { min: 0, max: 1_000 }),
      newDeviceEmail: r.boolean('NEW_DEVICE_EMAIL', true),
      loginLockoutMin: r.integer('LOGIN_LOCKOUT_MIN', 15, { min: 1 }),
      loginRequiresVerifiedEmail: r.boolean('LOGIN_REQUIRES_VERIFIED_EMAIL', false),
      resendCooldownSec: r.integer('RESEND_COOLDOWN_SEC', 60, { min: 0, max: 3_600 }),
      notifyUrl,
      notifyApiKey,
      notifyTimeoutMs: r.integer('NOTIFY_TIMEOUT_MS', 5_000, { min: 500, max: 60_000 }),
      appName: r.required('APP_NAME'),
      emailLocale,
      verifyUrlTemplate: Config.#urlTemplate(r.required('VERIFY_URL_TEMPLATE'), 'VERIFY_URL_TEMPLATE'),
      changeEmailUrlTemplate: Config.#urlTemplate(r.optional('CHANGE_EMAIL_URL_TEMPLATE') || r.required('VERIFY_URL_TEMPLATE'), 'CHANGE_EMAIL_URL_TEMPLATE'),
      resetUrlTemplate: Config.#urlTemplate(r.required('RESET_URL_TEMPLATE'), 'RESET_URL_TEMPLATE'),
      eventRetentionDays: r.integer('EVENT_RETENTION_DAYS', 90, { min: 1 }),
      auditOutboxRetentionDays: r.integer('AUDIT_OUTBOX_RETENTION_DAYS', 7, { min: 1 }),
    });
  }

  /**
   * @param {string} value
   * @param {string} name
   */
  static #urlTemplate(value, name) {
    if (!/^https:\/\/[^\s]+$/.test(value)) throw new ConfigError(`${name} must be an absolute https URL`);
    if (!value.includes('{token}')) throw new ConfigError(`${name} must contain {token}`);
    return value;
  }

  /** Roles a key may hold. Missing role defaults to `readwrite` — every key issued before Stage 4
   * (plain `id:secret`) keeps working exactly as before. */
  static ROLES = ['read', 'write', 'readwrite'];

  /**
   * Parse `id:secret[:role[:proxy]]`. `proxy` is the only valid flag today (a 4th field is a
   * `+`-joined list for consistency with every other service, but this service has exactly one
   * flag) — a key without it is not trusted to set `X-Client-IP`, see `ApiKeyAuth.isProxyTrusted`.
   * @param {string} raw
   * @returns {ApiKey[]}
   */
  static #parseApiKeys(raw) {
    return parseApiKeys(raw, 'AUTH_API_KEYS', {
      roles: Config.ROLES, minSecretLength: Config.MIN_SECRET_LENGTH,
      scopeValidate: (s) => s === 'proxy', scopeNoun: 'flag',
    });
  }
}
