import { Config } from './config.js';
import { AuditClient } from '@atc-web/atc-service-core/audit';
import { readServiceVersion } from '@atc-web/atc-service-core/fastify';
import { Lifecycle } from '@atc-web/atc-service-core/lifecycle';
import { AuditEvents } from './domain/audit-events.js';
import { JwtSigner } from './crypto/jwt.js';
import { PasswordHasher } from './crypto/password.js';
import { Database } from './db.js';
import { AuthService } from './domain/auth-service.js';
import { BreachCheck } from './domain/breach-check.js';
import { MfaStore } from './store/mfa-store.js';
import { SecretBox } from '@atc-web/atc-service-core/secrets';
import { NotifyMailer } from './domain/mailer.js';
import { PasswordPolicy } from './domain/password-policy.js';
import { AuthApi } from './http/auth-api.js';
import { Maintenance } from './maintenance.js';
import { ActionTokenStore } from './store/action-token-store.js';
import { EventStore } from './store/event-store.js';
import { GuardStore } from './store/guard-store.js';
import { SessionStore } from './store/session-store.js';
import { UserStore } from './store/user-store.js';
import { EventPublisher } from './events/event-publisher.js';

/**
 * Composition root: wires configuration, storage, crypto, domain, HTTP and maintenance,
 * and owns the process lifecycle.
 */
export class Application {
  /** @param {Config} config */
  constructor(config) {
    this.config = config;
    this.version = readServiceVersion(import.meta.url);
    this.db = new Database(config.dbPath, { backupDir: config.dbBackupDir });
    this.users = new UserStore(this.db);
    this.sessions = new SessionStore(this.db);
    this.tokens = new ActionTokenStore(this.db);
    this.events = new EventStore(this.db, AuditEvents.fromSecurityEvent);
    this.guard = new GuardStore(this.db);
    // Outbox mode, not buffered: a security event must survive a crash between the business
    // mutation that caused it and the network call that reports it — see EventStore.record and
    // docs/READINESS.md's Persistence section for why every other service stays buffered.
    this.audit = new AuditClient({
      target: config.audit,
      outbox: {
        pending: (limit) => this.events.outboxPending(limit),
        markSent: (ids) => this.events.outboxMarkSent(ids),
        purge: () => this.events.outboxPurge(config.auditOutboxRetentionDays),
      },
    });
    this.publisher = new EventPublisher({ source: 'atc-auth', target: config.webhookOut });
    this.jwt = JwtSigner.fromFiles({
      privateKeyPath: config.jwtPrivateKeyPath,
      previousPublicKeyPath: config.jwtPreviousPublicKeyPath,
      issuer: config.jwtIssuer,
      audience: config.jwtAudience,
      ttlSec: config.accessTokenTtlSec,
    });
    this.mailer = new NotifyMailer({ baseUrl: config.notifyUrl, apiKey: config.notifyApiKey, appName: config.appName, locale: config.emailLocale, timeoutMs: config.notifyTimeoutMs });
    /** @type {import('fastify').FastifyInstance|null} */
    this.app = null;
    /** @type {Maintenance|null} */
    this.maintenance = null;
    /** @type {(reason: string) => Promise<void>} */
    this.shutdown = async () => {};
  }

  /** Build from `process.env`; exits with a readable message on bad configuration. */
  static fromEnv() {
    try {
      return new Application(Config.fromEnv());
    } catch (err) {
      if (err instanceof Error && err.name === 'ConfigError') {
        console.error(`configuration error: ${err.message}`);
        process.exit(1);
      }
      throw err;
    }
  }

  async start() {
    const { config } = this;
    await this.jwt.init();
    const mfa = new MfaStore(this.db);
    const service = new AuthService({
      db: this.db, users: this.users, sessions: this.sessions, tokens: this.tokens, events: this.events, guard: this.guard, publisher: this.publisher,
      mfa, mfaBox: config.mfaSecretsKey ? new SecretBox(config.mfaSecretsKey) : null,
      breach: config.passwordBreachCheck ? new BreachCheck({ url: config.passwordBreachUrl, timeoutMs: config.passwordBreachTimeoutMs, log: { warn: (o, m) => this.app?.log.warn(o, m) } }) : null,
      hasher: new PasswordHasher({ logN: config.scryptLogN }),
      policy: new PasswordPolicy({ minLength: config.passwordMinLength }),
      jwt: this.jwt, mailer: this.mailer, log: /** @type {any} */ (console),
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
        passwordHistory: config.passwordHistory,
        mfaChallengeTtlMs: config.mfaChallengeTtlSec * 1000,
        mfaIssuer: config.appName,
      },
    });
    const { audit, events } = this;
    const api = new AuthApi({ config, service, jwt: this.jwt, db: this.db, mailer: this.mailer, users: this.users, sessions: this.sessions, events: this.events, publisher: this.publisher, version: this.version, audit: { get enabled() { return audit.enabled; }, get stats() { return audit.stats; }, get backlog() { return events.outboxPending(1000).length; } } });
    const app = await api.build();
    this.app = app;
    service.log = app.log.child({ component: 'atc-auth' });
    this.maintenance = new Maintenance({ sessions: this.sessions, tokens: this.tokens, events: this.events, guard: this.guard, mfa, log: app.log.child({ component: 'maintenance' }), options: { eventRetentionDays: config.eventRetentionDays } });
    const { shutdown } = Lifecycle.install({
      forceExitMs: 30_000,
      log: app.log,
      steps: [
        () => this.maintenance?.stop(),
        () => this.app?.close(),
        () => this.publisher.close(),
        () => this.audit.close(),
        () => this.db.close(),
      ],
    });
    this.shutdown = shutdown;
    this.audit.logger = app.log;
    this.publisher.logger = app.log;
    this.audit.start();
    await app.listen({ port: config.port, host: config.host });
    app.log.info({ tls: config.tls !== null, kid: this.jwt.kid, issuer: config.jwtIssuer }, config.tls ? 'serving HTTPS' : 'serving plain HTTP, terminate TLS at a reverse proxy');
    this.maintenance.start();
    if (process.send) process.send('ready'); // PM2 wait_ready
  }

}
