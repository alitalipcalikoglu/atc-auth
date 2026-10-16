import { readFileSync } from 'node:fs';
import { isIP } from 'node:net';
import rateLimit from '@fastify/rate-limit';
import Fastify from 'fastify';
import { registerInfo, registerOpenApi, registerProbes, registerRequestContext, requestOptions } from '@atc-web/atc-service-core/fastify';
import { Idempotency } from '@atc-web/atc-service-core/idempotency';
import { AuthError } from '../domain/errors.js';
import { ApiKeyAuth } from './api-key-auth.js';
import { Schemas } from './schemas.js';
import { Views } from './views.js';
import { AuditMetrics } from '../audit-metrics.js';

/** @typedef {import('../config.js').Config} Config */
/** @typedef {import('../domain/auth-service.js').AuthService} AuthService */
/** @typedef {import('../domain/auth-service.js').Ctx} Ctx */
/** @typedef {import('fastify').FastifyInstance} FastifyInstance */
/** @typedef {import('fastify').FastifyRequest} FastifyRequest */
/** @typedef {import('fastify').FastifyReply} FastifyReply */

/** Opaque keyset cursor for user listing. */
class UserCursor {
  /** @param {import('../types.js').UserRow} row */
  static encode(row) {
    return Buffer.from(`${row.created_at}:${row.id}`).toString('base64url');
  }

  /** @param {string} cursor */
  static decode(cursor) {
    const m = /^(\d{1,16}):(usr_[0-9a-z]{6,12}[0-9a-f]{16})$/.exec(Buffer.from(cursor, 'base64url').toString());
    if (!m) throw Object.assign(new Error('invalid cursor'), { statusCode: 400, code: 'INVALID_CURSOR' });
    return { createdAt: Number(m[1]), id: m[2] };
  }
}

/**
 * HTTP surface. Callers are trusted application backends holding an API key; they forward the
 * end user's address and agent in `X-Client-IP` / `X-Client-User-Agent` for the audit log.
 */
export class AuthApi {
  static READY_CACHE_MS = 30_000;

  /**
   * @param {object} deps
   * @param {Config} deps.config
   * @param {AuthService} deps.service
   * @param {import('../crypto/jwt.js').JwtSigner} deps.jwt
   * @param {import('../db.js').Database} deps.db
   * @param {import('../domain/mailer.js').Mailer} deps.mailer
   * @param {import('../store/user-store.js').UserStore} deps.users
   * @param {import('../store/session-store.js').SessionStore} deps.sessions
   * @param {import('../store/event-store.js').EventStore} deps.events
   * @param {string} deps.version
   * @param {import('../events/event-publisher.js').EventPublisher} [deps.publisher]
   * @param {Parameters<typeof AuditMetrics.lines>[0]} [deps.audit] Audit forwarding state, for /metrics.
   * @param {import('../types.js').Logger} [deps.logger]
   */
  constructor({ config, service, jwt, db, mailer, users, sessions, events, publisher, version, audit, logger }) {
    this.audit = audit;
    this.publisher = publisher ?? null;
    this.config = config;
    this.service = service;
    this.jwt = jwt;
    this.db = db;
    this.mailer = mailer;
    this.users = users;
    this.sessions = sessions;
    this.events = events;
    this.version = version;
    this.logger = logger;
    this.auth = new ApiKeyAuth(config.apiKeys);
  }

  /** @returns {Promise<FastifyInstance>} */
  async build() {
    const { config } = this;
    const app = Fastify({
      ...(config.tls ? { https: { cert: readFileSync(config.tls.certPath), key: readFileSync(config.tls.keyPath), minVersion: 'TLSv1.2' } } : {}),
      ...requestOptions({ logger: this.logger, logLevel: config.logLevel, extraRedact: ['req.headers["x-access-token"]'] }),
      trustProxy: config.trustProxy,
      bodyLimit: config.bodyLimit,
      ajv: { customOptions: { removeAdditional: false, coerceTypes: false } },
    });
    registerRequestContext(app, { trustProxy: config.trustProxy });
    app.decorateRequest('apiKeyId', '');
    app.decorateRequest('apiKeyRole', undefined);
    app.decorateRequest('apiKeyScopes', null);
    app.setErrorHandler(this.#errorHandler);
    // Opt-in per route: only admin create-style routes that answer without secrets (never /v1/auth/*, MFA, tokens).
    Idempotency.register(app, { raw: this.db.raw });
    app.setNotFoundHandler((_request, reply) => {
      reply.code(404).send({ error: { code: 'NOT_FOUND', message: 'route not found' } });
    });
    app.addHook('onSend', async (_request, reply) => {
      if (!reply.hasHeader('cache-control')) reply.header('cache-control', 'no-store');
    });
    this.#registerPublic(app);
    await app.register((api) => this.#registerV1(api), { prefix: '/v1' });
    await app.register((ops) => this.#registerMetrics(ops));
    return app;
  }

  /** @type {FastifyInstance['errorHandler']} */
  #errorHandler = (rawErr, request, reply) => {
    const err = /** @type {import('fastify').FastifyError & { validation?: { instancePath: string, message?: string, params: object }[], details?: Record<string, unknown> }} */ (rawErr);
    if (err instanceof AuthError) {
      const retry = /** @type {{ retryAfterSec?: number }|undefined} */ (err.details)?.retryAfterSec;
      if (retry) reply.header('retry-after', String(retry));
      return reply.code(err.statusCode).send({ error: { code: err.code, message: err.message, ...(err.details ? { details: err.details } : {}) } });
    }
    if (err.validation) {
      return reply.code(400).send({
        error: { code: 'VALIDATION_FAILED', message: err.message, details: err.validation.map((v) => ({ path: v.instancePath, message: v.message, params: v.params })) },
      });
    }
    const status = err.statusCode && err.statusCode >= 400 && err.statusCode < 600 ? err.statusCode : 500;
    if (status >= 500) {
      request.log.error({ err }, 'unhandled error');
      return reply.code(status).send({ error: { code: 'INTERNAL_ERROR', message: 'internal error' } });
    }
    return reply.code(status).send({ error: { code: err.code ?? 'REQUEST_ERROR', message: err.message } });
  };

  /**
   * Audit context: a calling backend holding a `proxy`-flagged key may forward the end user's
   * address via `X-Client-IP`; every other key gets the socket peer address regardless of what it
   * sends in that header (Stage 4 — see `ApiKeyAuth.isProxyTrusted`).
   * @param {FastifyRequest} request
   * @returns {Ctx}
   */
  static ctx(request) {
    const forwarded = request.headers['x-client-ip'];
    const trusted = ApiKeyAuth.isProxyTrusted(request);
    const ip = trusted && typeof forwarded === 'string' && isIP(forwarded.trim()) ? forwarded.trim() : request.ip;
    const ua = request.headers['x-client-user-agent'] ?? request.headers['user-agent'];
    return { ip: ip || null, userAgent: typeof ua === 'string' ? ua.slice(0, 512) : null };
  }

  /** @param {FastifyInstance} app */
  #registerPublic(app) {
    registerProbes(app, async () => {
      this.db.ping();
      await this.mailer.verify();
    }, { cacheMs: AuthApi.READY_CACHE_MS });
    registerOpenApi(app, new URL('../../openapi.yaml', import.meta.url));
    registerInfo(app, {
      service: 'atc-auth',
      version: this.version,
      capabilities: ['jwks', 'email-verification', 'password-reset', 'refresh-tokens', 'mfa-totp', 'password-history'],
      schemaVersion: this.db.schemaVersion,
    });
    app.get('/.well-known/jwks.json', { logLevel: 'warn' }, async (_request, reply) => {
      reply.header('cache-control', 'public, max-age=300');
      return this.jwt.jwks();
    });
  }

  /** @param {FastifyInstance} api */
  async #registerV1(api) {
    api.addHook('onRequest', this.auth.hook);
    await api.register(rateLimit, {
      max: this.config.rateLimitMax,
      timeWindow: '1 minute',
      keyGenerator: (request) => request.apiKeyId,
      errorResponseBuilder: (_request, context) => Object.assign(new Error(`rate limit exceeded, retry in ${context.after}`), { statusCode: 429, code: 'RATE_LIMITED' }),
    });
    const s = this.service;
    const ctx = AuthApi.ctx;

    // ---- users (administration by the calling backend)
    api.post('/users', { config: { idempotent: true }, schema: { body: Schemas.register }, preHandler: ApiKeyAuth.require('write') }, async (request, reply) => {
      const body = /** @type {{ email: string, password: string, name?: string|null }} */ (request.body);
      const { user, verificationEmailSent } = await s.register(body, ctx(request));
      reply.header('location', `/v1/users/${user.id}`);
      return reply.code(201).send({ user: Views.user(user), verificationEmailSent });
    });

    api.get('/users', { schema: { querystring: Schemas.listUsersQuery } }, async (request) => {
      const q = /** @type {{ email?: string, limit?: string, cursor?: string }} */ (request.query);
      if (q.email) {
        const u = this.users.byEmail(q.email);
        return { items: u ? [Views.user(u)] : [], nextCursor: null };
      }
      const limit = q.limit ? Number(q.limit) : 20;
      const rows = this.users.list({ limit: limit + 1, before: q.cursor ? UserCursor.decode(q.cursor) : undefined });
      const items = rows.slice(0, limit);
      const last = items.at(-1);
      return { items: items.map(Views.user), nextCursor: rows.length > limit && last ? UserCursor.encode(last) : null };
    });

    api.get('/users/:id', { schema: { params: Schemas.idParams } }, async (request) => {
      const u = this.users.byId(/** @type {{ id: string }} */ (request.params).id);
      if (!u) throw new AuthError('USER_NOT_FOUND', 'user not found');
      return { user: Views.user(u) };
    });

    api.patch('/users/:id', { schema: { params: Schemas.idParams, body: Schemas.patchUser }, preHandler: ApiKeyAuth.require('write') }, async (request) => {
      const { id } = /** @type {{ id: string }} */ (request.params);
      const { email, ...rest } = /** @type {{ email?: string, name?: string|null, status?: 'active'|'disabled' }} */ (request.body);
      let user = Object.keys(rest).length ? s.updateUser(id, rest, ctx(request)) : this.users.byId(id);
      if (email !== undefined) user = await s.adminSetEmail(id, email, ctx(request));
      if (!user) throw new AuthError('USER_NOT_FOUND', 'user not found');
      return { user: Views.user(user) };
    });

    api.get('/users/:id/export', { schema: { params: Schemas.idParams } }, async (request) => s.exportUser(/** @type {{ id: string }} */ (request.params).id));

    api.post('/users/:id/anonymize', { config: { idempotent: true }, schema: { params: Schemas.idParams }, preHandler: ApiKeyAuth.require('write') }, async (request, reply) => {
      await s.anonymize(/** @type {{ id: string }} */ (request.params).id, ctx(request));
      return reply.code(204).send();
    });

    api.delete('/users/:id', { schema: { params: Schemas.idParams }, preHandler: ApiKeyAuth.require('write') }, async (request, reply) => {
      s.deleteUser(/** @type {{ id: string }} */ (request.params).id, ctx(request));
      return reply.code(204).send();
    });

    api.get('/users/:id/sessions', { schema: { params: Schemas.idParams } }, async (request) => ({
      items: s.listSessions(/** @type {{ id: string }} */ (request.params).id).map(Views.session),
      nextCursor: null,
    }));

    api.delete('/users/:id/sessions', { schema: { params: Schemas.idParams }, preHandler: ApiKeyAuth.require('write') }, async (request) => ({
      revoked: s.revokeAllSessions(/** @type {{ id: string }} */ (request.params).id, ctx(request)),
    }));

    api.delete('/users/:id/sessions/:sid', { schema: { params: Schemas.idSidParams }, preHandler: ApiKeyAuth.require('write') }, async (request, reply) => {
      const { id, sid } = /** @type {{ id: string, sid: string }} */ (request.params);
      s.revokeSession(id, sid, ctx(request));
      return reply.code(204).send();
    });

    api.get('/users/:id/events', { schema: { params: Schemas.idParams, querystring: Schemas.listEventsQuery } }, async (request) => {
      const { id } = /** @type {{ id: string }} */ (request.params);
      const q = /** @type {{ limit?: string, cursor?: string }} */ (request.query);
      if (!this.users.byId(id)) throw new AuthError('USER_NOT_FOUND', 'user not found');
      const limit = q.limit ? Number(q.limit) : 50;
      const rows = this.events.forUser(id, { limit: limit + 1, beforeId: q.cursor ? Number(q.cursor) : undefined });
      const items = rows.slice(0, limit);
      return { items: items.map(Views.event), nextCursor: rows.length > limit ? String(items.at(-1)?.id) : null };
    });

    // ---- authentication flows
    api.post('/auth/login', { schema: { body: Schemas.login } }, async (request) => {
      const { user, tokens } = await s.login(/** @type {any} */ (request.body), ctx(request));
      return { user: Views.user(user), tokens: Views.tokens(tokens) };
    });

    api.post('/auth/login/mfa', { schema: { body: Schemas.loginMfa } }, async (request) => {
      const { user, tokens } = await s.loginMfa(/** @type {{ mfaToken: string, code: string }} */ (request.body), ctx(request));
      return { user: Views.user(user), tokens: Views.tokens(tokens) };
    });

    api.post('/auth/refresh', { schema: { body: Schemas.refresh } }, async (request) => {
      const { user, tokens } = await s.refresh(/** @type {{ refreshToken: string }} */ (request.body).refreshToken, ctx(request));
      return { user: Views.user(user), tokens: Views.tokens(tokens) };
    });

    api.post('/auth/logout', { schema: { body: Schemas.refresh } }, async (request, reply) => {
      s.logout(/** @type {{ refreshToken: string }} */ (request.body).refreshToken, ctx(request));
      return reply.code(204).send();
    });

    api.post('/auth/introspect', { schema: { body: Schemas.introspect } }, async (request) => {
      const r = await s.introspect(/** @type {{ accessToken: string }} */ (request.body).accessToken);
      return { active: r.active, ...(r.reason ? { reason: r.reason } : {}), ...(r.claims ? { claims: r.claims } : {}) };
    });

    api.post('/auth/verify-email', { schema: { body: Schemas.token } }, async (request) => ({
      user: Views.user(s.verifyEmail(/** @type {{ token: string }} */ (request.body).token, ctx(request))),
    }));

    api.post('/auth/verify-email/resend', { schema: { body: Schemas.emailOnly } }, async (request, reply) => {
      await s.resendVerification(/** @type {{ email: string }} */ (request.body).email, ctx(request));
      return reply.code(202).send({ accepted: true });
    });

    api.post('/auth/email/change', { schema: { body: Schemas.changeEmail } }, async (request, reply) => {
      await s.requestEmailChange(/** @type {any} */ (request.body), ctx(request));
      return reply.code(202).send({ accepted: true });
    });

    api.post('/auth/email/confirm', { schema: { body: Schemas.token } }, async (request) => ({
      user: Views.user(await s.confirmEmailChange(/** @type {{ token: string }} */ (request.body).token, ctx(request))),
    }));

    api.post('/auth/password/forgot', { schema: { body: Schemas.emailOnly } }, async (request, reply) => {
      await s.forgotPassword(/** @type {{ email: string }} */ (request.body).email, ctx(request));
      return reply.code(202).send({ accepted: true });
    });

    api.post('/auth/password/reset', { schema: { body: Schemas.resetPassword } }, async (request) => ({
      user: Views.user(await s.resetPassword(/** @type {any} */ (request.body), ctx(request))),
    }));

    // The end user's access token travels in X-Access-Token; the API key stays in Authorization.
    api.post('/auth/password/change', { schema: { body: Schemas.changePassword } }, async (request, reply) => {
      const claims = await this.#endUser(request);
      const body = /** @type {{ currentPassword: string, newPassword: string }} */ (request.body);
      await s.changePassword({ userId: claims.sub, sessionId: claims.sid, ...body }, ctx(request));
      return reply.code(204).send();
    });

    // ---- the end user's own MFA (X-Access-Token)
    // Every MFA change proves the password again: an access token alone must not be enough to bind another device.
    api.post('/auth/mfa/setup', { schema: { body: Schemas.passwordOnly } }, async (request) => s.mfaSetup((await this.#endUser(request)).sub, /** @type {{ password: string }} */ (request.body).password, ctx(request)));
    api.post('/auth/mfa/enable', { schema: { body: Schemas.disableMfa } }, async (request) => ({
      recoveryCodes: await s.mfaEnable((await this.#endUser(request)).sub, /** @type {{ password: string, code: string }} */ (request.body), ctx(request)),
    }));
    api.post('/auth/mfa/disable', { schema: { body: Schemas.disableMfa } }, async (request, reply) => {
      await s.mfaDisable((await this.#endUser(request)).sub, /** @type {{ password: string, code: string }} */ (request.body), ctx(request));
      return reply.code(204).send();
    });
    api.post('/auth/mfa/recovery-codes', { schema: { body: Schemas.disableMfa } }, async (request) => ({
      recoveryCodes: await s.mfaRecoveryCodes((await this.#endUser(request)).sub, /** @type {{ password: string, code: string }} */ (request.body), ctx(request)),
    }));

    // ---- administration of a user's MFA
    api.delete('/users/:id/mfa', { schema: { params: Schemas.idParams }, preHandler: ApiKeyAuth.require('write') }, async (request, reply) => {
      await s.adminResetMfa(/** @type {{ id: string }} */ (request.params).id, ctx(request));
      return reply.code(204).send();
    });
  }

  /**
   * The signed-in end user behind `X-Access-Token` (the API key stays in Authorization).
   * @param {FastifyRequest} request
   */
  async #endUser(request) {
    const header = request.headers['x-access-token'];
    const intro = typeof header === 'string' && header ? await this.service.introspect(header) : { active: false, reason: 'MISSING' };
    if (!intro.active || !intro.claims) throw new AuthError('INVALID_TOKEN', `access token ${intro.reason === 'MISSING' ? 'missing' : 'not active'}`);
    return intro.claims;
  }

  /** @param {FastifyInstance} ops */
  #registerMetrics(ops) {
    ops.addHook('onRequest', this.auth.hook);
    ops.get('/metrics', { logLevel: 'warn' }, async (_request, reply) => {
      const u = this.users.counts();
      reply.type('text/plain; version=0.0.4; charset=utf-8');
      return [
        '# HELP auth_users Users by status.',
        '# TYPE auth_users gauge',
        `auth_users{status="active"} ${u.active}`,
        `auth_users{status="disabled"} ${u.disabled}`,
        '# HELP auth_sessions_active Sessions that are neither revoked nor expired.',
        '# TYPE auth_sessions_active gauge',
        `auth_sessions_active ${this.sessions.countActive()}`,
        ...AuditMetrics.lines(this.audit),
        ...(this.publisher?.metricLines() ?? []),
        '# HELP auth_process_uptime_seconds Process uptime.',
        '# TYPE auth_process_uptime_seconds gauge',
        `auth_process_uptime_seconds ${process.uptime().toFixed(0)}`,
        '',
      ].join('\n');
    });
  }
}
