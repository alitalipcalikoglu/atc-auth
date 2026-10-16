import { createHash, randomBytes } from 'node:crypto';
import { PasswordHasher } from '../crypto/password.js';
import { Totp } from '../crypto/totp.js';
import { MfaStore } from '../store/mfa-store.js';
import { UserStore } from '../store/user-store.js';
import { AuthError } from './errors.js';

/** @typedef {import('../types.js').UserRow} UserRow */
/** @typedef {import('../types.js').SessionRow} SessionRow */
/** @typedef {import('../types.js').Logger} Logger */
/** @typedef {import('../crypto/jwt.js').JwtSigner} JwtSigner */
/** @typedef {import('../store/session-store.js').SessionStore} SessionStore */
/** @typedef {import('../store/action-token-store.js').ActionTokenStore} ActionTokenStore */
/** @typedef {import('../store/event-store.js').EventStore} EventStore */
/** @typedef {import('../store/guard-store.js').GuardStore} GuardStore */
/** @typedef {import('./mailer.js').Mailer} Mailer */
/** @typedef {import('./password-policy.js').PasswordPolicy} PasswordPolicy */

/**
 * Request context recorded in the audit log and on sessions.
 * @typedef {object} Ctx
 * @property {string|null} ip
 * @property {string|null} userAgent
 */

/**
 * @typedef {object} TokenPair
 * @property {string} accessToken
 * @property {number} accessTokenExpiresAt   Epoch ms.
 * @property {string} refreshToken
 * @property {number} refreshTokenExpiresAt  Epoch ms.
 * @property {string} sessionId
 */

/**
 * @typedef {object} AuthServiceOptions
 * @property {number} refreshTtlMs
 * @property {number} verifyTtlMs
 * @property {number} resetTtlMs
 * @property {number} loginMaxFailures        Per account and client address.
 * @property {number} loginMaxFailuresTotal   Per account over every address.
 * @property {number} maxSessions             0 = unlimited.
 * @property {boolean} newDeviceEmail
 * @property {string} changeEmailUrlTemplate
 * @property {number} lockoutMs
 * @property {boolean} loginRequiresVerifiedEmail
 * @property {number} resendCooldownMs
 * @property {string} verifyUrlTemplate
 * @property {string} resetUrlTemplate
 * @property {number} [passwordHistory]    Earlier passwords a new one may not repeat (0 = off).
 * @property {number} [mfaChallengeTtlMs]  Time between the password step and the code at sign-in.
 * @property {string} [mfaIssuer]          Shown in authenticator apps.
 */

/**
 * All authentication use-cases. Stores are synchronous SQLite wrappers; hashing, signing
 * and mail are async. Every state change is written to the audit log.
 */
export class AuthService {
  /**
   * @param {object} deps
   * @param {import('../db.js').Database} deps.db
   * @param {UserStore} deps.users
   * @param {SessionStore} deps.sessions
   * @param {ActionTokenStore} deps.tokens
   * @param {EventStore} deps.events
   * @param {GuardStore} deps.guard
   * @param {PasswordHasher} deps.hasher
   * @param {PasswordPolicy} deps.policy
   * @param {JwtSigner} deps.jwt
   * @param {Mailer} deps.mailer
   * @param {Logger} deps.log
   * @param {AuthServiceOptions} deps.options
   * @param {{ publish: (type: string, data?: unknown) => boolean }} [deps.publisher]  Domain events for webhook-out; ids only, no personal data.
   * @param {MfaStore} [deps.mfa]
   * @param {{ seal: (text: string) => string, open: (sealed: string) => string }|null} [deps.mfaBox]  Seals TOTP secrets; null = MFA unavailable.
   * @param {{ count: (password: string) => Promise<number|null> }|null} [deps.breach]  Optional breached-password check.
   * @param {() => number} [deps.now]
   */
  constructor({ db, users, sessions, tokens, events, guard, hasher, policy, jwt, mailer, log, options, publisher, mfa, mfaBox = null, breach = null, now = Date.now }) {
    this.mfa = mfa ?? new MfaStore(db);
    this.mfaBox = mfaBox;
    this.breach = breach;
    this.db = db;
    this.users = users;
    this.sessions = sessions;
    this.tokens = tokens;
    this.events = events;
    this.guard = guard;
    this.publisher = publisher ?? { publish: () => false };
    this.hasher = hasher;
    this.policy = policy;
    this.jwt = jwt;
    this.mailer = mailer;
    this.log = log;
    this.options = options;
    this.now = now;
    // Same cost as a real verification (logN/r/p from the configured hasher), so a login attempt
    // against an unknown e-mail takes the same time as one against a real, wrong password.
    this.#dummyHash = PasswordHasher.dummyHash(hasher.logN);
  }

  // ---------------------------------------------------------------- registration & verification

  /**
   * Create a user and send the verification email. Registration succeeds even if the mail
   * cannot be sent; `verificationEmailSent` tells the caller to offer a resend.
   * @param {{ email: string, password: string, name?: string|null }} input
   * @param {Ctx} ctx
   * @returns {Promise<{ user: UserRow, verificationEmailSent: boolean }>}
   */
  async register(input, ctx) {
    const email = UserStore.normalizeEmail(input.email);
    await this.#assertNewPassword(input.password, { email });
    if (this.users.byEmail(email)) throw new AuthError('EMAIL_TAKEN', 'an account with this email already exists');
    const passwordHash = await this.hasher.hash(input.password);
    if (this.users.byEmail(email)) throw new AuthError('EMAIL_TAKEN', 'an account with this email already exists'); // raced during hashing
    const now = this.now();
    const user = this.db.transaction(() => {
      const u = this.users.create({ email, name: input.name ?? null, passwordHash }, now);
      this.events.record({ userId: u.id, type: 'user.registered', ip: ctx.ip }, now);
      return u;
    });
    this.publisher.publish('auth.user.created', { id: user.id });
    const verificationEmailSent = await this.#sendVerification(user);
    return { user, verificationEmailSent };
  }

  /**
   * @param {string} token
   * @param {Ctx} ctx
   * @returns {UserRow}
   */
  verifyEmail(token, ctx) {
    const now = this.now();
    const userId = this.db.transaction(() => {
      const row = this.tokens.consume(token, 'verify_email', now);
      if (!row) throw new AuthError('INVALID_TOKEN', 'verification link is invalid or expired');
      this.users.markVerified(row.user_id, now);
      this.events.record({ userId: row.user_id, type: 'email.verified', ip: ctx.ip }, now);
      return row.user_id;
    });
    return this.#requireUser(userId);
  }

  /**
   * Re-send the verification mail. Silent when the email is unknown, already verified, or inside
   * the per-user cooldown, so the response never reveals whether an account exists.
   * @param {string} email
   * @param {Ctx} ctx
   * @returns {Promise<void>}
   */
  async resendVerification(email, ctx) {
    const user = this.users.byEmail(email);
    if (!user) return;
    if (user.email_verified_at || this.#resendThrottled(user.id, 'verify_email')) return;
    this.events.record({ userId: user.id, type: 'email.verification_resent', ip: ctx.ip }, this.now());
    await this.#sendVerification(user);
  }

  // ---------------------------------------------------------------- login & sessions

  /**
   * Password step. Without MFA the session starts here. With MFA it throws `MFA_REQUIRED` carrying a
   * short-lived `mfaToken` in its details, and {@link loginMfa} finishes the sign-in with a code.
   * @param {{ email: string, password: string }} input
   * @param {Ctx} ctx
   * @returns {Promise<{ user: UserRow, tokens: TokenPair }>}
   */
  async login(input, ctx) {
    const now = this.now();
    const found = this.users.byEmail(input.email);
    // Hash even when the user is missing so response time does not reveal existence.
    const user = await this.#verifyCredentials(found, input.password, ctx);
    const addr = ctx.ip ?? 'unknown';
    if (user.status === 'disabled') {
      this.events.record({ userId: user.id, type: 'login.failed', ip: ctx.ip, meta: { reason: 'disabled' } }, now);
      throw new AuthError('ACCOUNT_DISABLED', 'account is disabled');
    }
    if (this.options.loginRequiresVerifiedEmail && !user.email_verified_at) {
      this.events.record({ userId: user.id, type: 'login.failed', ip: ctx.ip, meta: { reason: 'unverified' } }, now);
      throw new AuthError('EMAIL_NOT_VERIFIED', 'verify your email before signing in');
    }
    // The rehash (needs the async hasher) happens before the transaction; everything else that
    // must commit together as one unit — success accounting, the new session, its audit event — is
    // synchronous and goes inside it.
    const rehash = this.hasher.needsRehash(user.password_hash) ? await this.hasher.hash(input.password) : null;
    if (user.mfa_enabled_at !== null) {
      const ttl = this.options.mfaChallengeTtlMs ?? 300_000;
      const mfaToken = this.db.transaction(() => {
        if (rehash) this.users.setPassword(user.id, rehash, now);
        this.events.record({ userId: user.id, type: 'login.mfa_required', ip: ctx.ip }, now);
        return this.mfa.createChallenge(user.id, ttl, now);
      });
      throw new AuthError('MFA_REQUIRED', 'enter the code from your authenticator app or a recovery code', { mfaToken, mfaTokenExpiresAt: new Date(now + ttl).toISOString() });
    }
    return this.#startSession(user, ctx, rehash);
  }

  /**
   * Second step of a sign-in with MFA: the challenge from {@link login} and a TOTP or recovery code.
   * Wrong codes count toward the same lockout as wrong passwords; a challenge allows five tries.
   * @param {{ mfaToken: string, code: string }} input
   * @param {Ctx} ctx
   * @returns {Promise<{ user: UserRow, tokens: TokenPair }>}
   */
  async loginMfa(input, ctx) {
    const now = this.now();
    const challenge = this.mfa.challenge(input.mfaToken, now);
    if (!challenge) throw new AuthError('INVALID_TOKEN', 'sign-in step expired; start again with the password');
    const user = this.#requireUser(challenge.user_id);
    const addr = ctx.ip ?? 'unknown';
    const lockedUntil = Math.max(user.locked_until ?? 0, this.guard.lockedUntil(user.id, addr, now) ?? 0);
    if (lockedUntil > now) {
      this.events.record({ userId: user.id, type: 'login.mfa_failed', ip: ctx.ip, meta: { reason: 'locked' } }, now);
      throw new AuthError('ACCOUNT_LOCKED', 'too many failed attempts, try again later', { retryAfterSec: Math.ceil((lockedUntil - now) / 1000) });
    }
    if (user.status === 'disabled') throw new AuthError('ACCOUNT_DISABLED', 'account is disabled');
    const method = this.#checkSecondFactor(user.id, input.code, now);
    if (!method) {
      this.db.transaction(() => {
        this.mfa.failChallenge(challenge.token_hash);
        const pair = this.guard.fail(user.id, addr, { maxFailures: this.options.loginMaxFailures, lockoutMs: this.options.lockoutMs }, now);
        this.events.record({ userId: user.id, type: 'login.mfa_failed', ip: ctx.ip, meta: { reason: 'bad_code', failures: pair.failures } }, now);
        if (pair.lockedUntil) this.events.record({ userId: user.id, type: 'account.locked', ip: ctx.ip, meta: { scope: 'address' } }, now);
      });
      throw new AuthError('INVALID_MFA_CODE', 'the code is not valid');
    }
    this.db.transaction(() => {
      this.mfa.deleteChallenge(challenge.token_hash);
      this.guard.clear(user.id, addr);
      if (method === 'recovery') this.events.record({ userId: user.id, type: 'mfa.recovery_code_used', ip: ctx.ip, meta: { left: this.mfa.recoveryCodesLeft(user.id) } }, now);
    });
    return this.#startSession(user, ctx, null);
  }

  /**
   * The session part of a sign-in (shared by the password-only and the MFA path).
   * @param {UserRow} user @param {Ctx} ctx @param {string|null} rehash
   * @returns {Promise<{ user: UserRow, tokens: TokenPair }>}
   */
  async #startSession(user, ctx, rehash) {
    const now = this.now();
    const device = createHash('sha256').update(ctx.userAgent ?? '').digest('hex').slice(0, 24);
    const { session, refreshToken, newDevice } = this.db.transaction(() => {
      if (rehash) this.users.setPassword(user.id, rehash, now);
      const created = this.sessions.create({ userId: user.id, ttlMs: this.options.refreshTtlMs, ip: ctx.ip, userAgent: ctx.userAgent }, now);
      this.events.record({ userId: user.id, type: 'login.succeeded', ip: ctx.ip, meta: { sessionId: created.session.id } }, now);
      // Session cap: the least recently used sessions beyond MAX_SESSIONS are signed out.
      if (this.options.maxSessions > 0) {
        for (const old of this.sessions.activeForUser(user.id, now).slice(this.options.maxSessions)) {
          if (this.sessions.revoke(old.id, now)) this.events.record({ userId: user.id, type: 'session.revoked', ip: ctx.ip, meta: { sessionId: old.id, reason: 'session_limit' } }, now);
        }
      }
      const isNew = this.guard.seenDevice(user.id, device, now);
      if (isNew) this.events.record({ userId: user.id, type: 'login.new_device', ip: ctx.ip, meta: { sessionId: created.session.id } }, now);
      return { ...created, newDevice: isNew };
    });
    if (newDevice && this.options.newDeviceEmail) {
      try { await this.mailer.sendNotice({ to: user.email, name: user.name, kind: 'new_device', details: { ip: ctx.ip ?? '', userAgent: (ctx.userAgent ?? '').slice(0, 120) } }); } catch (err) { this.log.error({ err, userId: user.id }, 'new device notice failed'); }
    }
    const fresh = this.#requireUser(user.id);
    return { user: fresh, tokens: await this.#tokenPair(fresh, session, refreshToken) };
  }

  /**
   * Rotate a refresh token. A replayed (already rotated) token revokes the whole session.
   * @param {string} refreshToken
   * @param {Ctx} ctx
   * @returns {Promise<{ user: UserRow, tokens: TokenPair }>}
   */
  async refresh(refreshToken, ctx) {
    const now = this.now();
    const found = this.sessions.findByToken(refreshToken);
    if (!found) throw new AuthError('INVALID_TOKEN', 'refresh token is invalid');
    const { session, current } = found;
    if (session.revoked_at !== null) throw new AuthError('INVALID_TOKEN', 'session has been revoked');
    if (!current) {
      this.db.transaction(() => {
        this.sessions.revoke(session.id, now);
        this.events.record({ userId: session.user_id, type: 'session.reuse_detected', ip: ctx.ip, meta: { sessionId: session.id } }, now);
      });
      this.log.warn({ userId: session.user_id, sessionId: session.id, ip: ctx.ip }, 'refresh token reuse detected, session revoked');
      throw new AuthError('TOKEN_REUSED', 'refresh token was already used; session revoked');
    }
    if (session.expires_at <= now) {
      this.sessions.revoke(session.id, now);
      throw new AuthError('INVALID_TOKEN', 'session expired');
    }
    const user = this.users.byId(session.user_id);
    if (!user || user.status === 'disabled') {
      this.sessions.revoke(session.id, now);
      throw new AuthError('ACCOUNT_DISABLED', 'account is disabled');
    }
    const { nextRefresh, updated } = this.db.transaction(() => {
      const refreshed = this.sessions.rotate(session.id, { ip: ctx.ip, userAgent: ctx.userAgent, now });
      const row = /** @type {SessionRow} */ (this.sessions.byId(session.id));
      this.events.record({ userId: user.id, type: 'session.refreshed', ip: ctx.ip, meta: { sessionId: session.id } }, now);
      return { nextRefresh: refreshed, updated: row };
    });
    return { user, tokens: await this.#tokenPair(user, updated, nextRefresh) };
  }

  /**
   * Revoke the session that owns this refresh token. Idempotent.
   * @param {string} refreshToken
   * @param {Ctx} ctx
   */
  logout(refreshToken, ctx) {
    const found = this.sessions.findByToken(refreshToken);
    if (!found) return;
    const now = this.now();
    this.db.transaction(() => {
      if (this.sessions.revoke(found.session.id, now)) {
        this.events.record({ userId: found.session.user_id, type: 'logout', ip: ctx.ip, meta: { sessionId: found.session.id } }, now);
      }
    });
  }

  /**
   * Validate an access token and confirm its session and user are still live.
   * @param {string} accessToken
   * @returns {Promise<{ active: boolean, claims?: Awaited<ReturnType<JwtSigner['verify']>>, reason?: string }>}
   */
  async introspect(accessToken) {
    let claims;
    try {
      claims = await this.jwt.verify(accessToken);
    } catch (err) {
      return { active: false, reason: /** @type {{ code?: string }} */ (err).code ?? 'INVALID' };
    }
    const session = this.sessions.byId(claims.sid);
    if (!session || session.revoked_at !== null) return { active: false, claims, reason: 'SESSION_REVOKED' };
    const user = this.users.byId(claims.sub);
    if (!user || user.status !== 'active') return { active: false, claims, reason: 'ACCOUNT_DISABLED' };
    return { active: true, claims };
  }

  /**
   * @param {string} userId
   * @returns {SessionRow[]}
   */
  listSessions(userId) {
    this.#requireUser(userId);
    return this.sessions.activeForUser(userId, this.now());
  }

  /**
   * @param {string} userId
   * @param {string} sessionId
   * @param {Ctx} ctx
   */
  revokeSession(userId, sessionId, ctx) {
    const s = this.sessions.byId(sessionId);
    if (!s || s.user_id !== userId) throw new AuthError('SESSION_NOT_FOUND', 'session not found');
    const now = this.now();
    this.db.transaction(() => {
      if (this.sessions.revoke(sessionId, now)) {
        this.events.record({ userId, type: 'session.revoked', ip: ctx.ip, meta: { sessionId } }, now);
      }
    });
  }

  /**
   * @param {string} userId
   * @param {Ctx} ctx
   * @returns {number} sessions revoked
   */
  revokeAllSessions(userId, ctx) {
    this.#requireUser(userId);
    const now = this.now();
    return this.db.transaction(() => {
      const n = this.sessions.revokeAllForUser(userId, now);
      this.events.record({ userId, type: 'sessions.revoked_all', ip: ctx.ip, meta: { count: n } }, now);
      return n;
    });
  }

  // ---------------------------------------------------------------- passwords

  /**
   * Always resolves, whether or not the email exists.
   * @param {string} email
   * @param {Ctx} ctx
   */
  async forgotPassword(email, ctx) {
    const user = this.users.byEmail(email);
    if (!user || user.status === 'disabled' || this.#resendThrottled(user.id, 'reset_password')) return;
    const now = this.now();
    const token = this.db.transaction(() => {
      const t = this.tokens.issue({ userId: user.id, purpose: 'reset_password', ttlMs: this.options.resetTtlMs }, now);
      this.events.record({ userId: user.id, type: 'password.reset_requested', ip: ctx.ip }, now);
      return t;
    });
    try {
      await this.mailer.sendPasswordReset({
        to: user.email, name: user.name, url: this.options.resetUrlTemplate.replace('{token}', encodeURIComponent(token)),
        expiresInMinutes: Math.round(this.options.resetTtlMs / 60_000), requestIp: ctx.ip,
      });
    } catch (err) {
      this.log.error({ err, userId: user.id }, 'password reset email failed');
    }
  }

  /**
   * @param {{ token: string, password: string }} input
   * @param {Ctx} ctx
   * @returns {Promise<UserRow>}
   */
  async resetPassword(input, ctx) {
    // Validate the new password before the token is spent, so a typo does not burn the link.
    const peek = this.tokens.peek(input.token, 'reset_password', this.now());
    if (!peek) throw new AuthError('INVALID_TOKEN', 'reset link is invalid or expired');
    const user = this.#requireUser(peek.user_id);
    await this.#assertNewPassword(input.password, { email: user.email, user });
    const hash = await this.hasher.hash(input.password);
    const now = this.now();
    this.db.transaction(() => {
      if (!this.tokens.consume(input.token, 'reset_password', now)) throw new AuthError('INVALID_TOKEN', 'reset link is invalid or expired');
      this.mfa.rememberPassword(user.id, user.password_hash, this.options.passwordHistory ?? 0, now);
      this.users.setPassword(user.id, hash, now);
      this.users.markVerified(user.id, now); // proved control of the mailbox
      this.sessions.revokeAllForUser(user.id, now);
      this.events.record({ userId: user.id, type: 'password.reset', ip: ctx.ip }, now);
    });
    return this.#requireUser(user.id);
  }

  /**
   * Change password with the current one; revokes every other session.
   * @param {{ userId: string, sessionId: string, currentPassword: string, newPassword: string }} input
   * @param {Ctx} ctx
   */
  async changePassword(input, ctx) {
    const user = this.#requireUser(input.userId);
    await this.#verifyCredentials(user, input.currentPassword, ctx, { failedEvent: 'password.change_failed' });
    await this.#assertNewPassword(input.newPassword, { email: user.email, user });
    const hash = await this.hasher.hash(input.newPassword);
    const now = this.now();
    this.db.transaction(() => {
      this.mfa.rememberPassword(user.id, user.password_hash, this.options.passwordHistory ?? 0, now);
      this.users.setPassword(user.id, hash, now);
      for (const s of this.sessions.activeForUser(user.id, now)) {
        if (s.id !== input.sessionId) this.sessions.revoke(s.id, now);
      }
      this.events.record({ userId: user.id, type: 'password.changed', ip: ctx.ip }, now);
    });
  }

  // ---------------------------------------------------------------- email address

  /**
   * The signed-out flow: the user proves the password and gets a link at the NEW address. Always
   * resolves quietly (an address already in use gets no mail and no hint).
   * @param {{ email: string, password: string, newEmail: string }} input
   * @param {Ctx} ctx
   */
  async requestEmailChange(input, ctx) {
    const found = this.users.byEmail(input.email);
    const user = await this.#verifyCredentials(found, input.password, ctx, { failedEvent: 'email.change_failed' });
    if (user.status === 'disabled') throw new AuthError('INVALID_CREDENTIALS', 'email or password is incorrect');
    const next = UserStore.normalizeEmail(input.newEmail);
    if (next === user.email) throw new AuthError('INVALID_ARGUMENT', 'that is already the email address of this account');
    if (this.users.byEmail(next) || this.#resendThrottled(user.id, 'change_email')) return;
    const now = this.now();
    const token = this.db.transaction(() => {
      const t = this.tokens.issue({ userId: user.id, purpose: 'change_email', ttlMs: this.options.verifyTtlMs, payload: next }, now);
      this.events.record({ userId: user.id, type: 'email.change_requested', ip: ctx.ip }, now);
      return t;
    });
    try {
      await this.mailer.sendEmailChange({ to: next, name: user.name, url: this.options.changeEmailUrlTemplate.replace('{token}', encodeURIComponent(token)), expiresInMinutes: Math.round(this.options.verifyTtlMs / 60_000) });
    } catch (err) {
      this.log.error({ err, userId: user.id }, 'email change mail failed');
    }
  }

  /**
   * The link in that mail: the address changes and counts as verified (the mailbox was proven). The old address is told.
   * @param {string} token
   * @param {Ctx} ctx
   * @returns {Promise<UserRow>}
   */
  async confirmEmailChange(token, ctx) {
    const now = this.now();
    const peek = this.tokens.peek(token, 'change_email', now);
    if (!peek?.payload) throw new AuthError('INVALID_TOKEN', 'confirmation link is invalid or expired');
    const user = this.#requireUser(peek.user_id);
    const next = peek.payload;
    if (this.users.byEmail(next)) throw new AuthError('EMAIL_TAKEN', 'an account with this email already exists');
    const previous = user.email;
    this.db.transaction(() => {
      if (!this.tokens.consume(token, 'change_email', now)) throw new AuthError('INVALID_TOKEN', 'confirmation link is invalid or expired');
      this.users.setEmail(user.id, next, now, now);
      this.tokens.invalidate(user.id, 'verify_email', now); // a pending verification of the old address no longer applies
      this.events.record({ userId: user.id, type: 'email.changed', ip: ctx.ip }, now);
    });
    try { await this.mailer.sendNotice({ to: previous, name: user.name, kind: 'email_changed', details: { ip: ctx.ip ?? '' } }); } catch (err) { this.log.error({ err, userId: user.id }, 'email change notice failed'); }
    return this.#requireUser(user.id);
  }

  /**
   * Administration: set another address directly. It starts unverified and a verification mail goes to it.
   * @param {string} userId @param {string} email @param {Ctx} ctx @returns {Promise<UserRow>}
   */
  async adminSetEmail(userId, email, ctx) {
    const user = this.#requireUser(userId);
    const next = UserStore.normalizeEmail(email);
    if (next === user.email) return user;
    if (this.users.byEmail(next)) throw new AuthError('EMAIL_TAKEN', 'an account with this email already exists');
    const now = this.now();
    this.db.transaction(() => {
      this.users.setEmail(userId, next, null, now);
      this.events.record({ userId, type: 'email.changed', ip: ctx.ip, meta: { by: 'admin' } }, now);
    });
    await this.#sendVerification(this.#requireUser(userId));
    return this.#requireUser(userId);
  }

  // ---------------------------------------------------------------- personal data

  /**
   * Everything stored about one person, for a data-subject request: profile, sessions, security events.
   * @param {string} userId
   */
  exportUser(userId) {
    const user = this.#requireUser(userId);
    const iso = (/** @type {number|null} */ ms) => (ms === null ? null : new Date(ms).toISOString());
    return {
      exportedAt: new Date(this.now()).toISOString(),
      user: { id: user.id, email: user.email, name: user.name, status: user.status, emailVerifiedAt: iso(user.email_verified_at), passwordChangedAt: iso(user.password_changed_at), createdAt: iso(user.created_at), updatedAt: iso(user.updated_at), mfaEnabled: user.mfa_enabled_at !== null, mfaEnabledAt: iso(user.mfa_enabled_at) },
      sessions: this.sessions.activeForUser(userId, this.now()).map((x) => ({ id: x.id, ip: x.ip, userAgent: x.user_agent, createdAt: iso(x.created_at), lastUsedAt: iso(x.last_used_at), expiresAt: iso(x.expires_at) })),
      events: this.events.forUser(userId, { limit: 1_000 }).map((e) => ({ type: e.type, ip: e.ip, meta: e.meta ? JSON.parse(e.meta) : null, at: iso(e.at) })),
    };
  }

  /**
   * Erase the person but keep the account row: the address becomes an unusable placeholder, the name,
   * password, sessions, tokens and recorded addresses go. The id stays so events and other services'
   * references still resolve. Irreversible.
   * @param {string} userId @param {Ctx} ctx
   */
  async anonymize(userId, ctx) {
    this.#requireUser(userId);
    const unusable = await this.hasher.hash(randomBytes(32).toString('hex'));
    const now = this.now();
    this.db.transaction(() => {
      this.users.anonymize(userId, `anonymized-${userId.slice(0, 8)}@anonymized.invalid`, unusable, now);
      this.sessions.revokeAllForUser(userId, now);
      this.events.scrub(userId);
      this.guard.purgeUser(userId);
      this.mfa.purgeUser(userId);
      this.events.record({ userId, type: 'account.anonymized', ip: ctx.ip }, now);
    });
    this.publisher.publish('auth.user.anonymized', { id: userId });
  }

  // ---------------------------------------------------------------- MFA

  /**
   * Start (or restart) enrolment: a new secret, stored sealed and not yet active. The password is
   * checked first (through the sign-in lockout): a stolen access token alone must not be able to
   * bind the account to an attacker's authenticator.
   * @param {string} userId @param {string} password @param {Ctx} ctx
   * @returns {Promise<{ secret: string, otpauthUrl: string }>}
   */
  async mfaSetup(userId, password, ctx) {
    const box = this.#requireMfaBox();
    const user = this.#requireUser(userId);
    await this.#verifyCredentials(user, password, ctx, { failedEvent: 'mfa.setup_failed' });
    if (user.mfa_enabled_at !== null) throw new AuthError('MFA_ALREADY_ENABLED', 'MFA is already on; turn it off first to enrol a new device');
    const secret = Totp.generateSecret();
    const now = this.now();
    this.db.transaction(() => {
      this.mfa.setPending(userId, box.seal(secret), now);
      this.events.record({ userId, type: 'mfa.setup_started', ip: ctx.ip }, now);
    });
    return { secret, otpauthUrl: Totp.uri({ secret, account: user.email, issuer: this.options.mfaIssuer ?? 'atc-auth' }) };
  }

  /**
   * Finish enrolment with the password and a code from the app; answers the recovery codes (shown once).
   * @param {string} userId @param {{ password: string, code: string }} input @param {Ctx} ctx
   * @returns {Promise<string[]>}
   */
  async mfaEnable(userId, input, ctx) {
    const box = this.#requireMfaBox();
    const user = this.#requireUser(userId);
    await this.#verifyCredentials(user, input.password, ctx, { failedEvent: 'mfa.enable_failed' });
    const row = this.mfa.get(userId);
    if (user.mfa_enabled_at !== null) throw new AuthError('MFA_ALREADY_ENABLED', 'MFA is already on');
    if (!row) throw new AuthError('MFA_SETUP_REQUIRED', 'start the setup first');
    const now = this.now();
    const step = Totp.verify(box.open(row.secret), input.code, now);
    if (step === null) {
      this.#failSecondFactor(user, ctx, 'mfa.enable_failed', now);
      throw new AuthError('INVALID_MFA_CODE', 'the code is not valid');
    }
    const codes = this.db.transaction(() => {
      this.mfa.enable(userId, step, now);
      this.events.record({ userId, type: 'mfa.enabled', ip: ctx.ip }, now);
      return this.mfa.replaceRecoveryCodes(userId);
    });
    await this.#notice(user, 'mfa_enabled', ctx);
    return codes;
  }

  /**
   * Turn MFA off: the password (through the shared lockout) and a current code or a recovery code.
   * @param {string} userId @param {{ password: string, code: string }} input @param {Ctx} ctx
   */
  async mfaDisable(userId, input, ctx) {
    const user = this.#requireUser(userId);
    await this.#verifyCredentials(user, input.password, ctx, { failedEvent: 'mfa.disable_failed' });
    if (user.mfa_enabled_at === null) throw new AuthError('MFA_NOT_ENABLED', 'MFA is not on');
    const now = this.now();
    if (!this.#checkSecondFactor(userId, input.code, now)) {
      this.events.record({ userId, type: 'mfa.disable_failed', ip: ctx.ip, meta: { reason: 'bad_code' } }, now);
      throw new AuthError('INVALID_MFA_CODE', 'the code is not valid');
    }
    this.db.transaction(() => {
      this.mfa.remove(userId);
      this.events.record({ userId, type: 'mfa.disabled', ip: ctx.ip }, now);
    });
    await this.#notice(user, 'mfa_disabled', ctx);
  }

  /**
   * New recovery codes (the old ones stop working), confirmed with the password and a current TOTP code.
   * @param {string} userId @param {{ password: string, code: string }} input @param {Ctx} ctx
   * @returns {Promise<string[]>}
   */
  async mfaRecoveryCodes(userId, input, ctx) {
    const box = this.#requireMfaBox();
    const user = this.#requireUser(userId);
    await this.#verifyCredentials(user, input.password, ctx, { failedEvent: 'mfa.recovery_codes_failed' });
    const row = this.mfa.get(userId);
    if (user.mfa_enabled_at === null || !row) throw new AuthError('MFA_NOT_ENABLED', 'MFA is not on');
    const now = this.now();
    const step = Totp.verify(box.open(row.secret), input.code, now);
    if (step === null || !this.mfa.useStep(userId, step)) {
      this.#failSecondFactor(user, ctx, 'mfa.recovery_codes_failed', now);
      throw new AuthError('INVALID_MFA_CODE', 'the code is not valid');
    }
    return this.db.transaction(() => {
      this.events.record({ userId, type: 'mfa.recovery_codes_replaced', ip: ctx.ip }, now);
      return this.mfa.replaceRecoveryCodes(userId);
    });
  }

  /**
   * Administration: remove a user's MFA (lost device, no recovery codes left). The user is told by mail.
   * @param {string} userId @param {Ctx} ctx
   */
  async adminResetMfa(userId, ctx) {
    const user = this.#requireUser(userId);
    if (user.mfa_enabled_at === null && !this.mfa.get(userId)) throw new AuthError('MFA_NOT_ENABLED', 'MFA is not on');
    const now = this.now();
    this.db.transaction(() => {
      this.mfa.remove(userId);
      this.events.record({ userId, type: 'mfa.reset', ip: ctx.ip, meta: { by: 'admin' } }, now);
    });
    await this.#notice(user, 'mfa_reset', ctx);
  }

  // ---------------------------------------------------------------- administration

  /**
   * @param {string} userId
   * @param {{ name?: string|null, status?: 'active'|'disabled' }} patch
   * @param {Ctx} ctx
   * @returns {UserRow}
   */
  updateUser(userId, patch, ctx) {
    const user = this.#requireUser(userId);
    const now = this.now();
    const statusChanged = patch.status !== undefined && patch.status !== user.status;
    this.db.transaction(() => {
      if (patch.name !== undefined) this.users.setName(userId, patch.name, now);
      if (patch.status !== undefined && patch.status !== user.status) {
        this.users.setStatus(userId, patch.status, now);
        if (patch.status === 'disabled') this.sessions.revokeAllForUser(userId, now);
        this.events.record({ userId, type: patch.status === 'disabled' ? 'account.disabled' : 'account.enabled', ip: ctx.ip }, now);
      }
    });
    if (statusChanged) this.publisher.publish(patch.status === 'disabled' ? 'auth.user.disabled' : 'auth.user.enabled', { id: userId });
    return this.#requireUser(userId);
  }

  /**
   * @param {string} userId
   * @param {Ctx} ctx
   */
  deleteUser(userId, ctx) {
    this.#requireUser(userId);
    this.db.transaction(() => {
      this.users.remove(userId);
      this.events.record({ userId, type: 'account.deleted', ip: ctx.ip }, this.now());
    });
    this.publisher.publish('auth.user.deleted', { id: userId });
  }

  // ---------------------------------------------------------------- internals

  /**
   * @param {UserRow} user
   * @param {SessionRow} session
   * @param {string} refreshToken
   * @returns {Promise<TokenPair>}
   */
  async #tokenPair(user, session, refreshToken) {
    const access = await this.jwt.sign({ sub: user.id, sid: session.id, email: user.email, email_verified: user.email_verified_at !== null }, this.now());
    return { accessToken: access.token, accessTokenExpiresAt: access.expiresAt, refreshToken, refreshTokenExpiresAt: session.expires_at, sessionId: session.id };
  }

  /**
   * @param {UserRow} user
   * @returns {Promise<boolean>} whether the mail was accepted by notify
   */
  async #sendVerification(user) {
    const token = this.tokens.issue({ userId: user.id, purpose: 'verify_email', ttlMs: this.options.verifyTtlMs }, this.now());
    try {
      await this.mailer.sendEmailVerification({
        to: user.email, name: user.name, url: this.options.verifyUrlTemplate.replace('{token}', encodeURIComponent(token)),
        expiresInMinutes: Math.round(this.options.verifyTtlMs / 60_000),
      });
      return true;
    } catch (err) {
      this.log.error({ err, userId: user.id }, 'verification email failed');
      return false;
    }
  }

  /**
   * @param {string} userId
   * @param {import('../types.js').TokenPurpose} purpose
   */
  #resendThrottled(userId, purpose) {
    if (this.options.resendCooldownMs <= 0) return false;
    return this.tokens.issuedSince(userId, purpose, this.now() - this.options.resendCooldownMs) > 0;
  }

  /**
   * Every rule a new password must pass: the policy, not one of the account's recent passwords
   * (current included), and, when the check is on, not in a known breach.
   * @param {string} password
   * @param {{ email: string, user?: UserRow }} o
   */
  async #assertNewPassword(password, { email, user }) {
    const problems = this.policy.problems(password, { email });
    if (!problems.length && user) {
      const keep = this.options.passwordHistory ?? 0;
      const previous = keep > 0 ? [user.password_hash, ...this.mfa.recentPasswords(user.id, keep - 1)] : [];
      for (const h of previous) {
        if (await this.hasher.verify(password, h)) { problems.push(`must not be one of your last ${keep} passwords`); break; }
      }
    }
    if (!problems.length && this.breach) {
      const n = await this.breach.count(password);
      if (n) problems.push('appears in known data breaches; choose another');
    }
    if (problems.length) throw new AuthError('WEAK_PASSWORD', `password ${problems.join('; ')}`, { problems });
  }

  /**
   * A TOTP code (each time step once) or an unused recovery code. Returns which one matched.
   * @param {string} userId @param {string} code @param {number} now
   * @returns {'totp'|'recovery'|null}
   */
  #checkSecondFactor(userId, code, now) {
    const row = this.mfa.get(userId);
    if (!row || row.enabled_at === null || !this.mfaBox) return null;
    const typed = code.trim();
    if (/^\d{6}$/.test(typed)) {
      const step = Totp.verify(this.mfaBox.open(row.secret), typed, now);
      return step !== null && this.mfa.useStep(userId, step) ? 'totp' : null;
    }
    return this.mfa.useRecoveryCode(userId, typed, now) ? 'recovery' : null;
  }

  #requireMfaBox() {
    if (!this.mfaBox) throw new AuthError('MFA_UNAVAILABLE', 'MFA is not configured on this server (MFA_SECRETS_KEY)');
    return this.mfaBox;
  }

  /** @param {UserRow} user @param {'mfa_enabled'|'mfa_disabled'|'mfa_reset'} kind @param {Ctx} ctx */
  async #notice(user, kind, ctx) {
    try { await this.mailer.sendNotice({ to: user.email, name: user.name, kind, details: { ip: ctx.ip ?? '' } }); } catch (err) { this.log.error({ err, userId: user.id }, `${kind} notice failed`); }
  }

  /** A wrong second factor outside sign-in counts toward the same per-user/address lockout as a wrong password. @param {UserRow} user @param {Ctx} ctx @param {string} type @param {number} now */
  #failSecondFactor(user, ctx, type, now) {
    const pair = this.guard.fail(user.id, ctx.ip ?? 'unknown', { maxFailures: this.options.loginMaxFailures, lockoutMs: this.options.lockoutMs }, now);
    this.events.record({ userId: user.id, type, ip: ctx.ip, meta: { reason: 'bad_code', failures: pair.failures } }, now);
    if (pair.lockedUntil) this.events.record({ userId: user.id, type: 'account.locked', ip: ctx.ip, meta: { scope: 'address' } }, now);
  }

  /**
   * The one place a password is checked (sign-in, email change, password change): constant work for
   * unknown accounts, lockout per account and client address (with the account-wide backstop), every
   * failure counted and recorded, a success clears the counters. Throws `ACCOUNT_LOCKED` while locked,
   * `INVALID_CREDENTIALS` otherwise; never reveals which part was wrong.
   * @param {UserRow|undefined} user
   * @param {string} password
   * @param {Ctx} ctx
   * @param {{ failedEvent?: string }} [o]
   * @returns {Promise<UserRow>}
   */
  async #verifyCredentials(user, password, ctx, { failedEvent = 'login.failed' } = {}) {
    const now = this.now();
    const addr = ctx.ip ?? 'unknown';
    const ok = user ? await this.hasher.verify(password, user.password_hash) : await this.#burnHash(password);
    if (!user) {
      this.events.record({ type: failedEvent, ip: ctx.ip, meta: { reason: 'unknown_email' } }, now);
      throw new AuthError('INVALID_CREDENTIALS', 'email or password is incorrect');
    }
    const addressLock = this.guard.lockedUntil(user.id, addr, now);
    const lockedUntil = Math.max(user.locked_until !== null && user.locked_until > now ? user.locked_until : 0, addressLock ?? 0);
    if (lockedUntil > now) {
      this.events.record({ userId: user.id, type: failedEvent, ip: ctx.ip, meta: { reason: 'locked' } }, now);
      throw new AuthError('ACCOUNT_LOCKED', 'too many failed attempts, try again later', { retryAfterSec: Math.ceil((lockedUntil - now) / 1000) });
    }
    if (!ok) {
      this.db.transaction(() => {
        const pair = this.guard.fail(user.id, addr, { maxFailures: this.options.loginMaxFailures, lockoutMs: this.options.lockoutMs }, now);
        const total = this.users.recordLoginFailure(user.id, { maxFailures: this.options.loginMaxFailuresTotal, lockoutMs: this.options.lockoutMs, now });
        this.events.record({ userId: user.id, type: failedEvent, ip: ctx.ip, meta: { reason: 'bad_password', failures: pair.failures } }, now);
        if (pair.lockedUntil) this.events.record({ userId: user.id, type: 'account.locked', ip: ctx.ip, meta: { scope: 'address' } }, now);
        else if (total.locked_until) this.events.record({ userId: user.id, type: 'account.locked', ip: ctx.ip, meta: { scope: 'account' } }, now);
      });
      throw new AuthError('INVALID_CREDENTIALS', 'email or password is incorrect');
    }
    this.users.recordLoginSuccess(user.id, now);
    this.guard.clear(user.id, addr);
    return user;
  }

  /** @param {string} id */
  #requireUser(id) {
    const user = this.users.byId(id);
    if (!user) throw new AuthError('USER_NOT_FOUND', 'user not found');
    return user;
  }

  /**
   * Spend the same CPU as a real verification so a missing account is not detectable by timing.
   * @param {string} password
   */
  async #burnHash(password) {
    await this.hasher.verify(password, this.#dummyHash);
    return false;
  }

  /** @type {string} */
  #dummyHash;
}
