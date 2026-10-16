import { Ids } from '@atc-web/atc-service-core/ids';
import { OpaqueToken } from '../crypto/opaque-token.js';

/** @typedef {import('../db.js').Database} Database */
/** @typedef {import('../types.js').SessionRow} SessionRow */

/**
 * Refresh-token families. Each row holds the hash of the one currently valid refresh token;
 * rotation moves it to `previous_token_hash` so a replay of the old token is detectable.
 */
export class SessionStore {
  static COLUMNS = 'id, user_id, token_hash, previous_token_hash, created_at, last_used_at, expires_at, revoked_at, ip, user_agent';

  /** @param {Database} db */
  constructor(db) {
    const C = SessionStore.COLUMNS;
    this.stmt = {
      insert: db.prepare(`INSERT INTO sessions (id, user_id, token_hash, created_at, last_used_at, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
      byId: db.prepare(`SELECT ${C} FROM sessions WHERE id = ?`),
      byTokenHash: db.prepare(`SELECT ${C} FROM sessions WHERE token_hash = ? OR previous_token_hash = ?`),
      rotate: db.prepare(`UPDATE sessions SET previous_token_hash = token_hash, token_hash = ?, last_used_at = ?, ip = COALESCE(?, ip), user_agent = COALESCE(?, user_agent) WHERE id = ? AND revoked_at IS NULL`),
      revoke: db.prepare(`UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`),
      revokeAllForUser: db.prepare(`UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`),
      activeForUser: db.prepare(`SELECT ${C} FROM sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ? ORDER BY last_used_at DESC`),
      countActive: db.prepare(`SELECT COUNT(*) AS n FROM sessions WHERE revoked_at IS NULL AND expires_at > ?`),
      purge: db.prepare(`DELETE FROM sessions WHERE expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?)`),
    };
  }

  /**
   * Start a new family. Returns the plaintext refresh token exactly once.
   * @param {{ userId: string, ttlMs: number, ip?: string|null, userAgent?: string|null }} input
   * @param {number} [now]
   * @returns {{ session: SessionRow, refreshToken: string }}
   */
  create({ userId, ttlMs, ip = null, userAgent = null }, now = Date.now()) {
    const id = Ids.create('ses');
    const { token, hash } = OpaqueToken.generate();
    this.stmt.insert.run(id, userId, hash, now, now, now + ttlMs, ip, userAgent);
    return { session: /** @type {SessionRow} */ (this.stmt.byId.get(id)), refreshToken: token };
  }

  /** @param {string} id */
  byId(id) {
    return /** @type {SessionRow|undefined} */ (this.stmt.byId.get(id));
  }

  /**
   * Look up by a presented refresh token (current or previous).
   * @param {string} token
   * @returns {{ session: SessionRow, current: boolean }|undefined}
   */
  findByToken(token) {
    const hash = OpaqueToken.hash(token);
    const session = /** @type {SessionRow|undefined} */ (this.stmt.byTokenHash.get(hash, hash));
    return session ? { session, current: session.token_hash === hash } : undefined;
  }

  /**
   * Replace the current refresh token. Returns the new plaintext token.
   * @param {string} id
   * @param {{ ip?: string|null, userAgent?: string|null, now?: number }} [o]
   * @returns {string}
   */
  rotate(id, { ip = null, userAgent = null, now = Date.now() } = {}) {
    const { token, hash } = OpaqueToken.generate();
    const res = this.stmt.rotate.run(hash, now, ip, userAgent, id);
    if (res.changes !== 1) throw new Error('rotate: session missing or revoked');
    return token;
  }

  /**
   * @param {string} id
   * @param {number} [now]
   * @returns {boolean}
   */
  revoke(id, now = Date.now()) {
    return this.stmt.revoke.run(now, id).changes === 1;
  }

  /**
   * @param {string} userId
   * @param {number} [now]
   * @returns {number}
   */
  revokeAllForUser(userId, now = Date.now()) {
    return Number(this.stmt.revokeAllForUser.run(now, userId).changes);
  }

  /**
   * @param {string} userId
   * @param {number} [now]
   * @returns {SessionRow[]}
   */
  activeForUser(userId, now = Date.now()) {
    return /** @type {SessionRow[]} */ (this.stmt.activeForUser.all(userId, now));
  }

  /** @param {number} [now] */
  countActive(now = Date.now()) {
    return /** @type {{ n: number }} */ (this.stmt.countActive.get(now)).n;
  }

  /**
   * Delete expired sessions and sessions revoked before `revokedBefore`.
   * @param {number} now
   * @param {number} revokedBefore
   */
  purge(now, revokedBefore) {
    return Number(this.stmt.purge.run(now, revokedBefore).changes);
  }
}
