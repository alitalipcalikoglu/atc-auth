import { OpaqueToken } from '../crypto/opaque-token.js';

/** @typedef {import('../db.js').Database} Database */
/** @typedef {import('../types.js').ActionTokenRow} ActionTokenRow */
/** @typedef {import('../types.js').TokenPurpose} TokenPurpose */

/** Single-use, expiring tokens for email verification and password reset. */
export class ActionTokenStore {
  static COLUMNS = 'token_hash, user_id, purpose, payload, expires_at, used_at, created_at';

  /** @param {Database} db */
  constructor(db) {
    const C = ActionTokenStore.COLUMNS;
    this.stmt = {
      insert: db.prepare(`INSERT INTO action_tokens (token_hash, user_id, purpose, payload, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)`),
      byHash: db.prepare(`SELECT ${C} FROM action_tokens WHERE token_hash = ? AND purpose = ?`),
      live: db.prepare(`SELECT ${C} FROM action_tokens WHERE token_hash = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?`),
      consume: db.prepare(`UPDATE action_tokens SET used_at = ? WHERE token_hash = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?`),
      invalidate: db.prepare(`UPDATE action_tokens SET used_at = ? WHERE user_id = ? AND purpose = ? AND used_at IS NULL`),
      recentCount: db.prepare(`SELECT COUNT(*) AS n FROM action_tokens WHERE user_id = ? AND purpose = ? AND created_at > ?`),
      purge: db.prepare(`DELETE FROM action_tokens WHERE expires_at < ? OR used_at < ?`),
    };
  }

  /**
   * Issue a token, invalidating any earlier unused token of the same purpose for the user.
   * @param {{ userId: string, purpose: TokenPurpose, ttlMs: number, payload?: string|null }} input
   * @param {number} [now]
   * @returns {string} plaintext token
   */
  issue({ userId, purpose, ttlMs, payload = null }, now = Date.now()) {
    this.stmt.invalidate.run(now, userId, purpose);
    const { token, hash } = OpaqueToken.generate();
    this.stmt.insert.run(hash, userId, purpose, payload, now + ttlMs, now);
    return token;
  }

  /** Spend every unused token of a purpose for a user. @param {string} userId @param {TokenPurpose} purpose @param {number} [now] */
  invalidate(userId, purpose, now = Date.now()) {
    this.stmt.invalidate.run(now, userId, purpose);
  }

  /**
   * Read a token without consuming it. Returns the row only if it is valid, unused and unexpired.
   * @param {string} token
   * @param {TokenPurpose} purpose
   * @param {number} [now]
   * @returns {ActionTokenRow|undefined}
   */
  peek(token, purpose, now = Date.now()) {
    if (!OpaqueToken.looksValid(token)) return undefined;
    return /** @type {ActionTokenRow|undefined} */ (this.stmt.live.get(OpaqueToken.hash(token), purpose, now));
  }

  /**
   * Atomically mark a token used. Returns the row only if it was valid, unused and unexpired.
   * @param {string} token
   * @param {TokenPurpose} purpose
   * @param {number} [now]
   * @returns {ActionTokenRow|undefined}
   */
  consume(token, purpose, now = Date.now()) {
    if (!OpaqueToken.looksValid(token)) return undefined;
    const hash = OpaqueToken.hash(token);
    if (this.stmt.consume.run(now, hash, purpose, now).changes !== 1) return undefined;
    return /** @type {ActionTokenRow} */ (this.stmt.byHash.get(hash, purpose));
  }

  /**
   * Tokens issued for a user/purpose since `since`; used to throttle resend requests.
   * @param {string} userId
   * @param {TokenPurpose} purpose
   * @param {number} since
   */
  issuedSince(userId, purpose, since) {
    return /** @type {{ n: number }} */ (this.stmt.recentCount.get(userId, purpose, since)).n;
  }

  /**
   * @param {number} now
   * @param {number} usedBefore
   */
  purge(now, usedBefore) {
    return Number(this.stmt.purge.run(now, usedBefore).changes);
  }
}
