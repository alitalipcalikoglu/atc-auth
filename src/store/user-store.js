import { randomUUID } from 'node:crypto';

/** @typedef {import('../db.js').Database} Database */
/** @typedef {import('../types.js').UserRow} UserRow */

/** Persistence for the `users` table. Emails are stored lower-cased and trimmed. */
export class UserStore {
  static COLUMNS = 'id, email, name, password_hash, status, email_verified_at, failed_logins, locked_until, password_changed_at, created_at, updated_at';

  /** @param {Database} db */
  constructor(db) {
    const C = UserStore.COLUMNS;
    this.stmt = {
      insert: db.prepare(`INSERT INTO users (id, email, name, password_hash, password_changed_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`),
      byId: db.prepare(`SELECT ${C} FROM users WHERE id = ?`),
      byEmail: db.prepare(`SELECT ${C} FROM users WHERE email = ?`),
      list: db.prepare(`SELECT ${C} FROM users WHERE (created_at < ? OR (created_at = ? AND id < ?)) ORDER BY created_at DESC, id DESC LIMIT ?`),
      count: db.prepare(`SELECT COUNT(*) AS n FROM users`),
      countByStatus: db.prepare(`SELECT status, COUNT(*) AS n FROM users GROUP BY status`),
      setPassword: db.prepare(`UPDATE users SET password_hash = ?, password_changed_at = ?, failed_logins = 0, locked_until = NULL, updated_at = ? WHERE id = ?`),
      setVerified: db.prepare(`UPDATE users SET email_verified_at = COALESCE(email_verified_at, ?), updated_at = ? WHERE id = ?`),
      setStatus: db.prepare(`UPDATE users SET status = ?, updated_at = ? WHERE id = ?`),
      setEmail: db.prepare(`UPDATE users SET email = ?, email_verified_at = ?, updated_at = ? WHERE id = ?`),
      anonymize: db.prepare(`UPDATE users SET email = ?, name = NULL, password_hash = ?, status = 'disabled', email_verified_at = NULL, failed_logins = 0, locked_until = NULL, updated_at = ? WHERE id = ?`),
      setName: db.prepare(`UPDATE users SET name = ?, updated_at = ? WHERE id = ?`),
      loginFailed: db.prepare(`UPDATE users SET failed_logins = failed_logins + 1, locked_until = CASE WHEN failed_logins + 1 >= ? THEN ? ELSE locked_until END, updated_at = ? WHERE id = ? RETURNING failed_logins, locked_until`),
      loginSucceeded: db.prepare(`UPDATE users SET failed_logins = 0, locked_until = NULL, updated_at = ? WHERE id = ?`),
      remove: db.prepare(`DELETE FROM users WHERE id = ?`),
    };
  }

  /**
   * @param {string} email
   * @returns {string}
   */
  static normalizeEmail(email) {
    return email.trim().toLowerCase();
  }

  /**
   * @param {{ email: string, name?: string|null, passwordHash: string }} input
   * @param {number} [now]
   * @returns {UserRow}
   */
  create(input, now = Date.now()) {
    const id = randomUUID();
    this.stmt.insert.run(id, UserStore.normalizeEmail(input.email), input.name ?? null, input.passwordHash, now, now, now);
    return /** @type {UserRow} */ (this.stmt.byId.get(id));
  }

  /** @param {string} id */
  byId(id) {
    return /** @type {UserRow|undefined} */ (this.stmt.byId.get(id));
  }

  /** @param {string} email */
  byEmail(email) {
    return /** @type {UserRow|undefined} */ (this.stmt.byEmail.get(UserStore.normalizeEmail(email)));
  }

  /**
   * Newest first, keyset pagination.
   * @param {{ limit: number, before?: { createdAt: number, id: string } }} q
   * @returns {UserRow[]}
   */
  list({ limit, before = { createdAt: Number.MAX_SAFE_INTEGER, id: '￿' } }) {
    return /** @type {UserRow[]} */ (this.stmt.list.all(before.createdAt, before.createdAt, before.id, limit));
  }

  /** @returns {{ total: number, active: number, disabled: number }} */
  counts() {
    const out = { total: 0, active: 0, disabled: 0 };
    for (const r of /** @type {{ status: 'active'|'disabled', n: number }[]} */ (this.stmt.countByStatus.all())) {
      out[r.status] = r.n;
      out.total += r.n;
    }
    return out;
  }

  /**
   * @param {string} id
   * @param {string} passwordHash
   * @param {number} [now]
   */
  setPassword(id, passwordHash, now = Date.now()) {
    this.stmt.setPassword.run(passwordHash, now, now, id);
  }

  /**
   * @param {string} id
   * @param {number} [now]
   */
  markVerified(id, now = Date.now()) {
    this.stmt.setVerified.run(now, now, id);
  }

  /**
   * @param {string} id
   * @param {'active'|'disabled'} status
   * @param {number} [now]
   */
  setStatus(id, status, now = Date.now()) {
    this.stmt.setStatus.run(status, now, id);
  }

  /** @param {string} id @param {string} email @param {number|null} verifiedAt @param {number} [now] */
  setEmail(id, email, verifiedAt, now = Date.now()) {
    this.stmt.setEmail.run(UserStore.normalizeEmail(email), verifiedAt, now, id);
  }

  /** Strip what identifies the person; the row (and its id in events) stays. @param {string} id @param {string} email @param {string} passwordHash @param {number} [now] */
  anonymize(id, email, passwordHash, now = Date.now()) {
    this.stmt.anonymize.run(email, passwordHash, now, id);
  }

  /**
   * @param {string} id
   * @param {string|null} name
   * @param {number} [now]
   */
  setName(id, name, now = Date.now()) {
    this.stmt.setName.run(name, now, id);
  }

  /**
   * Count a failed login; locks the account when the threshold is reached.
   * @param {string} id
   * @param {{ maxFailures: number, lockoutMs: number, now?: number }} o
   * @returns {{ failed_logins: number, locked_until: number|null }}
   */
  recordLoginFailure(id, { maxFailures, lockoutMs, now = Date.now() }) {
    return /** @type {{ failed_logins: number, locked_until: number|null }[]} */ (this.stmt.loginFailed.all(maxFailures, now + lockoutMs, now, id))[0];
  }

  /**
   * @param {string} id
   * @param {number} [now]
   */
  recordLoginSuccess(id, now = Date.now()) {
    this.stmt.loginSucceeded.run(now, id);
  }

  /**
   * Hard delete; sessions and action tokens cascade.
   * @param {string} id
   * @returns {boolean}
   */
  remove(id) {
    return this.stmt.remove.run(id).changes === 1;
  }
}
