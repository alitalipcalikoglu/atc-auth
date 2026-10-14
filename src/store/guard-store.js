/** @typedef {import('../db.js').Database} Database */

/**
 * Per-address sign-in failure counters and known sign-in devices. Lockouts are per (account, client
 * address) so one attacker cannot lock a victim out from everywhere; every repeat lockout of the same
 * pair doubles its length (up to a day). The account-wide counter on `users` is the backstop against
 * a distributed attack.
 */
export class GuardStore {
  static MAX_LOCK_MS = 86_400_000;

  /** @param {Database} db */
  constructor(db) {
    this.stmt = {
      get: db.prepare('SELECT failures, lockouts, locked_until FROM login_failures WHERE user_id = ? AND ip = ?'),
      upsert: db.prepare(`INSERT INTO login_failures (user_id, ip, failures, lockouts, locked_until, last_at) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT (user_id, ip) DO UPDATE SET failures = excluded.failures, lockouts = excluded.lockouts, locked_until = excluded.locked_until, last_at = excluded.last_at`),
      clear: db.prepare('DELETE FROM login_failures WHERE user_id = ? AND ip = ?'),
      purge: db.prepare('DELETE FROM login_failures WHERE last_at < ? AND (locked_until IS NULL OR locked_until < ?)'),
      purgeUser: db.prepare('DELETE FROM login_failures WHERE user_id = ?'),
      purgeDevices: db.prepare('DELETE FROM known_devices WHERE user_id = ?'),
      device: db.prepare('SELECT 1 AS known FROM known_devices WHERE user_id = ? AND device = ?'),
      deviceAny: db.prepare('SELECT COUNT(*) AS n FROM known_devices WHERE user_id = ?'),
      deviceUpsert: db.prepare(`INSERT INTO known_devices (user_id, device, first_at, last_at) VALUES (?, ?, ?, ?)
        ON CONFLICT (user_id, device) DO UPDATE SET last_at = excluded.last_at`),
      devicePurge: db.prepare('DELETE FROM known_devices WHERE last_at < ?'),
    };
  }

  /** Seconds-resolution lock check. @param {string} userId @param {string} ip @param {number} now @returns {number|null} locked until (ms) or null */
  lockedUntil(userId, ip, now) {
    const r = /** @type {{ locked_until: number|null }|undefined} */ (this.stmt.get.get(userId, ip));
    return r?.locked_until && r.locked_until > now ? r.locked_until : null;
  }

  /**
   * Count a failure for this address; at `maxFailures` the address is locked for `lockoutMs` doubled per earlier lockout.
   * @param {string} userId @param {string} ip @param {{ maxFailures: number, lockoutMs: number }} o @param {number} now
   * @returns {{ failures: number, lockedUntil: number|null }}
   */
  fail(userId, ip, { maxFailures, lockoutMs }, now) {
    const r = /** @type {{ failures: number, lockouts: number, locked_until: number|null }|undefined} */ (this.stmt.get.get(userId, ip));
    const failures = (r?.failures ?? 0) + 1;
    if (failures < maxFailures) {
      this.stmt.upsert.run(userId, ip, failures, r?.lockouts ?? 0, r?.locked_until ?? null, now);
      return { failures, lockedUntil: null };
    }
    const lockouts = (r?.lockouts ?? 0) + 1;
    const until = now + Math.min(GuardStore.MAX_LOCK_MS, lockoutMs * 2 ** (lockouts - 1));
    this.stmt.upsert.run(userId, ip, 0, lockouts, until, now);
    return { failures, lockedUntil: until };
  }

  /** @param {string} userId @param {string} ip */
  clear(userId, ip) { this.stmt.clear.run(userId, ip); }

  /** Forget a user's counters and devices. @param {string} userId */
  purgeUser(userId) { this.stmt.purgeUser.run(userId); this.stmt.purgeDevices.run(userId); }

  /** Rows idle for a day and not locked. @param {number} now */
  purge(now) { return Number(this.stmt.purge.run(now - GuardStore.MAX_LOCK_MS, now).changes) + Number(this.stmt.devicePurge.run(now - 180 * 86_400_000).changes); }

  /**
   * Record a sign-in device; says whether it is new (the user's very first device is not announced).
   * @param {string} userId @param {string} device @param {number} now @returns {boolean} true when a notice is due
   */
  seenDevice(userId, device, now) {
    const first = Number(/** @type {{ n: number }} */ (this.stmt.deviceAny.get(userId)).n) === 0;
    const known = this.stmt.device.get(userId, device) !== undefined;
    this.stmt.deviceUpsert.run(userId, device, now, now);
    return !first && !known;
  }
}
