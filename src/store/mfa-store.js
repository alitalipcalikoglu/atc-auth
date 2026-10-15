import { createHash, randomBytes } from 'node:crypto';

/** @typedef {import('../db.js').Database} Database */

/**
 * Persistence for end-user MFA: the sealed TOTP secret, hashed one-time recovery codes, sign-in
 * challenges (the step between a correct password and the code), and the password history.
 * Recovery codes and challenge tokens are random, so a plain SHA-256 is enough to store them.
 */
export class MfaStore {
  static CHALLENGE_MAX_ATTEMPTS = 5;

  /** @param {Database} db */
  constructor(db) {
    this.stmt = {
      get: db.prepare('SELECT user_id, secret, enabled_at, last_step FROM user_mfa WHERE user_id = ?'),
      upsertPending: db.prepare(`INSERT INTO user_mfa (user_id, secret, enabled_at, last_step, created_at) VALUES (?, ?, NULL, NULL, ?)
        ON CONFLICT (user_id) DO UPDATE SET secret = excluded.secret, enabled_at = NULL, last_step = NULL, created_at = excluded.created_at`),
      enable: db.prepare('UPDATE user_mfa SET enabled_at = ?, last_step = ? WHERE user_id = ? AND enabled_at IS NULL'),
      step: db.prepare('UPDATE user_mfa SET last_step = ? WHERE user_id = ? AND (last_step IS NULL OR last_step < ?)'),
      remove: db.prepare('DELETE FROM user_mfa WHERE user_id = ?'),
      codesClear: db.prepare('DELETE FROM mfa_recovery_codes WHERE user_id = ?'),
      codeInsert: db.prepare('INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES (?, ?)'),
      codeUse: db.prepare('UPDATE mfa_recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL'),
      codesLeft: db.prepare('SELECT COUNT(*) AS n FROM mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL'),
      challengeInsert: db.prepare('INSERT INTO mfa_challenges (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)'),
      challengeGet: db.prepare('SELECT token_hash, user_id, expires_at, attempts FROM mfa_challenges WHERE token_hash = ?'),
      challengeFail: db.prepare('UPDATE mfa_challenges SET attempts = attempts + 1 WHERE token_hash = ? RETURNING attempts'),
      challengeDelete: db.prepare('DELETE FROM mfa_challenges WHERE token_hash = ?'),
      challengesClear: db.prepare('DELETE FROM mfa_challenges WHERE user_id = ?'),
      challengePurge: db.prepare('DELETE FROM mfa_challenges WHERE expires_at < ?'),
      historyInsert: db.prepare('INSERT INTO password_history (user_id, hash, at) VALUES (?, ?, ?)'),
      historyRecent: db.prepare('SELECT hash FROM password_history WHERE user_id = ? ORDER BY at DESC, rowid DESC LIMIT ?'),
      historyTrim: db.prepare('DELETE FROM password_history WHERE user_id = ? AND rowid NOT IN (SELECT rowid FROM password_history WHERE user_id = ? ORDER BY at DESC, rowid DESC LIMIT ?)'),
      historyClear: db.prepare('DELETE FROM password_history WHERE user_id = ?'),
    };
  }

  /** @param {string} value */
  static hash(value) {
    return createHash('sha256').update(value).digest('hex');
  }

  /** Ten codes like `K7Q2M-X9DPA`; shown once, stored hashed. */
  static newRecoveryCodes(n = 10) {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    return Array.from({ length: n }, () => {
      const b = randomBytes(10);
      const s = [...b].map((x) => alphabet[x % alphabet.length]).join('');
      return `${s.slice(0, 5)}-${s.slice(5)}`;
    });
  }

  /** A typed recovery code in a comparable form (case, spaces and the dash do not matter). @param {string} code */
  static normalizeRecoveryCode(code) {
    const s = code.toUpperCase().replace(/[\s-]/g, '');
    return s.length === 10 ? `${s.slice(0, 5)}-${s.slice(5)}` : s;
  }

  /** @param {string} userId @returns {{ user_id: string, secret: string, enabled_at: number|null, last_step: number|null }|undefined} */
  get(userId) { return /** @type {any} */ (this.stmt.get.get(userId)); }
  /** @param {string} userId @param {string} sealed @param {number} now */
  setPending(userId, sealed, now) { this.stmt.upsertPending.run(userId, sealed, now); }
  /** @param {string} userId @param {number} step @param {number} now */
  enable(userId, step, now) { return Number(this.stmt.enable.run(now, step, userId).changes) === 1; }
  /** Record a used TOTP step; false when that step (or a later one) was already used. @param {string} userId @param {number} step */
  useStep(userId, step) { return Number(this.stmt.step.run(step, userId, step).changes) === 1; }
  /** @param {string} userId */
  remove(userId) { this.stmt.remove.run(userId); this.stmt.codesClear.run(userId); this.stmt.challengesClear.run(userId); }

  /** Replace the recovery codes; returns the plain codes. @param {string} userId */
  replaceRecoveryCodes(userId) {
    const codes = MfaStore.newRecoveryCodes();
    this.stmt.codesClear.run(userId);
    for (const c of codes) this.stmt.codeInsert.run(userId, MfaStore.hash(c));
    return codes;
  }

  /** @param {string} userId @param {string} code @param {number} now */
  useRecoveryCode(userId, code, now) { return Number(this.stmt.codeUse.run(now, userId, MfaStore.hash(MfaStore.normalizeRecoveryCode(code))).changes) === 1; }
  /** @param {string} userId */
  recoveryCodesLeft(userId) { return Number(/** @type {{ n: number }} */ (this.stmt.codesLeft.get(userId)).n); }

  /** @param {string} userId @param {number} ttlMs @param {number} now @returns {string} the plain token */
  createChallenge(userId, ttlMs, now) {
    const token = randomBytes(32).toString('base64url');
    this.stmt.challengeInsert.run(MfaStore.hash(token), userId, now + ttlMs, now);
    return token;
  }

  /** @param {string} token @param {number} now */
  challenge(token, now) {
    const row = /** @type {{ token_hash: string, user_id: string, expires_at: number, attempts: number }|undefined} */ (this.stmt.challengeGet.get(MfaStore.hash(token)));
    return row && row.expires_at > now && row.attempts < MfaStore.CHALLENGE_MAX_ATTEMPTS ? row : undefined;
  }

  /** Count a wrong code; the challenge is gone after the last allowed attempt. @param {string} tokenHash */
  failChallenge(tokenHash) {
    const r = /** @type {{ attempts: number }|undefined} */ (this.stmt.challengeFail.get(tokenHash));
    if (r && r.attempts >= MfaStore.CHALLENGE_MAX_ATTEMPTS) this.stmt.challengeDelete.run(tokenHash);
  }

  /** @param {string} tokenHash */
  deleteChallenge(tokenHash) { this.stmt.challengeDelete.run(tokenHash); }
  /** @param {number} now */
  purgeChallenges(now) { return Number(this.stmt.challengePurge.run(now).changes); }

  /** @param {string} userId @param {number} n */
  recentPasswords(userId, n) { return /** @type {{ hash: string }[]} */ (this.stmt.historyRecent.all(userId, n)).map((r) => r.hash); }
  /** Keep the replaced hash, at most `keep` per user. @param {string} userId @param {string} hash @param {number} keep @param {number} now */
  rememberPassword(userId, hash, keep, now) {
    if (keep <= 0) return;
    this.stmt.historyInsert.run(userId, hash, now);
    this.stmt.historyTrim.run(userId, userId, keep);
  }

  /** Everything MFA and history for one user (anonymisation). @param {string} userId */
  purgeUser(userId) { this.remove(userId); this.stmt.historyClear.run(userId); }
}
