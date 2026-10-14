import { randomUUID } from 'node:crypto';

/** @typedef {import('../db.js').Database} Database */
/** @typedef {import('../types.js').EventRow} EventRow */
/** @typedef {import('@atc-web/atc-service-core/audit').AuditEvent} AuditEvent */

/**
 * Append-only security audit log, and (Stage 4) the transactional outbox that forwards each event
 * to the audit service durably. `record()` writes both rows — the `events` row (this service's own
 * log, read by `forUser`) and the `outbox` row (drained later by `AuditClient` in outbox mode) — in
 * one SQLite transaction, piggybacking on the caller's already-open transaction when there is one
 * (`db.inTransaction`) or opening its own otherwise. Either way, the two inserts commit or roll back
 * together: an audit event is never visible in the outbox before the business mutation it describes
 * has committed, and never exists at all if that transaction rolls back.
 */
export class EventStore {
  static COLUMNS = 'id, user_id, type, ip, meta, at';

  /**
   * @param {Database} db
   * @param {(e: { userId: string|null, type: string, ip: string|null, meta: object|null }, at: number) => AuditEvent & { at: string }} toAuditEvent
   *   Maps a security event onto the shape forwarded to the audit service (`{ action, outcome, ... }`,
   *   no `id`/`at` — this store adds those itself, `at` as the outbox row's own column so it is never
   *   duplicated inside the JSON payload).
   */
  constructor(db, toAuditEvent) {
    this.db = db;
    this.toAuditEvent = toAuditEvent;
    const C = EventStore.COLUMNS;
    this.stmt = {
      insert: db.prepare(`INSERT INTO events (user_id, type, ip, meta, at) VALUES (?, ?, ?, ?, ?)`),
      forUser: db.prepare(`SELECT ${C} FROM events WHERE user_id = ? AND id < ? ORDER BY id DESC LIMIT ?`),
      purge: db.prepare(`DELETE FROM events WHERE at < ?`),
      scrub: db.prepare(`UPDATE events SET ip = NULL, meta = NULL WHERE user_id = ?`),
      outboxInsert: db.prepare(`INSERT INTO outbox (id, at, payload) VALUES (?, ?, ?)`),
      outboxPending: db.prepare(`SELECT id, at, payload FROM outbox WHERE sent_at IS NULL ORDER BY at LIMIT ?`),
      outboxPurge: db.prepare(`DELETE FROM outbox WHERE sent_at IS NOT NULL AND sent_at < ?`),
    };
  }

  /**
   * @param {{ userId?: string|null, type: string, ip?: string|null, meta?: object|null }} e
   * @param {number} [now]
   */
  record({ userId = null, type, ip = null, meta = null }, now = Date.now()) {
    const insert = () => {
      this.stmt.insert.run(userId, type, ip, meta ? JSON.stringify(meta) : null, now);
      const { at: _at, ...payload } = this.toAuditEvent({ userId, type, ip, meta }, now);
      this.stmt.outboxInsert.run(randomUUID(), now, JSON.stringify(payload));
    };
    if (this.db.inTransaction) insert();
    else this.db.transaction(insert);
  }

  /**
   * Newest first, keyset pagination on id.
   * @param {string} userId
   * @param {{ limit: number, beforeId?: number }} q
   * @returns {EventRow[]}
   */
  forUser(userId, { limit, beforeId = Number.MAX_SAFE_INTEGER }) {
    return /** @type {EventRow[]} */ (this.stmt.forUser.all(userId, beforeId, limit));
  }

  /** Drop addresses and details from a user's stored events (their types and times stay). @param {string} userId */
  scrub(userId) {
    return Number(this.stmt.scrub.run(userId).changes);
  }

  /** @param {number} before */
  purge(before) {
    return Number(this.stmt.purge.run(before).changes);
  }

  /**
   * Outbox rows not yet sent, oldest first — an {@link import('@atc-web/atc-service-core/audit').OutboxSource}.
   * @param {number} limit
   */
  outboxPending(limit) {
    return /** @type {{ id: string, at: number, payload: string }[]} */ (this.stmt.outboxPending.all(limit));
  }

  /** @param {string[]} ids */
  outboxMarkSent(ids) {
    if (ids.length === 0) return;
    const now = Date.now();
    this.db.transaction(() => {
      const stmt = this.db.prepare(`UPDATE outbox SET sent_at = ? WHERE id = ?`);
      for (const id of ids) stmt.run(now, id);
    });
  }

  /** Delete sent rows older than `retentionDays`. @param {number} retentionDays */
  outboxPurge(retentionDays) {
    return Number(this.stmt.outboxPurge.run(Date.now() - retentionDays * 86_400_000).changes);
  }
}
