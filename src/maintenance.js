/**
 * Periodic retention job: drops expired/revoked sessions, spent action tokens and old audit
 * events. Runs once at start and then on an interval.
 */
export class Maintenance {
  static INTERVAL_MS = 3_600_000;
  static REVOKED_SESSION_KEEP_MS = 30 * 86_400_000;
  static USED_TOKEN_KEEP_MS = 7 * 86_400_000;

  /**
   * @param {object} deps
   * @param {import('./store/session-store.js').SessionStore} deps.sessions
   * @param {import('./store/action-token-store.js').ActionTokenStore} deps.tokens
   * @param {import('./store/event-store.js').EventStore} deps.events
   * @param {import('./types.js').Logger} deps.log
   * @param {{ eventRetentionDays: number }} deps.options
   * @param {import('./store/guard-store.js').GuardStore} [deps.guard]
   */
  constructor({ sessions, tokens, events, log, options, guard }) {
    this.guard = guard;
    this.sessions = sessions;
    this.tokens = tokens;
    this.events = events;
    this.log = log;
    this.options = options;
    /** @type {NodeJS.Timeout|null} */
    this.timer = null;
  }

  start() {
    if (this.timer) return;
    this.run();
    this.timer = setInterval(() => this.run(), Maintenance.INTERVAL_MS);
    this.timer.unref();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /** @param {number} [now] */
  run(now = Date.now()) {
    try {
      const result = {
        sessions: this.sessions.purge(now, now - Maintenance.REVOKED_SESSION_KEEP_MS),
        tokens: this.tokens.purge(now, now - Maintenance.USED_TOKEN_KEEP_MS),
        guard: this.guard?.purge(now) ?? 0,
        events: this.events.purge(now - this.options.eventRetentionDays * 86_400_000),
      };
      if (result.sessions || result.tokens || result.events || result.guard) this.log.info(result, 'maintenance purged rows');
      return result;
    } catch (err) {
      this.log.error({ err }, 'maintenance failed');
      return null;
    }
  }
}
