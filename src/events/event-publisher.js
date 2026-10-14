import { randomUUID } from 'node:crypto';

/**
 * Best-effort publisher of operational and domain events to atc-webhook-out (`POST /v1/events`).
 * `publish` never throws and never waits: events go into a bounded in-memory queue and one drain
 * loop sends them with a few retries. Every event carries the idempotency key `<source>:<uuid>`, so
 * a retry after a lost response never fans out twice. A full queue drops the oldest event; a
 * restart loses what is still queued, which is acceptable for alerts (the next failure raises them
 * again). Where an event must survive a crash the service keeps its own outbox instead (atc-payments).
 * Without a target the publisher is disabled and `publish` returns false.
 */
export class EventPublisher {
  static CAPACITY = 500;
  static RETRIES = 3;

  /**
   * @param {object} o
   * @param {string} o.source  Service id used in the idempotency key.
   * @param {{ url: string, apiKey: string, timeoutMs: number }|null} o.target
   * @param {typeof fetch} [o.fetchImpl]
   * @param {number} [o.backoffMs]  First retry delay; doubles per attempt.
   * @param {number} [o.capacity]
   */
  constructor({ source, target, fetchImpl = fetch, backoffMs = 500, capacity = EventPublisher.CAPACITY }) {
    this.source = source;
    this.target = target;
    this.fetch = fetchImpl;
    this.backoffMs = backoffMs;
    this.capacity = capacity;
    /** @type {{ type: string, data: unknown, key: string }[]} */
    this.queue = [];
    this.stats = { published: 0, sent: 0, dropped: 0, failed: 0 };
    /** @type {{ warn: Function }|undefined} */
    this.logger = undefined;
    this.closing = false;
    /** @type {Promise<void>|null} */
    this.draining = null;
    /** @type {AbortController} */
    this.abort = new AbortController();
  }

  get enabled() { return this.target !== null; }

  /**
   * `WEBHOOK_OUT_URL` and `WEBHOOK_OUT_API_KEY`, both or neither (a key with `publish` or `write` on atc-webhook-out).
   * @param {{ optional: (n: string) => string, integer: (n: string, d: number, o?: object) => number }} r
   * @param {new (m: string) => Error} ConfigError
   */
  static parseEnv(r, ConfigError) {
    const url = r.optional('WEBHOOK_OUT_URL').replace(/\/+$/, '');
    const apiKey = r.optional('WEBHOOK_OUT_API_KEY');
    if (!url && !apiKey) return null;
    if (!url || !apiKey) throw new ConfigError('WEBHOOK_OUT_URL and WEBHOOK_OUT_API_KEY must be set together');
    if (!/^https?:\/\/[^\s]+$/.test(url)) throw new ConfigError('WEBHOOK_OUT_URL must be an absolute http(s) URL');
    return { url, apiKey, timeoutMs: r.integer('WEBHOOK_OUT_TIMEOUT_MS', 5_000, { min: 500 }) };
  }

  /** Queue an event. @param {string} type @param {unknown} [data] @returns {boolean} false when disabled or closed. */
  publish(type, data = null) {
    if (!this.target || this.closing) return false;
    this.stats.published += 1;
    if (this.queue.length >= this.capacity) { this.queue.shift(); this.stats.dropped += 1; }
    this.queue.push({ type, data, key: `${this.source}:${randomUUID()}` });
    this.draining ??= this.#drain().finally(() => { this.draining = null; });
    return true;
  }

  /** Waits (bounded) for the queue to empty, then stops accepting events. @param {number} [timeoutMs] */
  async close(timeoutMs = 5_000) {
    this.closing = true;
    const timer = setTimeout(() => this.abort.abort(), timeoutMs);
    timer.unref();
    await this.draining?.catch(() => {});
    clearTimeout(timer);
  }

  /** Prometheus lines. @returns {string[]} */
  metricLines() {
    const s = this.stats;
    return [
      '# HELP events_publish_enabled 1 when WEBHOOK_OUT_URL is configured and events are published.',
      '# TYPE events_publish_enabled gauge',
      `events_publish_enabled ${this.enabled ? 1 : 0}`,
      '# HELP events_publish_total Events by outcome (dropped = lost for good, failed = gave up after retries).',
      '# TYPE events_publish_total counter',
      `events_publish_total{result="published"} ${s.published}`,
      `events_publish_total{result="sent"} ${s.sent}`,
      `events_publish_total{result="dropped"} ${s.dropped}`,
      `events_publish_total{result="failed"} ${s.failed}`,
      '# HELP events_publish_pending Events waiting to be sent.',
      '# TYPE events_publish_pending gauge',
      `events_publish_pending ${this.queue.length}`,
    ];
  }

  async #drain() {
    while (this.queue.length > 0 && !this.abort.signal.aborted) {
      const e = /** @type {{ type: string, data: unknown, key: string }} */ (this.queue[0]);
      let delay = this.backoffMs;
      let sent = false;
      for (let attempt = 0; attempt <= EventPublisher.RETRIES && !sent && !this.abort.signal.aborted; attempt += 1) {
        try {
          await this.#send(e);
          sent = true;
        } catch (err) {
          if (attempt === EventPublisher.RETRIES) this.logger?.warn({ err, type: e.type }, 'event not published');
          else if (!this.closing) { await new Promise((r) => { setTimeout(r, delay).unref(); }); delay *= 2; }
        }
      }
      this.queue.shift();
      if (sent) this.stats.sent += 1; else this.stats.failed += 1;
    }
  }

  /** @param {{ type: string, data: unknown, key: string }} e */
  async #send(e) {
    const t = /** @type {NonNullable<typeof this.target>} */ (this.target);
    const res = await this.fetch(`${t.url}/v1/events`, {
      method: 'POST',
      headers: { authorization: `Bearer ${t.apiKey}`, 'content-type': 'application/json' },
      body: JSON.stringify({ type: e.type, data: e.data, idempotencyKey: e.key }),
      redirect: 'error',
      signal: AbortSignal.any([AbortSignal.timeout(t.timeoutMs), this.abort.signal]),
    });
    if (!res.ok) throw new Error(`atc-webhook-out responded ${res.status}`);
  }
}
