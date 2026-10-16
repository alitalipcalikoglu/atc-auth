import assert from 'node:assert/strict';
import { test } from 'node:test';
import { EventPublisher } from '../src/events/event-publisher.js';

const target = { url: 'http://hook', apiKey: 'k', timeoutMs: 1000 };
const settle = async (/** @type {EventPublisher} */ p) => { await p.close(2000); };

test('events: sent with a unique idempotency key, retried on failure, counted', async () => {
  /** @type {any[]} */ const calls = [];
  let fail = 2;
  const fetchImpl = /** @type {typeof fetch} */ (async (url, init) => {
    calls.push({ url, body: JSON.parse(String(init?.body)), auth: /** @type {any} */ (init?.headers).authorization, key: /** @type {any} */ (init?.headers)['idempotency-key'] });
    if (fail-- > 0) return new Response('x', { status: 503 });
    return new Response('{}', { status: 202 });
  });
  const p = new EventPublisher({ source: 'atc-x', target, fetchImpl, backoffMs: 1 });
  assert.equal(p.publish('ops.x.y', { a: 1 }), true);
  await settle(p);
  assert.equal(calls.length, 3);
  assert.deepEqual([calls[0].url, calls[0].auth, calls[0].body.type, calls[0].body.data], ['http://hook/v1/events', 'Bearer k', 'ops.x.y', { a: 1 }]);
  assert.equal(new Set(calls.map((c) => c.key)).size, 1, 'a retry reuses the key');
  assert.match(calls[0].key, /^atc-x:[0-9a-f-]{36}$/);
  assert.equal(calls[0].body.idempotencyKey, undefined, 'sent as the Idempotency-Key header, not in the body');
  assert.deepEqual(p.stats, { published: 1, sent: 1, dropped: 0, failed: 0 });
  assert.equal(p.publish('late'), false, 'closed');
});

test('events: gives up after the retries, drops the oldest when full, disabled does nothing', async () => {
  const fetchImpl = /** @type {typeof fetch} */ (async () => new Response('x', { status: 500 }));
  const p = new EventPublisher({ source: 'atc-x', target, fetchImpl, backoffMs: 1, capacity: 2 });
  p.publish('a'); p.publish('b'); p.publish('c'); p.publish('d');
  await settle(p);
  assert.equal(p.stats.published, 4);
  assert.ok(p.stats.dropped >= 1 && p.stats.failed >= 1);
  assert.match(p.metricLines().join('\n'), /events_publish_enabled 1/);
  const off = new EventPublisher({ source: 'atc-x', target: null });
  assert.equal(off.publish('a'), false);
  assert.match(off.metricLines().join('\n'), /events_publish_enabled 0/);
});

test('events: parseEnv needs url and key together', () => {
  class E extends Error {}
  const r = (/** @type {Record<string,string>} */ env) => ({ optional: (/** @type {string} */ n) => env[n] ?? '', integer: (/** @type {string} */ _n, /** @type {number} */ d) => d });
  assert.equal(EventPublisher.parseEnv(r({}), E), null);
  assert.deepEqual(EventPublisher.parseEnv(r({ WEBHOOK_OUT_URL: 'http://h/', WEBHOOK_OUT_API_KEY: 'k' }), E), { url: 'http://h', apiKey: 'k', timeoutMs: 5000 });
  assert.throws(() => EventPublisher.parseEnv(r({ WEBHOOK_OUT_URL: 'http://h' }), E), E);
  assert.throws(() => EventPublisher.parseEnv(r({ WEBHOOK_OUT_URL: 'ftp://h', WEBHOOK_OUT_API_KEY: 'k' }), E), E);
});
