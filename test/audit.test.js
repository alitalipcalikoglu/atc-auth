import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { AuditClient } from '@atc-web/atc-service-core/audit';
import { AuditEvents } from '../src/domain/audit-events.js';
import { Database } from '../src/db.js';
import { EventStore } from '../src/store/event-store.js';
import { UserStore } from '../src/store/user-store.js';

const silent = { warn() {}, error() {} };

/** @param {import('../src/db.js').Database} db @param {import('@atc-web/atc-service-core/audit').OutboxSource} outbox @param {any[]} [responses] */
function client(db, outbox, responses = [{ status: 200 }]) {
  let i = 0;
  const fetchImpl = /** @type {typeof fetch} */ (async (/** @type {any} */ _url, /** @type {any} */ init) => {
    const r = responses[Math.min(i, responses.length - 1)];
    i++;
    if (r.throws) throw new Error('ECONNREFUSED');
    return { ok: (r.status ?? 200) < 400, status: r.status ?? 200, text: async () => '' };
  });
  return new AuditClient({ target: { url: 'http://audit.test', apiKey: 'a'.repeat(40) }, logger: silent, sleep: async () => {}, fetch: fetchImpl, outbox });
}

/** @param {import('../src/db.js').Database} db */
function outboxSource(db) {
  const events = new EventStore(db, AuditEvents.fromSecurityEvent);
  return { events, outbox: { pending: (/** @type {number} */ limit) => events.outboxPending(limit), markSent: (/** @type {string[]} */ ids) => events.outboxMarkSent(ids), purge: () => {} } };
}

test('outbox row is inserted in the SAME transaction as the business mutation it describes', () => {
  const db = new Database(':memory:');
  const { events, outbox } = outboxSource(db);
  const users = new UserStore(db);
  db.transaction(() => {
    const u = users.create({ email: 'a@b.co', passwordHash: 'h' }, 1000);
    events.record({ userId: u.id, type: 'user.registered', ip: '1.2.3.4' }, 1000);
  });
  assert.equal(outbox.pending(10).length, 1);
  assert.equal(events.forUser(/** @type {any} */ (users.byEmail('a@b.co')).id, { limit: 10 }).length, 1);
});

test('1. business transaction rollback -> no outbox row (and no events row either)', () => {
  const db = new Database(':memory:');
  const { events, outbox } = outboxSource(db);
  const users = new UserStore(db);
  assert.throws(() => {
    db.transaction(() => {
      const u = users.create({ email: 'a@b.co', passwordHash: 'h' }, 1000);
      events.record({ userId: u.id, type: 'user.registered', ip: '1.2.3.4' }, 1000);
      throw new Error('simulated failure after the writes, before commit');
    });
  }, /simulated failure/);
  assert.equal(outbox.pending(10).length, 0, 'no outbox row survives the rollback');
  assert.equal(users.byEmail('a@b.co'), undefined, 'no user row either -- same transaction, same fate');
});

test('2. commit, then crash before delivery -> a fresh AuditClient against the same database delivers it on "restart"', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'auth-outbox-'));
  const path = join(dir, 'auth.db');
  try {
    const db1 = new Database(path);
    const { events: events1 } = outboxSource(db1);
    events1.record({ userId: 'u1', type: 'user.registered', ip: '1.2.3.4' }, 1000);
    db1.close(); // the "crash": no flush() ever ran against db1's AuditClient (there wasn't one)

    const db2 = new Database(path);
    const { outbox: outbox2 } = outboxSource(db2);
    /** @type {any[]} */ const sent = [];
    const fetchImpl = /** @type {typeof fetch} */ (async (/** @type {any} */ _url, /** @type {any} */ init) => {
      sent.push(...JSON.parse(String(init.body)).events);
      return { ok: true, status: 200, text: async () => '' };
    });
    const audit2 = new AuditClient({ target: { url: 'http://audit.test', apiKey: 'a'.repeat(40) }, logger: silent, fetch: fetchImpl, outbox: outbox2 });
    await audit2.flush();

    assert.equal(sent.length, 1);
    assert.equal(sent[0].action, 'atc-auth.user.registered');
    db2.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('3. duplicate delivery is safe/deterministic: the same outbox row is always sent with the same stable id', async () => {
  const db = new Database(':memory:');
  const { events, outbox } = outboxSource(db);
  events.record({ userId: 'u1', type: 'login.succeeded', ip: '1.2.3.4' }, 1000);

  const attempt1 = outbox.pending(10);
  // Simulate: delivery succeeded on the wire, but the process crashed before markSent ran.
  const attempt2 = outbox.pending(10); // "restart", nothing marked sent yet
  assert.equal(attempt1.length, 1);
  assert.equal(attempt2.length, 1);
  assert.equal(attempt1[0].id, attempt2[0].id, 'the retry after a crash-before-ack resends the identical id, so the audit service\'s UNIQUE(source, client_id) makes it a no-op there, not a new record');

  // End to end through AuditClient: two flushes with the row artificially left un-marked between
  // them both post the same id.
  const seenIds = /** @type {string[]} */ ([]);
  let markSentCalls = 0;
  const audit = client(db, {
    pending: (/** @type {number} */ limit) => events.outboxPending(limit),
    markSent: (/** @type {string[]} */ ids) => { markSentCalls++; if (markSentCalls > 1) events.outboxMarkSent(ids); }, // pretend the first markSent never happened (crash)
    purge: () => {},
  });
  const originalFetch = audit.fetch;
  audit.fetch = /** @type {any} */ (async (/** @type {any} */ url, /** @type {any} */ init) => { seenIds.push(JSON.parse(init.body).events[0].id); return originalFetch(url, init); });
  await audit.flush();
  await audit.flush();
  assert.equal(seenIds.length, 2);
  assert.equal(seenIds[0], seenIds[1], 'both delivery attempts used the exact same event id');
});

test('4. audit unavailable does not block or fail the business operation -- the event just stays pending', async () => {
  const db = new Database(':memory:');
  const { events, outbox } = outboxSource(db);
  const users = new UserStore(db);
  db.transaction(() => {
    const u = users.create({ email: 'a@b.co', passwordHash: 'h' }, 1000);
    events.record({ userId: u.id, type: 'user.registered', ip: '1.2.3.4' }, 1000);
  });
  assert.equal(users.byEmail('a@b.co')?.email, 'a@b.co', 'the write committed synchronously, independent of any network call');

  const audit = client(db, outbox, [{ throws: true }]);
  await audit.flush();
  assert.equal(outbox.pending(10).length, 1, 'still pending -- unreachable audit target neither loses nor falsely acknowledges the event');
});

test('5. restart/stale processing recovery: events recorded across two "process lifetimes" are all delivered exactly once, in order, none lost', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'auth-outbox-recovery-'));
  const path = join(dir, 'auth.db');
  try {
    const db1 = new Database(path);
    const { events: events1 } = outboxSource(db1);
    events1.record({ userId: 'u1', type: 'login.succeeded', ip: '1.1.1.1' }, 1000);
    events1.record({ userId: 'u1', type: 'logout', ip: '1.1.1.1' }, 2000);
    db1.close(); // crash: neither delivered

    const db2 = new Database(path);
    const { events: events2, outbox: outbox2 } = outboxSource(db2);
    events2.record({ userId: 'u1', type: 'session.refreshed', ip: '1.1.1.1' }, 3000); // a third event, this "restart"
    /** @type {string[]} */ const delivered = [];
    const audit2 = new AuditClient({
      target: { url: 'http://audit.test', apiKey: 'a'.repeat(40) }, logger: silent, outbox: outbox2,
      fetch: /** @type {any} */ (async (/** @type {any} */ _u, /** @type {any} */ init) => {
        for (const e of JSON.parse(init.body).events) delivered.push(e.action);
        return { ok: true, status: 200, text: async () => '' };
      }),
    });
    await audit2.flush();
    assert.deepEqual(delivered, ['atc-auth.login.succeeded', 'atc-auth.logout', 'atc-auth.session.refreshed'], 'oldest-first, nothing lost across the restart, the pre-restart backlog and the post-restart event both delivered exactly once');
    assert.equal(events2.outboxPending(10).length, 0);
    db2.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('security events are forwarded as auth.* audit events with outcome, actor and target', () => {
  const db = new Database(':memory:');
  const { events, outbox } = outboxSource(db);
  events.record({ userId: 'u1', type: 'login.failed', ip: '203.0.113.9', meta: { reason: 'bad_password', failures: 2 } }, Date.parse('2026-09-17T10:00:00Z'));
  events.record({ type: 'login.failed', ip: '203.0.113.9', meta: { reason: 'unknown_email' } }, Date.parse('2026-09-17T10:00:00Z'));
  events.record({ userId: 'u1', type: 'login.succeeded', ip: '203.0.113.9', meta: { sessionId: 's1' } }, Date.parse('2026-09-17T10:00:00Z'));
  const rows = outbox.pending(10).map((r) => ({ ...JSON.parse(r.payload), at: new Date(r.at).toISOString() }));
  const [a, b, c] = rows;
  assert.deepEqual([a.action, a.outcome, a.actor, a.target, a.ip, a.meta, a.at], ['atc-auth.login.failed', 'failure', { type: 'user', id: 'u1' }, { type: 'user', id: 'u1' }, '203.0.113.9', { reason: 'bad_password', failures: 2 }, '2026-09-17T10:00:00.000Z']);
  assert.deepEqual([b.actor, b.target, b.outcome], [undefined, undefined, 'failure']);
  assert.deepEqual([c.action, c.outcome], ['atc-auth.login.succeeded', 'success']);
  assert.equal(events.forUser('u1', { limit: 10 }).length, 2, 'local log still written');
});

test('AuditClient.record() throws in outbox mode -- inserting is EventStore\'s job, inside its own transaction', () => {
  const db = new Database(':memory:');
  const { outbox } = outboxSource(db);
  const audit = client(db, outbox);
  assert.throws(() => audit.record({ action: 'x' }), /not used in outbox mode/);
});
