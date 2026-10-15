import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AuditEvents } from '../src/domain/audit-events.js';
import { Maintenance } from '../src/maintenance.js';
import { ActionTokenStore } from '../src/store/action-token-store.js';
import { EventStore } from '../src/store/event-store.js';
import { SessionStore } from '../src/store/session-store.js';
import { UserStore } from '../src/store/user-store.js';
import { silentLog, testDb } from './helpers.js';

test('Maintenance purges expired sessions, spent tokens and old events', () => {
  const db = testDb();
  const users = new UserStore(db);
  const sessions = new SessionStore(db);
  const tokens = new ActionTokenStore(db);
  const events = new EventStore(db, AuditEvents.fromSecurityEvent);
  const u = users.create({ email: 'a@b.co', passwordHash: 'h' });
  const day = 86_400_000;
  const now = 100 * day;
  sessions.create({ userId: u.id, ttlMs: day }, now - 2 * day);           // expired
  sessions.create({ userId: u.id, ttlMs: 10 * day }, now);                // live
  const old = tokens.issue({ userId: u.id, purpose: 'verify_email', ttlMs: day }, now - 10 * day);
  tokens.consume(old, 'verify_email', now - 9 * day);                      // used long ago
  tokens.issue({ userId: u.id, purpose: 'reset_password', ttlMs: day }, now);
  events.record({ userId: u.id, type: 'old' }, now - 100 * day);
  events.record({ userId: u.id, type: 'new' }, now);

  const m = new Maintenance({ sessions, tokens, events, log: silentLog, options: { eventRetentionDays: 90 } });
  assert.deepEqual(m.run(now), { sessions: 1, tokens: 1, guard: 0, mfaChallenges: 0, events: 1 });
  assert.deepEqual(m.run(now), { sessions: 0, tokens: 0, guard: 0, mfaChallenges: 0, events: 0 });
  m.start();
  m.stop();
});
