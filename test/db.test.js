import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { Database } from '../src/db.js';

test('Database applies migrations once and enforces foreign keys', () => {
  const db = new Database(':memory:');
  const tables = /** @type {{ name: string }[]} */ (db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all()).map((r) => r.name);
  assert.deepEqual(tables, ['action_tokens', 'events', 'known_devices', 'login_failures', 'outbox', 'schema_migrations', 'sessions', 'users']);
  assert.equal(/** @type {{ user_version: number }} */ (db.prepare('PRAGMA user_version').get()).user_version, Database.MIGRATIONS.length);
  assert.throws(() => db.prepare("INSERT INTO sessions (id,user_id,token_hash,created_at,last_used_at,expires_at) VALUES ('s','missing','h',0,0,0)").run(), /FOREIGN KEY/);
  db.ping();
  db.close();
});

test('Database.transaction commits on success and rolls back on throw', () => {
  const db = new Database(':memory:');
  const insert = db.prepare("INSERT INTO events (type, at) VALUES (?, 0)");
  db.transaction(() => { insert.run('a'); insert.run('b'); });
  assert.throws(() => db.transaction(() => { insert.run('c'); throw new Error('boom'); }), /boom/);
  assert.equal(/** @type {{ n: number }} */ (db.prepare('SELECT COUNT(*) n FROM events').get()).n, 2);
});

test('Stage 4 migration v1 -> v2: an existing pre-outbox database gains the outbox table on upgrade, with its v1 data intact', () => {
  const dir = mkdtempSync(join(tmpdir(), 'auth-db-v1v2-'));
  const path = join(dir, 'auth.db');
  try {
    class V1Only extends Database {
      static MIGRATIONS = [Database.MIGRATIONS[0]];
    }
    const v1 = new V1Only(path);
    assert.equal(v1.schemaVersion, 1);
    v1.prepare("INSERT INTO users (id,email,password_hash,password_changed_at,created_at,updated_at) VALUES ('u1','a@b.co','h',0,0,0)").run();
    v1.prepare("INSERT INTO events (type, at) VALUES ('pre-upgrade', 0)").run();
    v1.close();

    const v2 = new Database(path); // this checkout's real MIGRATIONS: v1 schema + v2 outbox + v3 guards
    assert.equal(v2.schemaVersion, 3);
    assert.equal(/** @type {any} */ (v2.prepare("SELECT email FROM users WHERE id = 'u1'").get()).email, 'a@b.co', 'v1 data survived the upgrade');
    assert.equal(/** @type {any} */ (v2.prepare("SELECT COUNT(*) n FROM events").get()).n, 1);
    assert.equal(/** @type {any} */ (v2.prepare("SELECT COUNT(*) n FROM outbox").get()).n, 0, 'outbox table exists, empty (no historical events retrofitted into it)');
    v2.prepare("INSERT INTO outbox (id, at, payload) VALUES ('e1', 1, '{}')").run();
    assert.equal(/** @type {any} */ (v2.prepare("SELECT COUNT(*) n FROM outbox").get()).n, 1, 'usable immediately after the upgrade');
    v2.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
