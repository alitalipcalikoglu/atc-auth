import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RequestContext } from '@atc-web/atc-service-core/request-context';
import { TraceContext } from '@atc-web/atc-service-core/trace';
import { MailerError, NotifyMailer } from '../src/domain/mailer.js';

/** @param {(url: string, init: RequestInit) => Response|Promise<Response>} impl */
const mailerWith = (impl) => new NotifyMailer({ baseUrl: 'https://notify.local/', apiKey: 'k'.repeat(40), appName: 'Shop', locale: 'en', timeoutMs: 1000, fetch: /** @type {any} */ (impl) });

test('NotifyMailer posts template data with the API key and maps failures', async () => {
  /** @type {{ url: string, init: RequestInit }[]} */
  const calls = [];
  const m = mailerWith((url, init) => { calls.push({ url, init }); return new Response('{}', { status: 202 }); });
  await m.sendEmailVerification({ to: 'a@b.co', name: 'Ali', url: 'https://x/v?token=t', expiresInMinutes: 30 });
  await m.sendPasswordReset({ to: 'a@b.co', name: null, url: 'https://x/r?token=t', expiresInMinutes: 15, requestIp: '1.2.3.4' });
  await m.verify();
  assert.equal(calls[0].url, 'https://notify.local/v1/messages');
  assert.equal(/** @type {Record<string,string>} */ (calls[0].init.headers).authorization, `Bearer ${'k'.repeat(40)}`);
  const body = JSON.parse(String(calls[0].init.body));
  assert.deepEqual(body, { channel: 'email', template: 'email-verification', to: ['a@b.co'], data: { appName: 'Shop', locale: 'en', verifyUrl: 'https://x/v?token=t', expiresInMinutes: 30, name: 'Ali' } });
  const reset = JSON.parse(String(calls[1].init.body));
  assert.equal(reset.template, 'password-reset');
  assert.equal(reset.data.requestIp, '1.2.3.4');
  assert.equal('name' in reset.data, false);
  assert.equal(calls[2].url, 'https://notify.local/health');
  assert.equal(calls[2].init.method, 'GET');

  const bad = mailerWith(() => new Response('{"error":{"code":"X"}}', { status: 400 }));
  await assert.rejects(bad.sendEmailVerification({ to: 'a@b.co', name: null, url: 'https://x', expiresInMinutes: 1 }), (e) => e instanceof MailerError && e.statusCode === 400);
  const down = mailerWith(() => { throw new TypeError('fetch failed'); });
  await assert.rejects(down.verify(), (e) => e instanceof MailerError && /unreachable/.test(e.message));
});

test('NotifyMailer: post-production Phase 5 — propagates trace headers to notify (a trusted internal dependency) only when a RequestContext is active, opt-in, never fabricated', async () => {
  /** @type {{ init: RequestInit }[]} */
  const calls = [];
  const m = mailerWith((url, init) => { calls.push({ init }); return new Response('{}', { status: 202 }); });

  // No active RequestContext (e.g. a background task, not a real inbound request): no trace headers at all.
  await m.verify();
  const bare = /** @type {Record<string,string>} */ (calls[0].init.headers);
  assert.equal('traceparent' in bare, false);
  assert.equal('x-request-id' in bare, false);

  // Inside a real RequestContext: propagated, with a fresh child span, same trace-id.
  const inboundTrace = TraceContext.forRequest(undefined, false);
  const ctx = new RequestContext({ requestId: 'req-42', trace: inboundTrace });
  await RequestContext.run(ctx, () => m.verify());
  const withTrace = /** @type {Record<string,string>} */ (calls[1].init.headers);
  assert.equal(withTrace['x-request-id'], 'req-42');
  const parsed = TraceContext.parse(withTrace.traceparent);
  assert.equal(parsed?.traceId, inboundTrace.traceId);
  assert.notEqual(parsed?.spanId, inboundTrace.spanId, 'a fresh child span, never auth\'s own inbound span reused');
});
