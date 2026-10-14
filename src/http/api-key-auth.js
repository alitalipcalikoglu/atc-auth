import { ApiKeyAuth as CoreApiKeyAuth } from '@atc-web/atc-service-core/auth';
import { AuthError } from '../domain/errors.js';

/** @typedef {import('../types.js').ApiKey} ApiKey */

/**
 * Bearer API-key authentication for Fastify — the calling-backend key, not an end user's session
 * or JWT (those stay entirely local; nothing about login, tokens or passwords moves here). Thin
 * wrapper over service-core's `ApiKeyAuth`: `decorate` attaches `request.apiKeyId`, `apiKeyRole`
 * and `apiKeyScopes`, `identify()` keeps returning the id string.
 *
 * Stage 4 adds a role (`read`/`write`/`readwrite`, default `readwrite` — every key from before
 * Stage 4, plain `id:secret`, keeps its full access unchanged) and one flag, `proxy`. Only a handful
 * of clearly back-office mutations (`register`, `updateUser`, `deleteUser`) are gated by role today
 * — this is deliberately narrow, not a full read/write split across every route, since most routes
 * here proxy an end user's own action (login, refresh, password reset, …) and "read-only" has no
 * sensible meaning for them. `proxy` gates something unrelated to role: whether the key is trusted
 * to set `X-Client-IP` for the audit log (see `isProxyTrusted`) — a key without it gets `request.ip`
 * regardless of role.
 */
export class ApiKeyAuth {
  /** @param {ApiKey[]} apiKeys */
  constructor(apiKeys) {
    this.core = new CoreApiKeyAuth(apiKeys, {
      decorate: (request, key) => {
        request.apiKeyId = key.id;
        request.apiKeyRole = key.role;
        request.apiKeyScopes = key.scopes ?? null;
      },
    });
  }

  /** Fastify `onRequest` hook. */
  get hook() {
    return this.core.hook;
  }

  /**
   * @param {string} secret Presented secret.
   * @returns {string|undefined} Matching key id.
   */
  identify(secret) {
    return this.core.identify(secret)?.id;
  }

  /**
   * Route-level role guard as a Fastify `preHandler`. `write`/`readwrite` satisfy `need: 'write'`;
   * `read`/`readwrite` satisfy `need: 'read'`.
   * @param {'read'|'write'} need
   */
  static require(need) {
    return CoreApiKeyAuth.require(need, {
      roleOf: (request) => /** @type {any} */ (request).apiKeyRole,
      makeError: () => new AuthError('FORBIDDEN', `this API key does not have "${need}" access`),
      grants: { read: ['read', 'readwrite'], write: ['write', 'readwrite'] },
    });
  }

  /**
   * Whether the presented key may set `X-Client-IP` (see `AuthApi.ctx`). Unlike `scopes`
   * elsewhere in this codebase, `null`/omitted here means "not trusted" — the opposite of the
   * "no scopes = every scope" convention other services use for an allow-list, because this is a
   * single security-relevant flag, not a named-resource allow-list, and a key minted before this
   * flag existed must not silently gain IP-spoofing trust just because it has no scopes at all.
   * @param {import('fastify').FastifyRequest} request
   */
  static isProxyTrusted(request) {
    const scopes = /** @type {any} */ (request).apiKeyScopes;
    return Array.isArray(scopes) && scopes.includes('proxy');
  }
}
