/** @typedef {import('../types.js').UserRow} UserRow */
/** @typedef {import('../types.js').SessionRow} SessionRow */
/** @typedef {import('../types.js').EventRow} EventRow */

/** @param {number|null} ms */
const iso = (ms) => (ms === null ? null : new Date(ms).toISOString());

/** Public shapes returned by the API. Password hashes and token hashes never leave the store. */
export class Views {
  /** @param {UserRow} u */
  static user(u) {
    return {
      id: u.id,
      email: u.email,
      name: u.name,
      status: u.status,
      emailVerified: u.email_verified_at !== null,
      emailVerifiedAt: iso(u.email_verified_at),
      lockedUntil: u.locked_until !== null && u.locked_until > Date.now() ? iso(u.locked_until) : null,
      passwordChangedAt: iso(u.password_changed_at),
      mfaEnabled: u.mfa_enabled_at !== null,
      mfaEnabledAt: iso(u.mfa_enabled_at),
      createdAt: iso(u.created_at),
      updatedAt: iso(u.updated_at),
    };
  }

  /** @param {SessionRow} s */
  static session(s) {
    return { id: s.id, createdAt: iso(s.created_at), lastUsedAt: iso(s.last_used_at), expiresAt: iso(s.expires_at), ip: s.ip, userAgent: s.user_agent };
  }

  /** @param {EventRow} e */
  static event(e) {
    return { seq: Number(e.id), type: e.type, ip: e.ip, meta: e.meta ? JSON.parse(e.meta) : null, at: iso(e.at) };
  }

  /** @param {import('../domain/auth-service.js').TokenPair} t */
  static tokens(t) {
    return {
      tokenType: 'Bearer',
      accessToken: t.accessToken,
      accessTokenExpiresAt: iso(t.accessTokenExpiresAt),
      refreshToken: t.refreshToken,
      refreshTokenExpiresAt: iso(t.refreshTokenExpiresAt),
      sessionId: t.sessionId,
    };
  }
}
