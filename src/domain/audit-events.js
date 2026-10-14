/** @typedef {import('@atc-web/atc-service-core/audit').AuditEvent} AuditEvent */

/**
 * Maps the security events this service stores per user onto audit-service events: every event
 * becomes `auth.<type>`; attempts that did not succeed are `failure`, everything else `success`.
 */
export class AuditEvents {
  /** Event types recorded as failures. */
  static FAILURES = new Set(['login.failed', 'password.change_failed', 'session.reuse_detected', 'account.locked', 'email.change_failed']);

  /**
   * @param {{ userId: string|null, type: string, ip: string|null, meta: object|null }} e
   * @param {number} at
   * @returns {AuditEvent & { at: string }}
   */
  static fromSecurityEvent(e, at) {
    return {
      action: `atc-auth.${e.type}`,
      outcome: AuditEvents.FAILURES.has(e.type) ? 'failure' : 'success',
      actor: e.userId ? { type: 'user', id: e.userId } : undefined,
      target: e.userId ? { type: 'user', id: e.userId } : undefined,
      ip: e.ip ?? undefined,
      meta: e.meta ?? undefined,
      at: new Date(at).toISOString(),
    };
  }
}
