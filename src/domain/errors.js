/**
 * Domain error with a stable machine-readable code and the HTTP status the API maps it to.
 */
export class AuthError extends Error {
  /** @type {Record<string, number>} */
  static STATUS = {
    EMAIL_TAKEN: 409,
    WEAK_PASSWORD: 400,
    INVALID_CREDENTIALS: 401,
    ACCOUNT_LOCKED: 423,
    ACCOUNT_DISABLED: 403,
    EMAIL_NOT_VERIFIED: 403,
    FORBIDDEN: 403,
    INVALID_TOKEN: 401,
    TOKEN_REUSED: 401,
    INVALID_ARGUMENT: 400,
    USER_NOT_FOUND: 404,
    SESSION_NOT_FOUND: 404,
    INVALID_MFA_CODE: 401,
    MFA_REQUIRED: 401,
    MFA_ALREADY_ENABLED: 409,
    MFA_NOT_ENABLED: 409,
    MFA_SETUP_REQUIRED: 409,
    MFA_UNAVAILABLE: 503,
  };

  /**
   * @param {keyof typeof AuthError.STATUS} code
   * @param {string} message
   * @param {Record<string, unknown>} [details]
   */
  constructor(code, message, details) {
    super(message);
    this.name = 'AuthError';
    this.code = code;
    this.statusCode = AuthError.STATUS[code];
    this.details = details;
  }
}
