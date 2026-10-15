/**
 * Shared JSDoc typedefs for the auth service. No runtime exports.
 */

/**
 * @typedef {object} ApiKey
 * @property {string} id
 * @property {string} secret
 * @property {string} [role]      `read`, `write`, or `readwrite` (default when omitted).
 * @property {string[]|null} [scopes]  `null` (no `:proxy` given) or `['proxy']`.
 */

/**
 * Plain values accepted by the `Config` constructor.
 * @typedef {object} ConfigValues
 * @property {number} port
 * @property {string} host
 * @property {string} logLevel
 * @property {boolean} trustProxy
 * @property {{ certPath: string, keyPath: string }|null} tls
 * @property {{ url: string, apiKey: string }|null} audit   Audit service to forward events to; null = off.
 * @property {{ url: string, apiKey: string, timeoutMs: number }|null} webhookOut  atc-webhook-out target for events; null = off.
 * @property {number} bodyLimit
 * @property {string} dbPath
 * @property {string} [dbBackupDir]
 * @property {ApiKey[]} apiKeys
 * @property {number} rateLimitMax
 * @property {string} jwtPrivateKeyPath       PEM, PKCS#8, EC P-256.
 * @property {string|null} jwtPreviousPublicKeyPath  PEM SPKI of the key being rotated out.
 * @property {string} jwtIssuer
 * @property {string} jwtAudience
 * @property {number} accessTokenTtlSec
 * @property {number} refreshTokenTtlDays
 * @property {number} verifyTokenTtlMin
 * @property {number} resetTokenTtlMin
 * @property {number} passwordMinLength
 * @property {number} scryptLogN
 * @property {number} loginMaxFailures        Failed sign-ins from one address for one account before that address is locked out.
 * @property {string} changeEmailUrlTemplate  Link in the confirmation mail for a new address; defaults to VERIFY_URL_TEMPLATE.
 * @property {number} loginMaxFailuresTotal   Failed sign-ins for one account from every address together before the account is locked.
 * @property {number} maxSessions             Active sessions per user; the oldest is revoked on the next sign-in. 0 = unlimited.
 * @property {boolean} newDeviceEmail         Mail the user when a sign-in comes from a device not seen before.
 * @property {number} loginLockoutMin
 * @property {boolean} loginRequiresVerifiedEmail
 * @property {number} resendCooldownSec
 * @property {string} notifyUrl
 * @property {string} notifyApiKey
 * @property {number} notifyTimeoutMs
 * @property {string} appName
 * @property {'tr'|'en'} emailLocale
 * @property {string} verifyUrlTemplate     Contains `{token}`.
 * @property {string} resetUrlTemplate      Contains `{token}`.
 * @property {number} eventRetentionDays
 * @property {number} auditOutboxRetentionDays  Sent outbox rows older than this are purged.
 * @property {Buffer|null} mfaSecretsKey  Seals end-user TOTP secrets; null = MFA unavailable.
 * @property {number} mfaChallengeTtlSec
 * @property {number} passwordHistory       Earlier passwords a new one may not repeat (0 = off).
 * @property {boolean} passwordBreachCheck
 * @property {string} passwordBreachUrl
 * @property {number} passwordBreachTimeoutMs
 */

/** @typedef {import('./config.js').Config} Config */

/** @typedef {'active'|'disabled'} UserStatus */

/**
 * @typedef {object} UserRow
 * @property {string} id
 * @property {string} email
 * @property {string|null} name
 * @property {string} password_hash
 * @property {UserStatus} status
 * @property {number|null} email_verified_at
 * @property {number} failed_logins
 * @property {number|null} locked_until
 * @property {number} password_changed_at
 * @property {number} created_at
 * @property {number} updated_at
 * @property {number|null} mfa_enabled_at  From `user_mfa`; null while MFA is off or only being set up.
 */

/**
 * A refresh-token family. `token_hash` is the currently valid refresh token.
 * @typedef {object} SessionRow
 * @property {string} id
 * @property {string} user_id
 * @property {string} token_hash
 * @property {string|null} previous_token_hash
 * @property {number} created_at
 * @property {number} last_used_at
 * @property {number} expires_at
 * @property {number|null} revoked_at
 * @property {string|null} ip
 * @property {string|null} user_agent
 */

/** @typedef {'verify_email'|'reset_password'|'change_email'} TokenPurpose */

/**
 * @typedef {object} ActionTokenRow
 * @property {string} token_hash
 * @property {string} user_id
 * @property {TokenPurpose} purpose
 * @property {string|null} payload  change_email: the new address.
 * @property {number} expires_at
 * @property {number|null} used_at
 * @property {number} created_at
 */

/**
 * @typedef {object} EventRow
 * @property {number} id
 * @property {string|null} user_id
 * @property {string} type
 * @property {string|null} ip
 * @property {string|null} meta   JSON.
 * @property {number} at
 */

/**
 * Claims embedded in an access token.
 * @typedef {object} AccessClaims
 * @property {string} sub            User id.
 * @property {string} sid            Session id.
 * @property {string} email
 * @property {boolean} email_verified
 */

/** @typedef {import('fastify').FastifyBaseLogger} Logger */

export {};
