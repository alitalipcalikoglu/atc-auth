import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/** RFC 6238 TOTP (SHA-1, 6 digits, 30 s) compatible with Google Authenticator, 1Password, Authy. */
export class Totp {
  static STEP_SEC = 30;
  static DIGITS = 6;
  static ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  /** @returns {string} 160-bit secret, base32. */
  static generateSecret() {
    return Totp.base32Encode(randomBytes(20));
  }

  /**
   * @param {string} secret Base32.
   * @param {number} step   Unix time / 30.
   */
  static code(secret, step) {
    const key = Totp.base32Decode(secret);
    const msg = Buffer.alloc(8);
    msg.writeBigUInt64BE(BigInt(step));
    const h = createHmac('sha1', key).update(msg).digest();
    const offset = h[h.length - 1] & 0x0f;
    const bin = ((h[offset] & 0x7f) << 24) | (h[offset + 1] << 16) | (h[offset + 2] << 8) | h[offset + 3];
    return String(bin % 10 ** Totp.DIGITS).padStart(Totp.DIGITS, '0');
  }

  /**
   * Accepts the current step and one on either side (clock drift). Returns the matching step so the
   * caller can refuse a second use of the same code, or null.
   * @param {string} secret
   * @param {string} input
   * @param {number} [nowMs]
   * @returns {number|null}
   */
  static verify(secret, input, nowMs = Date.now()) {
    if (!/^\d{6}$/.test(input)) return null;
    const step = Math.floor(nowMs / 1000 / Totp.STEP_SEC);
    for (const delta of [0, -1, 1]) {
      const expected = Buffer.from(Totp.code(secret, step + delta));
      if (timingSafeEqual(expected, Buffer.from(input))) return step + delta;
    }
    return null;
  }

  /**
   * otpauth:// URI for QR enrollment.
   * @param {{ secret: string, account: string, issuer: string }} o
   */
  static uri({ secret, account, issuer }) {
    const label = encodeURIComponent(`${issuer}:${account}`);
    return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${Totp.DIGITS}&period=${Totp.STEP_SEC}`;
  }

  /** @param {Buffer} buf */
  static base32Encode(buf) {
    let bits = 0;
    let value = 0;
    let out = '';
    for (const byte of buf) {
      value = (value << 8) | byte;
      bits += 8;
      while (bits >= 5) {
        out += Totp.ALPHABET[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) out += Totp.ALPHABET[(value << (5 - bits)) & 31];
    return out;
  }

  /** @param {string} str */
  static base32Decode(str) {
    const clean = str.toUpperCase().replace(/[^A-Z2-7]/g, '');
    const bytes = [];
    let bits = 0;
    let value = 0;
    for (const ch of clean) {
      value = (value << 5) | Totp.ALPHABET.indexOf(ch);
      bits += 5;
      if (bits >= 8) {
        bytes.push((value >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    return Buffer.from(bytes);
  }
}
