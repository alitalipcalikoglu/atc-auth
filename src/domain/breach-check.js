import { createHash } from 'node:crypto';

/**
 * Optional check against the Have I Been Pwned password range API (k-anonymity): only the first five
 * hex characters of the password's SHA-1 leave the process, the comparison happens here, and the
 * request asks for padding so the response size says nothing either. A network or HTTP failure
 * never blocks a password: the check answers `null` and the caller lets the password through.
 */
export class BreachCheck {
  /**
   * @param {object} o
   * @param {string} o.url        API origin, e.g. https://api.pwnedpasswords.com
   * @param {number} o.timeoutMs
   * @param {typeof fetch} [o.fetch]
   * @param {{ warn: (obj: object, msg: string) => void }} [o.log]
   */
  constructor({ url, timeoutMs, fetch: fetchImpl = fetch, log }) {
    this.url = url.replace(/\/+$/, '');
    this.timeoutMs = timeoutMs;
    this.fetch = fetchImpl;
    this.log = log;
  }

  /**
   * How often the password appears in known breaches; `null` when the service could not be asked.
   * @param {string} password
   * @returns {Promise<number|null>}
   */
  async count(password) {
    const sha1 = createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
    const prefix = sha1.slice(0, 5);
    const suffix = sha1.slice(5);
    try {
      const res = await this.fetch(`${this.url}/range/${prefix}`, { headers: { 'add-padding': 'true', 'user-agent': 'atc-auth' }, redirect: 'error', signal: AbortSignal.timeout(this.timeoutMs) });
      if (!res.ok) throw new Error(`range API answered ${res.status}`);
      for (const line of (await res.text()).split('\n')) {
        const [hash, n] = line.trim().split(':');
        if (hash === suffix) return Number(n) || 0;
      }
      return 0;
    } catch (err) {
      this.log?.warn({ err: err instanceof Error ? err.message : String(err) }, 'password breach check unavailable, password accepted without it');
      return null;
    }
  }
}
