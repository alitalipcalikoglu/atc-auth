import { RequestContext } from '@atc-web/atc-service-core/request-context';

/**
 * Outbound transactional mail contract. The auth service never renders email itself; it
 * hands template data to the notify service.
 * @abstract
 */
export class Mailer {
  /**
   * @abstract
   * @param {{ to: string, name: string|null, url: string, expiresInMinutes: number }} m
   * @returns {Promise<void>}
   */
  async sendEmailVerification(m) {
    void m;
    throw new Error('Mailer.sendEmailVerification must be overridden');
  }

  /**
   * @abstract
   * @param {{ to: string, name: string|null, url: string, expiresInMinutes: number, requestIp: string|null }} m
   * @returns {Promise<void>}
   */
  async sendPasswordReset(m) {
    void m;
    throw new Error('Mailer.sendPasswordReset must be overridden');
  }

  /**
   * @abstract
   * @param {{ to: string, name: string|null, url: string, expiresInMinutes: number }} m  Sent to the NEW address.
   * @returns {Promise<void>}
   */
  async sendEmailChange(m) {
    void m;
    throw new Error('Mailer.sendEmailChange must be overridden');
  }

  /**
   * A plain security notice (new sign-in device, address changed).
   * @abstract
   * @param {{ to: string, name: string|null, kind: 'new_device'|'email_changed', details: Record<string, string> }} m
   * @returns {Promise<void>}
   */
  async sendNotice(m) {
    void m;
    throw new Error('Mailer.sendNotice must be overridden');
  }

  /** Readiness probe; throws when the backend is unreachable. */
  async verify() {}
}

export class MailerError extends Error {
  /**
   * @param {string} message
   * @param {{ statusCode?: number, cause?: unknown }} [info]
   */
  constructor(message, info = {}) {
    super(message, { cause: info.cause });
    this.name = 'MailerError';
    this.statusCode = info.statusCode;
  }
}

/**
 * {@link Mailer} backed by the notify service's HTTP API.
 */
export class NotifyMailer extends Mailer {
  /**
   * @param {object} o
   * @param {string} o.baseUrl        e.g. https://notify.internal:3001
   * @param {string} o.apiKey
   * @param {string} o.appName
   * @param {'tr'|'en'} o.locale
   * @param {number} o.timeoutMs
   * @param {typeof fetch} [o.fetch]  Injectable for tests.
   */
  constructor({ baseUrl, apiKey, appName, locale, timeoutMs, fetch: fetchImpl = fetch }) {
    super();
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.appName = appName;
    this.locale = locale;
    this.timeoutMs = timeoutMs;
    this.fetch = fetchImpl;
    this.#apiKey = apiKey;
  }

  /** @type {string} */
  #apiKey;

  /** @param {{ to: string, name: string|null, url: string, expiresInMinutes: number }} m */
  async sendEmailVerification(m) {
    await this.#send('email-verification', m.to, {
      appName: this.appName, locale: this.locale, verifyUrl: m.url, expiresInMinutes: m.expiresInMinutes, ...(m.name ? { name: m.name } : {}),
    });
  }

  /** @param {{ to: string, name: string|null, url: string, expiresInMinutes: number, requestIp: string|null }} m */
  async sendPasswordReset(m) {
    await this.#send('password-reset', m.to, {
      appName: this.appName, locale: this.locale, resetUrl: m.url, expiresInMinutes: m.expiresInMinutes,
      ...(m.name ? { name: m.name } : {}), ...(m.requestIp ? { requestIp: m.requestIp } : {}),
    });
  }

  /** @param {{ to: string, name: string|null, url: string, expiresInMinutes: number }} m */
  async sendEmailChange(m) {
    const tr = this.locale === 'tr';
    await this.#send('generic', m.to, {
      locale: this.locale, appName: this.appName,
      subject: tr ? `${this.appName}: e-posta adresinizi onaylayın` : `${this.appName}: confirm your new email address`,
      title: tr ? 'Yeni e-posta adresinizi onaylayın' : 'Confirm your new email address',
      paragraphs: [tr ? `Hesabınızın e-posta adresini bu adrese değiştirmek için aşağıdaki düğmeye ${m.expiresInMinutes} dakika içinde tıklayın. Bunu siz istemediyseniz bu iletiyi yok sayın.` : `Click the button within ${m.expiresInMinutes} minutes to make this the email address of your account. If you did not ask for this, ignore this message.`],
      button: { label: tr ? 'Adresi onayla' : 'Confirm address', url: m.url },
    });
  }

  /** @param {{ to: string, name: string|null, kind: 'new_device'|'email_changed', details: Record<string, string> }} m */
  async sendNotice(m) {
    const tr = this.locale === 'tr';
    const d = m.details;
    const lines = m.kind === 'new_device'
      ? [tr ? 'Hesabınıza daha önce kullanılmamış bir cihazdan giriş yapıldı.' : 'Your account was signed in to from a device we have not seen before.', ...(d.ip ? [`IP: ${d.ip}`] : []), ...(d.userAgent ? [`${tr ? 'Cihaz' : 'Device'}: ${d.userAgent}`] : []), tr ? 'Siz değilseniz parolanızı hemen değiştirin.' : 'If this was not you, change your password now.']
      : [tr ? 'Hesabınızın e-posta adresi değiştirildi. Bu adres artık bildirim almayacak.' : 'The email address of your account was changed. This address will no longer receive messages.', ...(d.ip ? [`IP: ${d.ip}`] : []), tr ? 'Siz yapmadıysanız hemen destekle iletişime geçin.' : 'If you did not do this, contact support immediately.'];
    await this.#send('generic', m.to, {
      locale: this.locale, appName: this.appName,
      subject: m.kind === 'new_device' ? (tr ? `${this.appName}: yeni cihazdan giriş` : `${this.appName}: new sign-in`) : (tr ? `${this.appName}: e-posta adresi değişti` : `${this.appName}: email address changed`),
      title: m.kind === 'new_device' ? (tr ? 'Yeni cihazdan giriş' : 'New sign-in') : (tr ? 'E-posta adresi değişti' : 'Email address changed'),
      paragraphs: lines,
    });
  }

  async verify() {
    const res = await this.#request('GET', '/health', undefined);
    if (!res.ok) throw new MailerError(`notify health returned ${res.status}`, { statusCode: res.status });
  }

  /**
   * @param {string} template
   * @param {string} to
   * @param {Record<string, unknown>} data
   */
  async #send(template, to, data) {
    const res = await this.#request('POST', '/v1/messages', { channel: 'email', template, to: [to], data });
    if (res.status !== 202 && res.status !== 200) {
      const text = (await res.text().catch(() => '')).slice(0, 500);
      throw new MailerError(`notify responded ${res.status}${text ? `: ${text}` : ''}`, { statusCode: res.status });
    }
  }

  /**
   * @param {'GET'|'POST'} method
   * @param {string} path
   * @param {object|undefined} body
   */
  async #request(method, path, body) {
    try {
      // Post-production Phase 5: explicit, opt-in propagation — notify is a fixed, trusted
      // internal platform dependency (never an operator-configured target), so this is the one
      // call site in auth that's allowed to attach it. `RequestContext.get()` is `null` outside a
      // real inbound request (a startup task, a test with no context set up); propagate nothing
      // in that case rather than fabricate a trace for it.
      const trace = RequestContext.get()?.propagationHeaders() ?? {};
      return await this.fetch(`${this.baseUrl}${path}`, {
        method,
        headers: { authorization: `Bearer ${this.#apiKey}`, ...(body ? { 'content-type': 'application/json' } : {}), ...trace },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(this.timeoutMs),
        redirect: 'error',
      });
    } catch (err) {
      throw new MailerError(`notify unreachable: ${err instanceof Error ? err.message : String(err)}`, { cause: err });
    }
  }
}
