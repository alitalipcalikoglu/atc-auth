/** JSON Schemas for the HTTP surface. */
export class Schemas {
  static uuid = { type: 'string', format: 'uuid' };
  static email = { type: 'string', format: 'email', maxLength: 254 };
  static password = { type: 'string', minLength: 1, maxLength: 1024 };
  static opaqueToken = { type: 'string', minLength: 1, maxLength: 128 };
  static name = { type: 'string', minLength: 1, maxLength: 120, nullable: true };

  /**
   * @param {string[]} required
   * @param {Record<string, object>} properties
   */
  static body(required, properties) {
    return { type: 'object', additionalProperties: false, required, properties };
  }

  static idParams = { type: 'object', properties: { id: Schemas.uuid }, required: ['id'] };
  static idSidParams = { type: 'object', properties: { id: Schemas.uuid, sid: Schemas.uuid }, required: ['id', 'sid'] };

  static listUsersQuery = {
    type: 'object',
    additionalProperties: false,
    properties: {
      email: Schemas.email,
      limit: { type: 'string', pattern: '^([1-9]|[1-9][0-9]|100)$' },
      cursor: { type: 'string', maxLength: 128 },
    },
  };

  static listEventsQuery = {
    type: 'object',
    additionalProperties: false,
    properties: {
      limit: { type: 'string', pattern: '^([1-9]|[1-9][0-9]|100)$' },
      before: { type: 'string', pattern: '^[0-9]{1,15}$' },
    },
  };

  static register = Schemas.body(['email', 'password'], { email: Schemas.email, password: Schemas.password, name: Schemas.name });
  static login = Schemas.body(['email', 'password'], { email: Schemas.email, password: Schemas.password });
  static refresh = Schemas.body(['refreshToken'], { refreshToken: Schemas.opaqueToken });
  static introspect = Schemas.body(['accessToken'], { accessToken: { type: 'string', minLength: 1, maxLength: 4096 } });
  static token = Schemas.body(['token'], { token: Schemas.opaqueToken });
  static emailOnly = Schemas.body(['email'], { email: Schemas.email });
  static resetPassword = Schemas.body(['token', 'password'], { token: Schemas.opaqueToken, password: Schemas.password });
  static changePassword = Schemas.body(['currentPassword', 'newPassword'], { currentPassword: Schemas.password, newPassword: Schemas.password });
  static changeEmail = Schemas.body(['email', 'password', 'newEmail'], { email: Schemas.email, password: Schemas.password, newEmail: Schemas.email });
  static patchUser = {
    type: 'object', additionalProperties: false, minProperties: 1,
    properties: { name: Schemas.name, email: Schemas.email, status: { type: 'string', enum: ['active', 'disabled'] } },
  };
}
