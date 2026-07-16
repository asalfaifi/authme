import pino from 'pino';

const sensitiveFields = [
  'password',
  'currentPassword',
  'newPassword',
  'token',
  'tokens',
  'accessToken',
  'refreshToken',
  'idToken',
  'code',
  'code_verifier',
  'refresh_token',
  'client_secret',
  'clientSecret',
  'otp',
  'totp',
  'totpToken',
  'totpSecret',
  'provisioningUri',
  'recoveryCode',
  'recoveryCodes',
  'recoveryCodeHashes',
];

const redact = {
  paths: [
    'req.headers.authorization',
    'req.headers.cookie',
    'body',
    '*.body',
    ...sensitiveFields.flatMap((field) => [field, `*.${field}`, `*.*.${field}`]),
  ],
  censor: '[Redacted]',
};

export function loggableError(error, message) {
  const code = error?.code ?? error?.type;
  const bodyParsingError = typeof error?.type === 'string'
    && /^(?:charset|encoding|entity|request)\./u.test(error.type);
  return {
    name: typeof error?.name === 'string' ? error.name.slice(0, 128) : 'Error',
    code: typeof code === 'string' || typeof code === 'number' ? code : undefined,
    message: message ?? (bodyParsingError
      ? 'The request body could not be parsed safely.'
      : typeof error?.message === 'string' ? error.message.slice(0, 1024) : 'Unknown error'),
  };
}

export function createLogger(level = 'info') {
  return pino({
    level,
    redact,
    base: { service: 'authme' },
    timestamp: pino.stdTimeFunctions.isoTime,
  });
}
