import pino from 'pino';

const redact = {
  paths: [
    'req.headers.authorization',
    'req.headers.cookie',
    'req.body.password',
    'req.body.token',
    'req.body.code',
    'req.body.code_verifier',
    'req.body.refresh_token',
    'req.body.client_secret',
    'password',
    'token',
    'refreshToken',
    'clientSecret',
    'totpSecret',
  ],
  censor: '[Redacted]',
};

export function createLogger(level = 'info') {
  return pino({
    level,
    redact,
    base: { service: 'authme' },
    timestamp: pino.stdTimeFunctions.isoTime,
  });
}
