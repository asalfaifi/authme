import { createHmac } from 'node:crypto';
import Redis from 'ioredis';
import { RateLimiterMemory, RateLimiterRedis } from 'rate-limiter-flexible';

function limiter(redis, options) {
  if (!redis) return new RateLimiterMemory(options);
  return new RateLimiterRedis({ storeClient: redis, insuranceLimiter: new RateLimiterMemory(options), ...options });
}

export function createRateLimits(config, logger) {
  const redis = config.redisUrl
    ? new Redis(config.redisUrl, { enableOfflineQueue: false, maxRetriesPerRequest: 1, lazyConnect: true })
    : null;
  if (redis) {
    redis.on('error', (error) => logger.warn({ error }, 'Redis rate-limit backend unavailable; insurance limiter is active'));
  }

  const loginIp = limiter(redis, { keyPrefix: 'authme:login:ip', points: 20, duration: 60, blockDuration: 60 });
  const loginAccount = limiter(redis, { keyPrefix: 'authme:login:account', points: 10, duration: 900, blockDuration: 900 });
  const admin = limiter(redis, { keyPrefix: 'authme:admin', points: 120, duration: 60, blockDuration: 60 });
  const registration = limiter(redis, { keyPrefix: 'authme:registration', points: 30, duration: 60, blockDuration: 60 });
  const deviceVerification = limiter(redis, { keyPrefix: 'authme:device:verify', points: 30, duration: 60, blockDuration: 60 });

  function opaqueKey(domain, value) {
    return createHmac('sha256', config.passwordPepper)
      .update(`authme-rate-limit\u0000${domain}\u0000${String(value || 'unknown')}`)
      .digest('base64url');
  }

  return {
    async consumeLogin(ip, account) {
      // A blocked source must not be able to poison arbitrary account buckets.
      await loginIp.consume(opaqueKey('login-ip', ip));
      await loginAccount.consume(opaqueKey('login-account', account));
    },
    async consumeAdmin(ip) {
      await admin.consume(opaqueKey('admin-ip', ip));
    },
    async consumeRegistration(ip) {
      await registration.consume(opaqueKey('registration-ip', ip));
    },
    async consumeDeviceVerification(ip) {
      await deviceVerification.consume(opaqueKey('device-ip', ip));
    },
    async ready() {
      if (!redis) return true;
      if (redis.status === 'wait') await redis.connect();
      return (await redis.ping()) === 'PONG';
    },
    async close() {
      if (redis && redis.status !== 'end') await redis.quit();
    },
  };
}
