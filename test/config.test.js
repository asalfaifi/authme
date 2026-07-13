import assert from 'node:assert/strict';
import { test } from 'node:test';

import { issuerFor, loadConfig } from '../src/config.js';

const secret = (character) => character.repeat(32);

function productionEnvironment(overrides = {}) {
  return {
    AUTHME_PUBLIC_URL: 'https://login.example.test/',
    AUTHME_REALMS: 'master,staff',
    AUTHME_COOKIE_KEYS: `${secret('a')},${secret('b')}`,
    AUTHME_CSRF_SECRET: secret('c'),
    AUTHME_PASSWORD_PEPPER: secret('d'),
    AUTHME_SUBJECT_SALT: secret('e'),
    AUTHME_FIELD_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString('base64url'),
    AUTHME_ADMIN_TOKEN: secret('f'),
    AUTHME_JWKS_DIR: '/run/secrets/authme-jwks',
    DATABASE_URL: 'postgres://authme@db.example.test/authme',
    ...overrides,
  };
}

test('development configuration supplies safe defaults and freezes top-level collections', () => {
  const config = loadConfig({
    AUTHME_DEV_MODE: 'yes',
    AUTHME_REALMS: 'master, engineering',
    AUTHME_PORT: '4100',
    AUTHME_TRUST_PROXY: 'on',
  });

  assert.equal(config.devMode, true);
  assert.equal(config.trustProxy, true);
  assert.equal(config.publicUrl, 'http://127.0.0.1:4100');
  assert.equal(config.port, 4100);
  assert.deepEqual(config.realms, ['master', 'engineering']);
  assert.deepEqual(config.clientsByRealm, { master: [], engineering: [] });
  assert.equal(config.cookieKeys.length, 1);
  assert.ok(Buffer.byteLength(config.cookieKeys[0]) >= 32);
  assert.ok(Buffer.byteLength(config.csrfSecret) >= 32);
  assert.equal(config.fieldEncryptionKey.length, 32);
  assert.equal(config.accessTokenTtl, 300);
  assert.equal(config.authorizationCodeTtl, 60);
  assert.equal(config.sessionTtl, 28_800);
  assert.equal(config.auditRetentionDays, 90);
  assert.equal(Object.isFrozen(config), true);
  assert.equal(Object.isFrozen(config.realms), true);
  assert.equal(Object.isFrozen(config.cookieKeys), true);
});

test('an empty optional Redis URL is treated as disabled', () => {
  const config = loadConfig({ AUTHME_DEV_MODE: 'true', REDIS_URL: '' });
  assert.equal(config.redisUrl, undefined);
});

test('production configuration normalizes its URL and maps clients by realm', () => {
  const clients = {
    master: [{ client_id: 'console' }],
    staff: [{ client_id: 'timesheets' }],
  };
  const config = loadConfig(productionEnvironment({
    AUTHME_CLIENTS_JSON: JSON.stringify(clients),
    AUTHME_ACCESS_TOKEN_TTL_SECONDS: '600',
    AUTHME_AUTHORIZATION_CODE_TTL_SECONDS: '90',
    AUTHME_SESSION_TTL_SECONDS: '7200',
    AUTHME_ENABLE_DYNAMIC_REGISTRATION: 'TRUE',
  }));

  assert.equal(config.devMode, false);
  assert.equal(config.publicUrl, 'https://login.example.test');
  assert.deepEqual(config.clientsByRealm, clients);
  assert.equal(config.enableDynamicRegistration, true);
  assert.equal(Object.isFrozen(config.clientsByRealm), true);
  assert.equal(Object.isFrozen(config.clientsByRealm.master), true);
  assert.equal(Object.isFrozen(config.clientsByRealm.master[0]), true);
  assert.equal(config.accessTokenTtl, 600);
  assert.equal(config.authorizationCodeTtl, 90);
  assert.equal(config.sessionTtl, 7200);
  assert.equal(issuerFor(config, 'staff'), 'https://login.example.test/realms/staff');
  assert.throws(() => issuerFor(config, 'other'), /Unknown realm: other/);
});

test('production mode rejects unsafe or incomplete settings', () => {
  assert.throws(
    () => loadConfig(productionEnvironment({ AUTHME_PUBLIC_URL: 'http://login.example.test' })),
    /must use HTTPS/,
  );

  assert.throws(
    () => loadConfig(productionEnvironment({ AUTHME_COOKIE_KEYS: secret('a') })),
    /at least two comma-separated keys/,
  );

  assert.throws(
    () => loadConfig(productionEnvironment({ AUTHME_COOKIE_KEYS: `${secret('a')},${secret('a')}` })),
    /distinct keys/,
  );

  assert.throws(
    () => loadConfig(productionEnvironment({ AUTHME_PUBLIC_URL: 'https://user:password@login.example.test' })),
    /cannot contain credentials/,
  );

  assert.throws(
    () => loadConfig(productionEnvironment({ AUTHME_ADMIN_TOKEN: 'replace-with-a-production-admin-token-value' })),
    /example placeholder/,
  );

  const missingCsrfSecret = productionEnvironment();
  delete missingCsrfSecret.AUTHME_CSRF_SECRET;
  assert.throws(() => loadConfig(missingCsrfSecret), /AUTHME_CSRF_SECRET is required/);

  const missingDatabase = productionEnvironment();
  delete missingDatabase.DATABASE_URL;
  assert.throws(() => loadConfig(missingDatabase), /DATABASE_URL is required/);

  const missingJwks = productionEnvironment();
  delete missingJwks.AUTHME_JWKS_DIR;
  assert.throws(() => loadConfig(missingJwks), /AUTHME_JWKS_DIR is required/);

});

test('realm, client, key, URL, and TTL validation fail closed', () => {
  assert.throws(
    () => loadConfig({ AUTHME_DEV_MODE: 'true', AUTHME_REALMS: 'master,master' }),
    /duplicate realm names/,
  );
  assert.throws(
    () => loadConfig({ AUTHME_DEV_MODE: 'true', AUTHME_REALMS: 'Master' }),
    /Invalid realm name/,
  );
  assert.throws(
    () => loadConfig({ AUTHME_DEV_MODE: 'true', AUTHME_CLIENTS_JSON: '{not-json' }),
    /must contain valid JSON/,
  );
  assert.throws(
    () => loadConfig({ AUTHME_DEV_MODE: 'true', AUTHME_CLIENTS_JSON: '[]' }),
    /must be an object keyed by realm/,
  );
  assert.throws(
    () => loadConfig({
      AUTHME_DEV_MODE: 'true',
      AUTHME_FIELD_ENCRYPTION_KEY: Buffer.alloc(31).toString('base64url'),
    }),
    /base64url-encoded 32-byte key/,
  );
  assert.throws(
    () => loadConfig({ AUTHME_DEV_MODE: 'true', AUTHME_PUBLIC_URL: 'http://localhost/?mode=test' }),
    /cannot contain a query or fragment/,
  );
  assert.throws(
    () => loadConfig({ AUTHME_DEV_MODE: 'true', AUTHME_PUBLIC_URL: 'http://localhost/auth' }),
    /must be an origin without a path/,
  );
  assert.throws(
    () => loadConfig({ AUTHME_DEV_MODE: 'true', AUTHME_ACCESS_TOKEN_TTL_SECONDS: '59' }),
  );
});
