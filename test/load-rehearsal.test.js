import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { createAuthMeApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { authorizationCodeRoundTrip } from '../src/operations/authorization-code-rehearsal.js';

test('representative load operation completes authorization, token, and refresh exchanges', { timeout: 30_000 }, async () => {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const redirectUri = 'http://127.0.0.1:49231/callback';
  const password = 'Representative-Load-Password-2026!';
  const runtime = await createAuthMeApp(loadConfig({
    AUTHME_DEV_MODE: 'true', AUTHME_PUBLIC_URL: baseUrl, AUTHME_PORT: String(address.port),
    AUTHME_LOG_LEVEL: 'silent', AUTHME_DEV_ADMIN_PASSWORD: password,
    AUTHME_CLIENTS_JSON: JSON.stringify({ master: [{
      client_id: 'load-test', client_name: 'Representative load test', application_type: 'native',
      token_endpoint_auth_method: 'none', redirect_uris: [redirectUri], response_types: ['code'],
      grant_types: ['authorization_code', 'refresh_token'],
    }] }),
  }));
  server.on('request', runtime.app);
  try {
    const result = await authorizationCodeRoundTrip({
      baseUrl, clientId: 'load-test', redirectUri, username: 'admin', password,
    });
    assert.equal(result.refreshed, true);
  } finally {
    await runtime.close();
    server.closeIdleConnections();
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
