import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { createAuthMeApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { authorizationCodeRoundTrip } from '../src/operations/authorization-code-rehearsal.js';

async function closeServer(server) {
  server.closeIdleConnections();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

test('load rehearsal counts each failed operation once and reports bounded reasons', async () => {
  let responses = 0;
  const server = createServer((_request, response) => {
    response.statusCode = 500 + responses;
    responses += 1;
    response.end('{"error":"unavailable"}');
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  const child = spawn(process.execPath, [
    fileURLToPath(new URL('../scripts/load-rehearsal.mjs', import.meta.url)),
    '--base-url', `http://127.0.0.1:${address.port}`,
    '--requests', '12', '--concurrency', '2', '--p95-ms', '500',
  ], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', (chunk) => { stdout += chunk; });
  child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr += chunk; });
  const exitCode = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', resolve);
  });
  await closeServer(server);
  assert.equal(exitCode, 1, stderr);
  assert.notEqual(stdout, '', stderr);
  const report = JSON.parse(stdout);
  assert.equal(report.failures, 12);
  assert.equal(Object.keys(report.failureReasons).length, 10);
  assert.equal(Object.values(report.failureReasons).reduce((sum, count) => sum + count, 0), 12);
  assert.equal(report.failureReasons['Discovery returned HTTP 500'], 1);
  assert.equal(report.failureReasons['Other failures'], 3);
});

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
    await closeServer(server);
  }
});
