import assert from 'node:assert/strict';
import { beforeEach, test } from 'node:test';
import { clearMemoryAdapter, createMemoryAdapter, revokeMemoryAccount } from '../src/adapters/memory.js';

beforeEach(() => clearMemoryAdapter());

test('account revocation removes sessions, grants, and grant-linked artifacts only in one realm', async () => {
  const securityVersionFor = async () => 0;
  const Master = createMemoryAdapter({ realm: 'master', securityVersionFor });
  const Staff = createMemoryAdapter({ realm: 'staff', securityVersionFor });
  const grants = new Master('Grant');
  const sessions = new Master('Session');
  const tokens = new Master('AccessToken');
  const staffGrants = new Staff('Grant');

  await grants.upsert('grant-alice', { accountId: 'alice' }, 600);
  await grants.upsert('grant-bob', { accountId: 'bob' }, 600);
  await sessions.upsert('session-alice', { accountId: 'alice' }, 600);
  await tokens.upsert('token-alice', { grantId: 'grant-alice', clientId: 'app' }, 600);
  await tokens.upsert('token-bob', { grantId: 'grant-bob', clientId: 'app' }, 600);
  await staffGrants.upsert('grant-alice', { accountId: 'alice' }, 600);

  assert.equal(revokeMemoryAccount('master', 'alice'), 3);
  assert.equal(await grants.find('grant-alice'), undefined);
  assert.equal(await sessions.find('session-alice'), undefined);
  assert.equal(await tokens.find('token-alice'), undefined);
  assert.ok(await grants.find('grant-bob'));
  assert.ok(await tokens.find('token-bob'));
  assert.ok(await staffGrants.find('grant-alice'));
});

test('account-bound records become invalid when the account security version changes', async () => {
  let version = 3;
  const Adapter = createMemoryAdapter({ realm: 'master', securityVersionFor: async () => version });
  const tokens = new Adapter('RefreshToken');
  await tokens.upsert('token', { accountId: 'alice' }, 600);
  assert.ok(await tokens.find('token'));
  version += 1;
  assert.equal(await tokens.find('token'), undefined);
});

test('grant-linked artifacts require a live parent at the same account epoch', async () => {
  let version = 4;
  const Adapter = createMemoryAdapter({ realm: 'master', securityVersionFor: async () => version });
  const grants = new Adapter('Grant');
  const tokens = new Adapter('AccessToken');
  await grants.upsert('grant', { accountId: 'alice' }, 600);
  await tokens.upsert('token', { grantId: 'grant' }, 600);
  assert.equal((await tokens.find('token')).accountId, 'alice');

  version += 1;
  await assert.rejects(tokens.upsert('late-token', { grantId: 'grant' }, 600), /invalid_grant/);
  await assert.rejects(tokens.upsert('wrong-account', { grantId: 'grant', accountId: 'bob' }, 600), /invalid_grant/);
  await assert.rejects(tokens.upsert('missing-parent', { grantId: 'missing' }, 600), /invalid_grant/);
});

test('a grant-linked save cannot cross an in-memory account revocation', async () => {
  let version = 8;
  let interleave = false;
  let firstBlockedLookup = true;
  let releaseLookup;
  let signalLookup;
  const lookupStarted = new Promise((resolve) => { signalLookup = resolve; });
  const lookupReleased = new Promise((resolve) => { releaseLookup = resolve; });
  const Adapter = createMemoryAdapter({
    realm: 'master',
    async securityVersionFor() {
      const captured = version;
      if (interleave && firstBlockedLookup) {
        firstBlockedLookup = false;
        signalLookup();
        await lookupReleased;
      }
      return captured;
    },
  });
  const grants = new Adapter('Grant');
  const tokens = new Adapter('AccessToken');
  await grants.upsert('grant', { accountId: 'alice' }, 600);

  interleave = true;
  const lateSave = tokens.upsert('late', { grantId: 'grant' }, 600);
  await lookupStarted;
  version += 1;
  revokeMemoryAccount('master', 'alice');
  releaseLookup();

  await assert.rejects(lateSave, /invalid_grant/);
  assert.equal(await grants.find('grant'), undefined);
  assert.equal(await tokens.find('late'), undefined);
});

test('backchannel requests enforce one-way completion and realm-local polling cadence', async () => {
  const securityVersionFor = async () => 1;
  const Master = createMemoryAdapter({ realm: 'master', securityVersionFor });
  const Staff = createMemoryAdapter({ realm: 'staff', securityVersionFor });
  const requests = new Master('BackchannelAuthenticationRequest');
  const staffRequests = new Staff('BackchannelAuthenticationRequest');
  const grants = new Master('Grant');

  await requests.upsert('auth-request', { accountId: 'alice', clientId: 'client' }, 600);
  assert.deepEqual(await requests.checkCibaPoll('auth-request', 'client', 1), {
    status: 'allowed', interval: 1,
  });
  assert.deepEqual(await requests.checkCibaPoll('auth-request', 'client', 1), {
    status: 'slow_down', interval: 6,
  });
  let continuedBackoff;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    continuedBackoff = await requests.checkCibaPoll('auth-request', 'client', 1);
  }
  assert.deepEqual(continuedBackoff, { status: 'slow_down', interval: 306 });
  assert.deepEqual(await requests.checkCibaPoll('auth-request', 'other-client', 1), { status: 'invalid' });
  assert.deepEqual(await staffRequests.checkCibaPoll('auth-request', 'client', 1), { status: 'invalid' });

  await grants.upsert('grant', { accountId: 'alice', clientId: 'client' }, 600);
  await requests.upsert('auth-request', { accountId: 'alice', clientId: 'client', grantId: 'grant' }, 600);
  await assert.rejects(
    requests.upsert('auth-request', { accountId: 'alice', clientId: 'client', grantId: 'grant' }, 600),
    /invalid_grant/,
  );
  await assert.rejects(
    requests.upsert('auth-request', { accountId: 'alice', clientId: 'client' }, 600),
    /invalid_grant/,
  );
});

test('expired backchannel payloads remain readable so the provider can return expired_token', async () => {
  const Adapter = createMemoryAdapter({ realm: 'master', securityVersionFor: async () => 1 });
  const requests = new Adapter('BackchannelAuthenticationRequest');
  await requests.upsert('expired', { accountId: 'alice', clientId: 'client' }, 0);
  assert.deepEqual(await requests.find('expired'), { accountId: 'alice', clientId: 'client' });
  assert.deepEqual(await requests.checkCibaPoll('expired', 'client', 1), { status: 'invalid' });
});
