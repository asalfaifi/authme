import assert from 'node:assert/strict';
import { test } from 'node:test';

import { createPostgresAdapter } from '../src/adapters/postgres.js';

function createMockPool(...results) {
  const calls = [];
  let resultIndex = 0;

  return {
    calls,
    async query(text, values) {
      calls.push({ text, values });
      const result = results[resultIndex];
      resultIndex += 1;
      return result ?? { rows: [], rowCount: 1 };
    },
  };
}

function compactSql(text) {
  return text.replace(/\s+/g, ' ').trim();
}

test('realm and model are bound on every lookup and isolate otherwise identical ids', async () => {
  const pool = createMockPool();
  const MasterAdapter = createPostgresAdapter({ pool, realm: 'master' });
  const StaffAdapter = createPostgresAdapter({ pool, realm: 'staff' });

  await new MasterAdapter('AccessToken').find('shared-id');
  await new MasterAdapter('Session').find('shared-id');
  await new StaffAdapter('AccessToken').find('shared-id');

  assert.deepEqual(
    pool.calls.map(({ values }) => values),
    [
      ['master', 'AccessToken', 'shared-id'],
      ['master', 'Session', 'shared-id'],
      ['staff', 'AccessToken', 'shared-id'],
    ],
  );
  assert.ok(pool.calls.every(({ text }) => /records\.realm_name = \$1 AND records\.model = \$2 AND records\.id = \$3/.test(compactSql(text))));
});

test('upsert binds the record, lookup fields, consumed time, and parameterized expiry', async () => {
  const pool = createMockPool();
  const Adapter = createPostgresAdapter({ pool, realm: 'master' });
  const adapter = new Adapter('AuthorizationCode');
  const payload = {
    accountId: '00000000-0000-4000-8000-000000000001',
    grantId: 'grant-1',
    userCode: 'ABCD-EFGH',
    uid: 'device-1',
    consumed: 1_700_000_123,
    nested: { prompt: 'login' },
  };

  await adapter.upsert('code-1', payload, '45.5');
  await adapter.upsert('code-without-expiry', {});

  const first = pool.calls[0];
  assert.deepEqual(first.values.slice(0, 5), [
    'master',
    'AuthorizationCode',
    'code-1',
    {
      accountId: '00000000-0000-4000-8000-000000000001',
      grantId: 'grant-1',
      userCode: 'ABCD-EFGH',
      uid: 'device-1',
      nested: { prompt: 'login' },
    },
    45.5,
  ]);
  assert.deepEqual(first.values.slice(5), [
    new Date(1_700_000_123_000),
    'grant-1',
    'ABCD-EFGH',
    'device-1',
    '00000000-0000-4000-8000-000000000001',
  ]);
  assert.deepEqual(payload, {
    accountId: '00000000-0000-4000-8000-000000000001',
    grantId: 'grant-1',
    userCode: 'ABCD-EFGH',
    uid: 'device-1',
    consumed: 1_700_000_123,
    nested: { prompt: 'login' },
  });

  const sql = compactSql(first.text);
  assert.match(sql, /INSERT INTO oidc_records/);
  assert.match(sql, /SELECT \$1, \$2, \$3, CASE WHEN security\.account_id IS NULL THEN \$4::jsonb/);
  assert.match(sql, /SELECT security_version FROM users/);
  assert.match(sql, /model='Grant' AND id=\$7/);
  assert.match(sql, /parent_grant\.account_security_version=users\.security_version/);
  assert.match(sql, /FOR SHARE OF users/);
  assert.match(sql, /jsonb_build_object\('accountId', security\.account_id\)/);
  assert.match(sql, /CASE WHEN \$5::double precision IS NULL THEN NULL/);
  assert.match(sql, /CURRENT_TIMESTAMP \+ \(\$5::double precision \* INTERVAL '1 second'\)/);
  assert.match(sql, /ON CONFLICT \(realm_name, model, id\) DO UPDATE/);
  assert.match(sql, /consumed_at = COALESCE\(oidc_records\.consumed_at, EXCLUDED\.consumed_at\)/);

  assert.deepEqual(pool.calls[1].values, [
    'master',
    'AuthorizationCode',
    'code-without-expiry',
    {},
    null,
    null,
    null,
    null,
    null,
    null,
  ]);
});

test('find restores consumed from either a Date or timestamp string and returns undefined when absent', async () => {
  const pool = createMockPool(
    {
      rows: [{
        payload: JSON.stringify({ accountId: 'account-1', consumed: 1 }),
        consumed_at: new Date('2024-01-02T03:04:05.987Z'),
      }],
    },
    {
      rows: [{
        payload: { accountId: 'account-2' },
        consumed_at: '2024-02-03T04:05:06.999Z',
      }],
    },
    { rows: [] },
  );
  const Adapter = createPostgresAdapter({ pool, realm: 'master' });
  const adapter = new Adapter('RefreshToken');

  assert.deepEqual(await adapter.find('token-1'), {
    accountId: 'account-1',
    consumed: 1_704_164_645,
  });
  assert.deepEqual(await adapter.find('token-2'), {
    accountId: 'account-2',
    consumed: 1_706_933_106,
  });
  assert.equal(await adapter.find('missing'), undefined);

  assert.deepEqual(pool.calls.map(({ values }) => values), [
    ['master', 'RefreshToken', 'token-1'],
    ['master', 'RefreshToken', 'token-2'],
    ['master', 'RefreshToken', 'missing'],
  ]);
  assert.ok(pool.calls.every(({ text }) => compactSql(text).includes(
    '(records.expires_at IS NULL OR records.expires_at > CURRENT_TIMESTAMP)',
  )));
  assert.ok(pool.calls.every(({ text }) => compactSql(text).includes(
    'users.security_version=records.account_security_version',
  )));
});

test('findByUserCode and findByUid use scoped indexed columns and restore payloads', async () => {
  const pool = createMockPool(
    { rows: [{ payload: { userCode: 'USER-CODE' }, consumed_at: null }] },
    {
      rows: [{
        payload: JSON.stringify({ uid: 'device-uid' }),
        consumed_at: new Date('2024-03-04T05:06:07.000Z'),
      }],
    },
  );
  const Adapter = createPostgresAdapter({ pool, realm: 'customers' });
  const adapter = new Adapter('DeviceCode');

  assert.deepEqual(await adapter.findByUserCode('USER-CODE'), { userCode: 'USER-CODE' });
  assert.deepEqual(await adapter.findByUid('device-uid'), {
    uid: 'device-uid',
    consumed: 1_709_528_767,
  });

  assert.deepEqual(pool.calls[0].values, ['customers', 'DeviceCode', 'USER-CODE']);
  assert.match(compactSql(pool.calls[0].text), /user_code = \$3/);
  assert.match(compactSql(pool.calls[0].text), /LIMIT 1$/);
  assert.deepEqual(pool.calls[1].values, ['customers', 'DeviceCode', 'device-uid']);
  assert.match(compactSql(pool.calls[1].text), /uid = \$3/);
  assert.match(compactSql(pool.calls[1].text), /LIMIT 1$/);
});

test('consume atomically claims a live record and rejects a losing claim', async () => {
  const pool = createMockPool({ rows: [{ id: 'token-1' }], rowCount: 1 }, { rows: [], rowCount: 0 });
  const Adapter = createPostgresAdapter({ pool, realm: 'master' });

  const adapter = new Adapter('AuthorizationCode');
  await adapter.consume('token-1');
  await assert.rejects(adapter.consume('token-1'), /invalid_grant/);

  assert.deepEqual(pool.calls[0].values, ['master', 'AuthorizationCode', 'token-1']);
  const sql = compactSql(pool.calls[0].text);
  assert.match(sql, /SET consumed_at = CURRENT_TIMESTAMP/);
  assert.match(sql, /updated_at = CURRENT_TIMESTAMP/);
  assert.match(sql, /realm_name = \$1 AND model = \$2 AND id = \$3/);
  assert.match(sql, /consumed_at IS NULL/);
  assert.match(sql, /RETURNING id$/);
});

test('replay-detection upsert is insert-only and rejects a conflicting claim', async () => {
  const pool = createMockPool({ rows: [], rowCount: 1 }, { rows: [], rowCount: 0 });
  const Adapter = createPostgresAdapter({ pool, realm: 'master' });
  const adapter = new Adapter('ReplayDetection');
  await adapter.upsert('proof', { iss: 'client' }, 60);
  await assert.rejects(adapter.upsert('proof', { iss: 'client' }, 60), /invalid_request/);
  assert.match(compactSql(pool.calls[0].text), /ON CONFLICT \(realm_name, model, id\) DO NOTHING RETURNING id$/);
});

test('destroy and revokeByGrantId delete only records in the adapter realm and model', async () => {
  const pool = createMockPool();
  const Adapter = createPostgresAdapter({ pool, realm: 'partners' });
  const adapter = new Adapter('Grant');

  await adapter.destroy('record-1');
  await adapter.revokeByGrantId('grant-1');

  assert.equal(
    compactSql(pool.calls[0].text),
    'DELETE FROM oidc_records WHERE realm_name = $1 AND model = $2 AND id = $3',
  );
  assert.deepEqual(pool.calls[0].values, ['partners', 'Grant', 'record-1']);
  assert.equal(
    compactSql(pool.calls[1].text),
    'DELETE FROM oidc_records WHERE realm_name = $1 AND model = $2 AND grant_id = $3',
  );
  assert.deepEqual(pool.calls[1].values, ['partners', 'Grant', 'grant-1']);
});

test('factory, constructor, and methods reject invalid identifiers before querying', async () => {
  const pool = createMockPool();

  assert.throws(() => createPostgresAdapter({ pool: null, realm: 'master' }), /pool must be a PostgreSQL queryable/);
  assert.throws(() => createPostgresAdapter({ pool: {}, realm: 'master' }), /pool must be a PostgreSQL queryable/);
  for (const realm of [undefined, null, '', 42]) {
    assert.throws(() => createPostgresAdapter({ pool, realm }), /realm must be a non-empty string/);
  }

  const Adapter = createPostgresAdapter({ pool, realm: 'master' });
  for (const model of [undefined, null, '', 42]) {
    assert.throws(() => new Adapter(model), /model must be a non-empty string/);
  }
  const adapter = new Adapter('Session');

  for (const id of [undefined, null, '', 42]) {
    await assert.rejects(adapter.upsert(id, {}), /id must be a non-empty string/);
    await assert.rejects(adapter.find(id), /id must be a non-empty string/);
    await assert.rejects(adapter.consume(id), /id must be a non-empty string/);
    await assert.rejects(adapter.destroy(id), /id must be a non-empty string/);
  }
  for (const userCode of [undefined, null, '', 42]) {
    await assert.rejects(adapter.findByUserCode(userCode), /userCode must be a non-empty string/);
  }
  for (const uid of [undefined, null, '', 42]) {
    await assert.rejects(adapter.findByUid(uid), /uid must be a non-empty string/);
  }
  for (const grantId of [undefined, null, '', 42]) {
    await assert.rejects(adapter.revokeByGrantId(grantId), /grantId must be a non-empty string/);
  }

  assert.equal(pool.calls.length, 0);
});

test('upsert rejects invalid payloads, lookup fields, consumed values, and expiry values', async () => {
  const pool = createMockPool();
  const Adapter = createPostgresAdapter({ pool, realm: 'master' });
  const adapter = new Adapter('Session');

  for (const payload of [undefined, null, 'payload', [], 7]) {
    await assert.rejects(adapter.upsert('record-1', payload), /payload must be an object/);
  }
  await assert.rejects(adapter.upsert('record-1', { grantId: '' }), /payload\.grantId must be a non-empty string/);
  await assert.rejects(adapter.upsert('record-1', { userCode: 7 }), /payload\.userCode must be a non-empty string/);
  await assert.rejects(adapter.upsert('record-1', { uid: {} }), /payload\.uid must be a non-empty string/);
  await assert.rejects(adapter.upsert('record-1', { accountId: 'not-a-uuid' }), /payload\.accountId must be a UUID/);

  for (const consumed of [-1, Number.NaN, Number.POSITIVE_INFINITY, 'not-a-time']) {
    await assert.rejects(
      adapter.upsert('record-1', { consumed }),
      /payload\.consumed must be a non-negative epoch timestamp/,
    );
  }
  for (const expiresIn of [-1, Number.NaN, Number.POSITIVE_INFINITY, 'not-a-duration']) {
    await assert.rejects(
      adapter.upsert('record-1', {}, expiresIn),
      /expiresIn must be a non-negative number of seconds/,
    );
  }

  assert.equal(pool.calls.length, 0);
});

test('all caller-controlled values are sent as parameters and never interpolated into SQL', async () => {
  const markers = {
    realm: "realm-'/*realm-marker*/",
    model: 'model-"/*model-marker*/',
    id: "id-' OR TRUE /*id-marker*/",
    grantId: "grant-' OR TRUE /*grant-marker*/",
    userCode: "code-' OR TRUE /*user-code-marker*/",
    uid: "uid-' OR TRUE /*uid-marker*/",
    payload: "value-' OR TRUE /*payload-marker*/",
  };
  const pool = createMockPool();
  const Adapter = createPostgresAdapter({ pool, realm: markers.realm });
  const adapter = new Adapter(markers.model);

  await adapter.upsert(markers.id, {
    value: markers.payload,
    grantId: markers.grantId,
    userCode: markers.userCode,
    uid: markers.uid,
  }, 60);
  await adapter.find(markers.id);
  await adapter.findByUserCode(markers.userCode);
  await adapter.findByUid(markers.uid);
  await adapter.consume(markers.id);
  await adapter.destroy(markers.id);
  await adapter.revokeByGrantId(markers.grantId);

  for (const { text } of pool.calls) {
    for (const marker of Object.values(markers)) {
      assert.equal(text.includes(marker), false, `SQL unexpectedly contains ${marker}`);
    }
  }
  assert.deepEqual(pool.calls[0].values, [
    markers.realm,
    markers.model,
    markers.id,
    {
      value: markers.payload,
      grantId: markers.grantId,
      userCode: markers.userCode,
      uid: markers.uid,
    },
    60,
    null,
    markers.grantId,
    markers.userCode,
    markers.uid,
    null,
  ]);
  assert.deepEqual(pool.calls.slice(1).map(({ values }) => values), [
    [markers.realm, markers.model, markers.id],
    [markers.realm, markers.model, markers.userCode],
    [markers.realm, markers.model, markers.uid],
    [markers.realm, markers.model, markers.id],
    [markers.realm, markers.model, markers.id],
    [markers.realm, markers.model, markers.grantId],
  ]);
});
