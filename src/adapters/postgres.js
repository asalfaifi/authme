import { errors } from 'oidc-provider';

const backchannelRequestModel = 'BackchannelAuthenticationRequest';

function requiredIdentifier(value, name) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  return value;
}

function optionalIdentifier(value, name) {
  if (value == null) return null;
  return requiredIdentifier(value, name);
}

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function storedPayload(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new TypeError('payload must be an object');
  }

  // Consumption is stored as a timestamp column so it can be updated atomically.
  const { consumed, ...record } = payload;
  let consumedAt = null;
  if (consumed != null) {
    const epochSeconds = Number(consumed);
    if (!Number.isFinite(epochSeconds) || epochSeconds < 0) {
      throw new TypeError('payload.consumed must be a non-negative epoch timestamp');
    }
    consumedAt = new Date(epochSeconds * 1000);
  }

  return { record, consumedAt };
}

function restorePayload(row) {
  if (!row) return undefined;

  const decoded = typeof row.payload === 'string' ? JSON.parse(row.payload) : row.payload;
  const payload = { ...decoded };
  if (row.consumed_at != null) {
    const consumedAt = row.consumed_at instanceof Date
      ? row.consumed_at
      : new Date(row.consumed_at);
    payload.consumed = Math.floor(consumedAt.getTime() / 1000);
  }
  return payload;
}

function ttlSeconds(expiresIn) {
  if (expiresIn == null) return null;
  const seconds = Number(expiresIn);
  if (!Number.isFinite(seconds) || seconds < 0) {
    throw new TypeError('expiresIn must be a non-negative number of seconds');
  }
  return seconds;
}

/**
 * Creates an oidc-provider adapter class isolated to one realm.
 * Pass the returned class as the provider's `adapter` configuration value.
 */
export function createPostgresAdapter({ pool, realm }) {
  if (!pool || typeof pool.query !== 'function') {
    throw new TypeError('pool must be a PostgreSQL queryable');
  }
  const realmName = requiredIdentifier(realm, 'realm');

  return class PostgresAdapter {
    constructor(model) {
      this.model = requiredIdentifier(model, 'model');
    }

    async upsert(id, payload, expiresIn) {
      const recordId = requiredIdentifier(id, 'id');
      const lifetime = ttlSeconds(expiresIn);
      const { record, consumedAt } = storedPayload(payload);
      const grantId = optionalIdentifier(record.grantId, 'payload.grantId');
      const userCode = optionalIdentifier(record.userCode, 'payload.userCode');
      const uid = optionalIdentifier(record.uid, 'payload.uid');
      const accountId = optionalIdentifier(record.accountId, 'payload.accountId');
      if (accountId && !uuid.test(accountId)) throw new TypeError('payload.accountId must be a UUID');

      let conflict;
      if (this.model === 'ReplayDetection') {
        conflict = 'DO NOTHING';
      } else {
        const transition = this.model === backchannelRequestModel
          ? `WHERE (EXCLUDED.grant_id IS NOT NULL OR EXCLUDED.payload ? 'error')
             AND oidc_records.grant_id IS NULL
             AND NOT (oidc_records.payload ? 'error')
             AND oidc_records.consumed_at IS NULL`
          : '';
        conflict = `DO UPDATE SET
           payload = EXCLUDED.payload,
           expires_at = EXCLUDED.expires_at,
           consumed_at = COALESCE(oidc_records.consumed_at, EXCLUDED.consumed_at),
           grant_id = EXCLUDED.grant_id,
           user_code = EXCLUDED.user_code,
           uid = EXCLUDED.uid,
           account_security_version = EXCLUDED.account_security_version,
           updated_at = CURRENT_TIMESTAMP
           ${transition}`;
      }
      const result = await pool.query(
        `WITH account AS (
           SELECT security_version FROM users
           WHERE realm_name=$1 AND id=$10::uuid AND enabled
           FOR SHARE
         ), parent_grant AS (
           SELECT payload->>'accountId' AS account_id, account_security_version
           FROM oidc_records
           WHERE realm_name=$1 AND model='Grant' AND id=$7
             AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
           FOR SHARE
         ), parent_account AS (
           SELECT users.id, users.security_version
           FROM users
           JOIN parent_grant ON parent_grant.account_id=users.id::text
           WHERE users.realm_name=$1 AND users.enabled
             AND parent_grant.account_security_version=users.security_version
           FOR SHARE OF users
         ), security AS (
           SELECT COALESCE(
                    (SELECT security_version FROM account),
                    (SELECT security_version FROM parent_account)
                  ) AS version,
                  COALESCE($10::text, (SELECT id::text FROM parent_account)) AS account_id,
                  ($10::text IS NULL OR EXISTS (SELECT 1 FROM account))
                    AND ($7::text IS NULL OR EXISTS (SELECT 1 FROM parent_account))
                    AND ($10::text IS NULL OR $7::text IS NULL OR EXISTS (
                      SELECT 1 FROM parent_account WHERE id=$10::uuid
                    )) AS valid
         )
         INSERT INTO oidc_records
          (realm_name, model, id, payload, expires_at, consumed_at, grant_id, user_code, uid, account_security_version)
         SELECT
           $1, $2, $3,
           CASE WHEN security.account_id IS NULL THEN $4::jsonb
             ELSE $4::jsonb || jsonb_build_object('accountId', security.account_id) END,
           CASE WHEN $5::double precision IS NULL THEN NULL
             ELSE CURRENT_TIMESTAMP + ($5::double precision * INTERVAL '1 second') END,
           $6, $7, $8, $9, security.version
         FROM security WHERE security.valid
         ON CONFLICT (realm_name, model, id) ${conflict}
         RETURNING id`,
        [realmName, this.model, recordId, record, lifetime, consumedAt, grantId, userCode, uid, accountId],
      );
      if (this.model === backchannelRequestModel && result.rowCount !== 1) {
        throw new errors.InvalidGrant('backchannel authentication request state transition was rejected');
      }
      if ((accountId || grantId) && result.rowCount !== 1) {
        throw new errors.InvalidGrant('account or parent grant is unavailable or stale');
      }
      if (this.model === 'ReplayDetection' && result.rowCount !== 1) {
        throw new errors.InvalidRequest('replayed assertion or proof detected');
      }
    }

    async find(id) {
      const expiry = this.model === backchannelRequestModel
        ? ''
        : 'AND (records.expires_at IS NULL OR records.expires_at > CURRENT_TIMESTAMP)';
      const result = await pool.query(
        `SELECT records.payload, records.consumed_at
           FROM oidc_records AS records
          WHERE records.realm_name = $1 AND records.model = $2 AND records.id = $3
            ${expiry}
            AND (records.account_security_version IS NULL OR EXISTS (
              SELECT 1 FROM users
              WHERE users.realm_name=records.realm_name
                AND users.id=(records.payload->>'accountId')::uuid
                AND users.enabled
                AND users.security_version=records.account_security_version
            ))`,
        [realmName, this.model, requiredIdentifier(id, 'id')],
      );
      return restorePayload(result.rows[0]);
    }

    async findByUserCode(userCode) {
      const result = await pool.query(
        `SELECT records.payload, records.consumed_at
           FROM oidc_records AS records
          WHERE records.realm_name = $1 AND records.model = $2 AND records.user_code = $3
            AND (records.expires_at IS NULL OR records.expires_at > CURRENT_TIMESTAMP)
            AND (records.account_security_version IS NULL OR EXISTS (
              SELECT 1 FROM users
              WHERE users.realm_name=records.realm_name
                AND users.id=(records.payload->>'accountId')::uuid
                AND users.enabled
                AND users.security_version=records.account_security_version
            ))
          LIMIT 1`,
        [realmName, this.model, requiredIdentifier(userCode, 'userCode')],
      );
      return restorePayload(result.rows[0]);
    }

    async findByUid(uid) {
      const result = await pool.query(
        `SELECT records.payload, records.consumed_at
           FROM oidc_records AS records
          WHERE records.realm_name = $1 AND records.model = $2 AND records.uid = $3
            AND (records.expires_at IS NULL OR records.expires_at > CURRENT_TIMESTAMP)
            AND (records.account_security_version IS NULL OR EXISTS (
              SELECT 1 FROM users
              WHERE users.realm_name=records.realm_name
                AND users.id=(records.payload->>'accountId')::uuid
                AND users.enabled
                AND users.security_version=records.account_security_version
            ))
          LIMIT 1`,
        [realmName, this.model, requiredIdentifier(uid, 'uid')],
      );
      return restorePayload(result.rows[0]);
    }

    async consume(id) {
      const result = await pool.query(
        `UPDATE oidc_records
            SET consumed_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
          WHERE realm_name = $1 AND model = $2 AND id = $3
            AND consumed_at IS NULL
            AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
          RETURNING id`,
        [realmName, this.model, requiredIdentifier(id, 'id')],
      );
      if (result.rowCount !== 1) {
        if (['AuthorizationCode', 'RefreshToken', 'DeviceCode', backchannelRequestModel].includes(this.model)) {
          throw new errors.InvalidGrant('one-use grant artifact was already consumed');
        }
        throw new errors.InvalidRequest('one-use artifact was already consumed');
      }
    }

    async checkCibaPoll(id, clientId, intervalSeconds) {
      if (this.model !== backchannelRequestModel) throw new TypeError('CIBA polling is only valid for backchannel authentication requests');
      const interval = Number(intervalSeconds);
      if (!Number.isSafeInteger(interval) || interval < 1 || interval > 300) {
        throw new TypeError('CIBA polling interval must be an integer between 1 and 300 seconds');
      }
      const result = await pool.query(
        `WITH target AS MATERIALIZED (
           SELECT records.id, records.ciba_poll_interval_seconds,
                  records.ciba_next_poll_at IS NULL
                    OR records.ciba_next_poll_at <= CURRENT_TIMESTAMP AS allowed
           FROM oidc_records AS records
           WHERE records.realm_name=$1 AND records.model='BackchannelAuthenticationRequest'
             AND records.id=$2 AND records.payload->>'clientId'=$3
             AND records.consumed_at IS NULL
             AND records.expires_at > CURRENT_TIMESTAMP
             AND (records.account_security_version IS NULL OR EXISTS (
               SELECT 1 FROM users
               WHERE users.realm_name=records.realm_name
                 AND users.id=(records.payload->>'accountId')::uuid
                 AND users.enabled
                 AND users.security_version=records.account_security_version
             ))
           FOR UPDATE
         ), updated AS (
           UPDATE oidc_records AS records
           SET ciba_poll_interval_seconds=CASE WHEN target.allowed
                 THEN COALESCE(target.ciba_poll_interval_seconds, $4::integer)
                 ELSE LEAST(COALESCE(target.ciba_poll_interval_seconds, $4::integer) + 5, 300)
               END,
               ciba_next_poll_at=CURRENT_TIMESTAMP + (CASE WHEN target.allowed
                 THEN COALESCE(target.ciba_poll_interval_seconds, $4::integer)
                 ELSE LEAST(COALESCE(target.ciba_poll_interval_seconds, $4::integer) + 5, 300)
               END * INTERVAL '1 second'),
               updated_at=CURRENT_TIMESTAMP
           FROM target
           WHERE records.realm_name=$1 AND records.model='BackchannelAuthenticationRequest'
             AND records.id=target.id
           RETURNING target.allowed, records.ciba_poll_interval_seconds
         )
         SELECT allowed, ciba_poll_interval_seconds FROM updated`,
        [realmName, requiredIdentifier(id, 'id'), requiredIdentifier(clientId, 'clientId'), interval],
      );
      const row = result.rows[0];
      if (!row) return { status: 'invalid' };
      return {
        status: row.allowed ? 'allowed' : 'slow_down',
        interval: Number(row.ciba_poll_interval_seconds),
      };
    }

    async destroy(id) {
      await pool.query(
        'DELETE FROM oidc_records WHERE realm_name = $1 AND model = $2 AND id = $3',
        [realmName, this.model, requiredIdentifier(id, 'id')],
      );
    }

    async revokeByGrantId(grantId) {
      await pool.query(
        'DELETE FROM oidc_records WHERE realm_name = $1 AND model = $2 AND grant_id = $3',
        [realmName, this.model, requiredIdentifier(grantId, 'grantId')],
      );
    }
  };
}

export default createPostgresAdapter;
