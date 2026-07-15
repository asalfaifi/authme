import { randomUUID } from 'node:crypto';

import { SCIM_URNS } from '../scim/constants.js';
import { ScimRepositoryError } from '../scim/errors.js';
import { parseFilter } from '../scim/filter.js';

function repositoryError(code, message) {
  return new ScimRepositoryError(code, message);
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isUuid(value) {
  return typeof value === 'string' && uuidPattern.test(value);
}

function json(value) {
  if (!value) return {};
  return typeof value === 'string' ? JSON.parse(value) : value;
}

function scimAttributes(attributes) {
  const { password, externalId, userName, active, ...safe } = attributes;
  return safe;
}

function primaryValue(values) {
  if (!Array.isArray(values)) return '';
  const primary = values.find((item) => item?.primary === true && typeof item.value === 'string');
  const first = values.find((item) => typeof item?.value === 'string');
  return String(primary?.value ?? first?.value ?? '').trim();
}

function coreUser(attributes, id) {
  const extra = scimAttributes(attributes);
  const givenName = String(attributes.name?.givenName ?? '').trim();
  const familyName = String(attributes.name?.familyName ?? '').trim();
  const displayName = String(attributes.displayName
    ?? attributes.name?.formatted
    ?? [givenName, familyName].filter(Boolean).join(' ')
    ?? attributes.userName).trim() || attributes.userName;
  const email = primaryValue(attributes.emails).toLowerCase()
    || (String(attributes.userName).includes('@') ? String(attributes.userName).toLowerCase() : `scim-${id}@invalid.local`);
  const roles = Array.isArray(attributes.roles)
    ? [...new Set(attributes.roles.map((role) => String(role?.value ?? role?.display ?? '').trim()).filter(Boolean))]
    : [];
  return {
    username: attributes.userName,
    email,
    emailVerified: Boolean(attributes.emails?.find((item) => item?.value?.toLowerCase?.() === email)?.verified),
    displayName,
    givenName,
    familyName,
    enabled: attributes.active !== false,
    roles,
    extra,
  };
}

function rowToUser(row) {
  if (!row) return undefined;
  const attributes = json(row.scim_attributes);
  return {
    ...attributes,
    userName: row.username,
    ...(row.external_id == null ? {} : { externalId: row.external_id }),
    displayName: row.display_name,
    name: {
      ...(attributes.name ?? {}),
      ...(row.given_name ? { givenName: row.given_name } : {}),
      ...(row.family_name ? { familyName: row.family_name } : {}),
      formatted: row.display_name,
    },
    emails: Array.isArray(attributes.emails) && attributes.emails.length
      ? attributes.emails : [{ value: row.email, primary: true }],
    roles: Array.isArray(attributes.roles) && attributes.roles.length
      ? attributes.roles : row.roles.map((value) => ({ value })),
    active: row.enabled,
    id: row.id,
    version: Number(row.version),
    createdAt: row.scim_created_at?.toISOString?.() ?? row.scim_created_at,
    updatedAt: row.scim_updated_at?.toISOString?.() ?? row.scim_updated_at,
  };
}

function rowToGroup(row, members = []) {
  if (!row) return undefined;
  return {
    ...(row.external_id == null ? {} : { externalId: row.external_id }),
    displayName: row.display_name,
    members: members.map((value) => ({ value, type: 'User' })),
    id: row.id,
    version: Number(row.version),
    createdAt: row.created_at?.toISOString?.() ?? row.created_at,
    updatedAt: row.updated_at?.toISOString?.() ?? row.updated_at,
  };
}

const userColumns = `users.*, resources.external_id, resources.version,
  resources.created_at AS scim_created_at, resources.updated_at AS scim_updated_at,
  users.attributes->'scim' AS scim_attributes`;

const userFrom = `FROM users JOIN scim_user_resources AS resources
  ON resources.realm_name=users.realm_name AND resources.user_id=users.id`;

const userSelect = `SELECT ${userColumns} ${userFrom}`;

const userDocument = `(COALESCE(users.attributes->'scim', '{}'::jsonb) || jsonb_build_object(
  'id', users.id::text,
  'externalId', resources.external_id,
  'userName', users.username,
  'displayName', users.display_name,
  'name', COALESCE(users.attributes->'scim'->'name', '{}'::jsonb)
    || CASE WHEN users.given_name <> '' THEN jsonb_build_object('givenName', users.given_name) ELSE '{}'::jsonb END
    || CASE WHEN users.family_name <> '' THEN jsonb_build_object('familyName', users.family_name) ELSE '{}'::jsonb END
    || jsonb_build_object('formatted', users.display_name),
  'emails', CASE
    WHEN jsonb_typeof(users.attributes->'scim'->'emails') = 'array'
      AND jsonb_array_length(users.attributes->'scim'->'emails') > 0
      THEN users.attributes->'scim'->'emails'
    ELSE jsonb_build_array(jsonb_build_object('value', users.email, 'primary', true))
  END,
  'roles', CASE
    WHEN jsonb_typeof(users.attributes->'scim'->'roles') = 'array'
      AND jsonb_array_length(users.attributes->'scim'->'roles') > 0
      THEN users.attributes->'scim'->'roles'
    ELSE (SELECT COALESCE(jsonb_agg(jsonb_build_object('value', role)), '[]'::jsonb)
          FROM unnest(users.roles) AS role)
  END,
  'active', users.enabled
))`;

const commonSortPaths = [
  'schemas', 'id', 'externalId', 'meta.resourceType', 'meta.created',
  'meta.lastModified', 'meta.location', 'meta.version',
];

const userSortPaths = new Set([
  ...commonSortPaths,
  'userName', 'name.formatted', 'name.familyName', 'name.givenName', 'name.middleName',
  'name.honorificPrefix', 'name.honorificSuffix', 'displayName', 'nickName', 'profileUrl',
  'title', 'userType', 'preferredLanguage', 'locale', 'timezone', 'active',
  ...['emails', 'phoneNumbers', 'ims', 'photos', 'entitlements', 'roles'].flatMap((name) => (
    ['value', 'display', 'type', 'primary'].map((child) => `${name}.${child}`)
  )),
  ...['formatted', 'streetAddress', 'locality', 'region', 'postalCode', 'country', 'type', 'primary']
    .map((child) => `addresses.${child}`),
  ...['value', '$ref', 'display', 'type'].map((child) => `groups.${child}`),
  'x509Certificates.value',
]);

const groupSortPaths = new Set([
  ...commonSortPaths, 'displayName',
  ...['value', '$ref', 'display', 'type'].map((child) => `members.${child}`),
]);

class SqlParameters {
  constructor(realm) { this.values = [realm]; }

  add(value) {
    this.values.push(value);
    return `$${this.values.length}`;
  }
}

function normalizedFilter(filter, resourceType) {
  if (!filter || filter.type) return filter;
  const literal = JSON.stringify(filter.value);
  if (typeof filter.attribute !== 'string' || literal === undefined) {
    throw new TypeError('The repository filter is invalid');
  }
  return parseFilter(`${filter.attribute} eq ${literal}`, resourceType);
}

function jsonPath(segments) {
  return `$${segments.map((segment) => `.${JSON.stringify(segment)}`).join('')}`;
}

function rawValuesSql(parameters, attribute, source) {
  if (source.relative) {
    const path = parameters.add(jsonPath(attribute.segments));
    return `SELECT path.value FROM jsonb_path_query(${source.document}, ${path}::jsonpath) AS path(value)`;
  }

  let value;
  if (source.columns?.[attribute.path]) {
    value = `to_jsonb(${source.columns[attribute.path]})`;
  } else if (attribute.path === 'schemas') {
    value = `jsonb_build_array(to_jsonb(${parameters.add(source.schema)}::text))`;
  } else if (attribute.path === 'meta.resourceType') {
    value = `to_jsonb(${parameters.add(source.resourceType)}::text)`;
  } else if (attribute.path === 'meta.created') {
    value = `to_jsonb(${source.created})`;
  } else if (attribute.path === 'meta.lastModified') {
    value = `to_jsonb(${source.updated})`;
  } else if (attribute.path === 'meta.version') {
    value = `to_jsonb(('W/"' || ${source.version}::text || '"')::text)`;
  } else if (attribute.path === 'meta' || attribute.path === 'meta.location') {
    value = 'NULL::jsonb';
  } else {
    const path = parameters.add(jsonPath(attribute.segments));
    return `SELECT path.value FROM jsonb_path_query(${source.document}, ${path}::jsonpath) AS path(value)`;
  }
  return `SELECT ${value} AS value`;
}

function attributeValuesSql(parameters, attribute, source, { flattenComplex = true } = {}) {
  const raw = rawValuesSql(parameters, attribute, source);
  const expanded = `SELECT CASE WHEN jsonb_typeof(raw.value) = 'array' THEN elements.value ELSE raw.value END AS value
    FROM (${raw}) AS raw
    LEFT JOIN LATERAL jsonb_array_elements(
      CASE WHEN jsonb_typeof(raw.value) = 'array' THEN raw.value ELSE '[]'::jsonb END
    ) AS elements(value) ON true
    WHERE jsonb_typeof(raw.value) <> 'array' OR elements.value IS NOT NULL`;
  if (!flattenComplex || attribute.type !== 'complex') return expanded;
  return `SELECT CASE WHEN jsonb_typeof(expanded.value) = 'object' THEN children.value ELSE expanded.value END AS value
    FROM (${expanded}) AS expanded
    LEFT JOIN LATERAL jsonb_each(
      CASE WHEN jsonb_typeof(expanded.value) = 'object' THEN expanded.value ELSE '{}'::jsonb END
    ) AS children(key, value) ON true
    WHERE jsonb_typeof(expanded.value) <> 'object' OR children.value IS NOT NULL`;
}

function stringComparison(parameters, expression, actual) {
  const expected = parameters.add(expression.value);
  const isString = `jsonb_typeof(candidate.value) = 'string'`;
  if (expression.value === null) {
    if (expression.operator === 'ne') return `${expected}::text IS NULL`;
    return `${expected}::text IS NOT NULL AND false`;
  }
  const left = expression.attribute.caseExact ? actual : `lower(${actual})`;
  const right = expression.attribute.caseExact ? `${expected}::text` : `lower(${expected}::text)`;
  if (expression.operator === 'eq') return `${isString} AND ${left} = ${right}`;
  if (expression.operator === 'ne') return `NOT ${isString} OR ${left} <> ${right}`;
  if (expression.operator === 'co') return `${isString} AND strpos(${left}, ${right}) > 0`;
  if (expression.operator === 'sw') return `${isString} AND left(${left}, length(${right})) = ${right}`;
  if (expression.operator === 'ew') return `${isString} AND right(${left}, length(${right})) = ${right}`;
  const operator = { gt: '>', ge: '>=', lt: '<', le: '<=' }[expression.operator];
  if (!operator) throw new TypeError(`Unsupported SCIM comparison operator ${expression.operator}`);
  return `${isString} AND (${left} COLLATE "C") ${operator} (${right} COLLATE "C")`;
}

function booleanComparison(parameters, expression, actual) {
  const expectedValue = typeof expression.value === 'string'
    ? expression.value.toLowerCase() === 'true' : expression.value;
  const expected = parameters.add(expectedValue);
  const valid = `(jsonb_typeof(candidate.value) = 'boolean'
    OR (jsonb_typeof(candidate.value) = 'string' AND lower(${actual}) IN ('true', 'false')))`;
  const left = `(CASE WHEN ${valid} THEN ${actual}::boolean END)`;
  if (expression.operator === 'eq') return `${valid} AND ${left} = ${expected}::boolean`;
  if (expression.operator === 'ne') return `NOT ${valid} OR ${left} <> ${expected}::boolean`;
  throw new TypeError(`Unsupported SCIM boolean comparison operator ${expression.operator}`);
}

function dateComparison(parameters, expression, actual) {
  const expected = parameters.add(expression.value);
  const parsed = Date.parse(expression.value);
  if (Number.isNaN(parsed)) {
    if (expression.operator === 'ne') return `${expected}::text IS NOT NULL`;
    return `${expected}::text IS NULL AND false`;
  }
  const instant = parameters.add(new Date(parsed).toISOString());
  const isString = `jsonb_typeof(candidate.value) = 'string'`;
  const operator = { eq: '=', ne: '<>', gt: '>', ge: '>=', lt: '<', le: '<=' }[expression.operator];
  if (!operator) throw new TypeError(`Unsupported SCIM date comparison operator ${expression.operator}`);
  if (expression.operator === 'ne') {
    return `NOT ${isString} OR ${actual}::timestamptz ${operator} ${instant}::timestamptz`;
  }
  return `${isString} AND ${actual}::timestamptz ${operator} ${instant}::timestamptz`;
}

function comparisonSql(parameters, expression, source) {
  const values = attributeValuesSql(parameters, expression.attribute, source);
  const actual = `(candidate.value #>> '{}')`;
  let predicate;
  if (expression.attribute.type === 'boolean') {
    predicate = booleanComparison(parameters, expression, actual);
  } else if (expression.attribute.type === 'dateTime') {
    predicate = dateComparison(parameters, expression, actual);
  } else {
    predicate = stringComparison(parameters, expression, actual);
  }
  return `EXISTS (SELECT 1 FROM (${values}) AS candidate
    WHERE jsonb_typeof(candidate.value) <> 'null' AND (${predicate}))`;
}

// Every node emitted by parseFilter is compiled here. Unknown nodes fail
// closed instead of falling back to an unbounded in-memory realm scan.
function filterSql(parameters, expression, source) {
  if (!expression) return 'true';
  if (expression.type === 'logical') {
    if (!['and', 'or'].includes(expression.operator)) throw new TypeError('Unsupported SCIM logical operator');
    return `(${filterSql(parameters, expression.left, source)} ${expression.operator.toUpperCase()} ${filterSql(parameters, expression.right, source)})`;
  }
  if (expression.type === 'not') return `(NOT (${filterSql(parameters, expression.expression, source)}))`;
  if (expression.type === 'presence') {
    const values = attributeValuesSql(parameters, expression.attribute, source);
    return `EXISTS (SELECT 1 FROM (${values}) AS candidate
      WHERE jsonb_typeof(candidate.value) <> 'null'
        AND (jsonb_typeof(candidate.value) <> 'string' OR candidate.value #>> '{}' <> ''))`;
  }
  if (expression.type === 'valuePath') {
    const candidates = attributeValuesSql(parameters, expression.attribute, source, { flattenComplex: false });
    const relative = { ...source, document: 'candidate.value', relative: true };
    return `EXISTS (SELECT 1 FROM (${candidates}) AS candidate
      WHERE jsonb_typeof(candidate.value) = 'object'
        AND (${filterSql(parameters, expression.expression, relative)}))`;
  }
  if (expression.type === 'comparison') return comparisonSql(parameters, expression, source);
  throw new TypeError(`Unsupported SCIM filter node ${expression.type}`);
}

function filterReferences(expression, path) {
  if (!expression) return false;
  if (expression.attribute?.path === path || expression.attribute?.path.startsWith(`${path}.`)) return true;
  return filterReferences(expression.left, path)
    || filterReferences(expression.right, path)
    || filterReferences(expression.expression, path);
}

function sortRawValueSql(parameters, sort, source) {
  const { attribute } = sort;
  if (attribute.multiValued && attribute.segments.length > 1) {
    const parentPath = parameters.add([attribute.segments[0]]);
    const childPath = parameters.add(jsonPath(attribute.segments.slice(1)));
    return `(SELECT (
        SELECT child.value #>> '{}'
        FROM jsonb_path_query(selected.value, ${childPath}::jsonpath) AS child(value)
        WHERE jsonb_typeof(child.value) <> 'null'
        LIMIT 1
      )
      FROM (
        SELECT item.value
        FROM jsonb_array_elements(CASE
          WHEN jsonb_typeof(jsonb_extract_path(${source.document}, VARIADIC ${parentPath}::text[])) = 'array'
            THEN jsonb_extract_path(${source.document}, VARIADIC ${parentPath}::text[])
          ELSE '[]'::jsonb
        END) WITH ORDINALITY AS item(value, ordinal)
        ORDER BY (item.value->'primary' = 'true'::jsonb) DESC, item.ordinal
        LIMIT 1
      ) AS selected)`;
  }
  const values = attributeValuesSql(parameters, attribute, source);
  return `(SELECT candidate.value #>> '{}' FROM (${values}) AS candidate
    WHERE jsonb_typeof(candidate.value) <> 'null' LIMIT 1)`;
}

function sortSql(parameters, sort, source) {
  if (!sort) {
    return {
      selection: `NULL::text AS scim_sort_key, false AS scim_sort_missing`,
      order: 'id ASC',
    };
  }
  const allowlist = source.resourceType === 'User' ? userSortPaths : groupSortPaths;
  if (!allowlist.has(sort.attribute.path) || !['ascending', 'descending'].includes(sort.order)) {
    throw new TypeError('Unsupported SCIM sort');
  }
  const raw = sortRawValueSql(parameters, sort, source);
  let key = raw;
  let missing = `${raw} IS NULL`;
  if (sort.attribute.type === 'boolean') {
    key = `${raw}::boolean`;
  } else if (sort.attribute.type === 'dateTime') {
    key = `${raw}::timestamptz`;
  } else {
    missing = `(${raw} IS NULL OR ${raw} = '')`;
    key = sort.attribute.caseExact ? `(${raw} COLLATE "C")` : `(lower(${raw}) COLLATE "C")`;
  }
  const direction = sort.order === 'ascending' ? 'ASC' : 'DESC';
  return {
    selection: `${key} AS scim_sort_key, ${missing} AS scim_sort_missing`,
    order: `scim_sort_missing ${direction}, scim_sort_key ${direction}, id ASC`,
  };
}

function userSource() {
  return {
    document: 'listed.scim_document', schema: SCIM_URNS.user, resourceType: 'User',
    created: 'listed.scim_created_at', updated: 'listed.scim_updated_at', version: 'listed.version',
    columns: {
      id: 'listed.id::text', externalId: 'listed.external_id', userName: 'listed.username',
      displayName: 'listed.display_name', 'name.formatted': 'listed.display_name', active: 'listed.enabled',
    },
  };
}

function userListSource() {
  return `SELECT ${userColumns}, ${userDocument} AS scim_document
    ${userFrom} WHERE users.realm_name=$1`;
}

function groupDocument(members) {
  return `jsonb_build_object(
    'id', groups.id::text,
    'externalId', groups.external_id,
    'displayName', groups.display_name,
    'members', ${members}
  )`;
}

function groupListSource(includeMembers) {
  const join = includeMembers ? `LEFT JOIN (
      SELECT memberships.realm_name, memberships.group_id,
        jsonb_agg(jsonb_build_object('value', memberships.user_id::text, 'type', 'User')
          ORDER BY memberships.user_id) AS scim_members,
        array_agg(memberships.user_id::text ORDER BY memberships.user_id) AS scim_member_ids
      FROM scim_group_members AS memberships
      WHERE memberships.realm_name=$1
      GROUP BY memberships.realm_name, memberships.group_id
    ) AS member_values
      ON member_values.realm_name=groups.realm_name AND member_values.group_id=groups.id` : '';
  const members = includeMembers ? `COALESCE(member_values.scim_members, '[]'::jsonb)` : `'[]'::jsonb`;
  const memberIds = includeMembers ? `COALESCE(member_values.scim_member_ids, '{}'::text[])` : 'NULL::text[]';
  return `SELECT groups.*, ${memberIds} AS scim_member_ids,
      ${groupDocument(members)} AS scim_document
    FROM scim_groups AS groups ${join}
    WHERE groups.realm_name=$1`;
}

function groupSource() {
  return {
    document: 'listed.scim_document', schema: SCIM_URNS.group, resourceType: 'Group',
    created: 'listed.created_at', updated: 'listed.updated_at', version: 'listed.version',
    columns: {
      id: 'listed.id::text', externalId: 'listed.external_id', displayName: 'listed.display_name',
    },
  };
}

function translateConstraint(error, resourceType) {
  if (error?.code === '23505') {
    return repositoryError('UNIQUENESS', `${resourceType} userName, displayName, email, or externalId already exists in this realm.`);
  }
  if (error?.code === '23503') return repositoryError('INVALID_VALUE', 'A referenced User does not exist in this realm.');
  if (error?.code === '22P02') return repositoryError('INVALID_VALUE', 'A SCIM resource identifier is invalid.');
  return error;
}

async function withTransaction(pool, operation) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await operation(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function revokeAccounts(client, realm, accountIds) {
  if (!accountIds.length) return;
  await client.query(
    `WITH account_grants AS MATERIALIZED (
       SELECT id FROM oidc_records
       WHERE realm_name=$1 AND model='Grant'
         AND payload ? 'accountId' AND payload->>'accountId'=ANY($2::text[])
     ), doomed AS (
       SELECT realm_name,model,id FROM oidc_records
       WHERE realm_name=$1
         AND payload ? 'accountId' AND payload->>'accountId'=ANY($2::text[])
       UNION
       SELECT records.realm_name,records.model,records.id
       FROM oidc_records AS records
       JOIN account_grants AS grants ON grants.id=records.grant_id
       WHERE records.realm_name=$1 AND records.grant_id IS NOT NULL
     )
     DELETE FROM oidc_records AS records USING doomed
     WHERE records.realm_name=doomed.realm_name
       AND records.model=doomed.model AND records.id=doomed.id`,
    [realm, accountIds],
  );
}

export class PostgresScimRepository {
  constructor(pool, { hashPassword, disabledPasswordHash }) {
    if (!pool?.query || !pool?.connect) throw new TypeError('PostgresScimRepository requires a PostgreSQL pool');
    if (typeof hashPassword !== 'function' || typeof disabledPasswordHash !== 'string') {
      throw new TypeError('PostgresScimRepository requires password hashing and a disabled password hash');
    }
    this.pool = pool;
    this.hashPassword = hashPassword;
    this.disabledPasswordHash = disabledPasswordHash;
  }

  async listUsers(realm, options) {
    const filter = normalizedFilter(options.filter, 'User');
    const countParameters = new SqlParameters(realm);
    const countWhere = filterSql(countParameters, filter, userSource());
    const count = await this.pool.query(
      `SELECT count(*)::bigint AS total
       FROM (${userListSource()}) AS listed
       WHERE ${countWhere}`,
      countParameters.values,
    );
    const totalResults = Number(count.rows[0].total);
    const offset = options.startIndex - 1;
    if (options.count === 0 || offset >= totalResults) return { totalResults, resources: [] };

    const pageParameters = new SqlParameters(realm);
    const source = userSource();
    const pageWhere = filterSql(pageParameters, filter, source);
    const sorting = sortSql(pageParameters, options.sort, source);
    const limit = pageParameters.add(options.count);
    const pageOffset = pageParameters.add(offset);
    const page = await this.pool.query(
      `SELECT listed.*, ${sorting.selection}
       FROM (${userListSource()}) AS listed
       WHERE ${pageWhere}
       ORDER BY ${sorting.order}
       LIMIT ${limit}::bigint OFFSET ${pageOffset}::bigint`,
      pageParameters.values,
    );
    return { totalResults, resources: page.rows.map(rowToUser) };
  }

  async getUser(realm, id) {
    if (!isUuid(id)) return undefined;
    const result = await this.pool.query(`${userSelect} WHERE users.realm_name=$1 AND users.id=$2`, [realm, id]);
    return rowToUser(result.rows[0]);
  }

  async createUser(realm, attributes) {
    const id = randomUUID();
    const core = coreUser(attributes, id);
    let passwordHash = this.disabledPasswordHash;
    if (attributes.password !== undefined) {
      if (typeof attributes.password !== 'string' || attributes.password.length < 12 || attributes.password.length > 1024) {
        throw repositoryError('INVALID_VALUE', 'password does not meet the AuthMe password policy.');
      }
      passwordHash = await this.hashPassword(attributes.password);
    }
    try {
      return await withTransaction(this.pool, async (client) => {
        await client.query(
          `INSERT INTO users
           (realm_name,id,username,email,email_verified,display_name,given_name,family_name,enabled,
            password_hash,roles,groups,client_roles,attributes)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'{}','{}',$12)`,
          [realm, id, core.username, core.email, core.emailVerified, core.displayName, core.givenName,
            core.familyName, core.enabled, passwordHash, core.roles, { scim: core.extra }],
        );
        await client.query(
          'UPDATE scim_user_resources SET external_id=$3 WHERE realm_name=$1 AND user_id=$2',
          [realm, id, attributes.externalId ?? null],
        );
        const result = await client.query(`${userSelect} WHERE users.realm_name=$1 AND users.id=$2`, [realm, id]);
        return rowToUser(result.rows[0]);
      });
    } catch (error) { throw translateConstraint(error, 'User'); }
  }

  async replaceUser(realm, id, attributes, expectedVersion) {
    if (!isUuid(id)) throw repositoryError('NOT_FOUND', 'The requested SCIM User does not exist.');
    const core = coreUser(attributes, id);
    let passwordHash;
    if (attributes.password !== undefined) {
      if (typeof attributes.password !== 'string' || attributes.password.length < 12 || attributes.password.length > 1024) {
        throw repositoryError('INVALID_VALUE', 'password does not meet the AuthMe password policy.');
      }
      passwordHash = await this.hashPassword(attributes.password);
    }
    try {
      return await withTransaction(this.pool, async (client) => {
        const locked = await client.query(
          `SELECT users.password_hash, resources.version FROM users JOIN scim_user_resources AS resources
           ON resources.realm_name=users.realm_name AND resources.user_id=users.id
           WHERE users.realm_name=$1 AND users.id=$2 FOR UPDATE OF users, resources`,
          [realm, id],
        );
        if (!locked.rows.length) throw repositoryError('NOT_FOUND', 'The requested SCIM User does not exist.');
        if (Number(locked.rows[0].version) !== expectedVersion) {
          throw repositoryError('VERSION_MISMATCH', 'The SCIM User changed since it was read.');
        }
        await client.query(
          `UPDATE users SET username=$3,email=$4,email_verified=$5,display_name=$6,given_name=$7,
             family_name=$8,enabled=$9,password_hash=$10,roles=$11,
             attributes=jsonb_set(attributes,'{scim}',$12::jsonb,true),
             security_version=security_version+1,failed_attempts=0,locked_until=NULL
           WHERE realm_name=$1 AND id=$2`,
          [realm, id, core.username, core.email, core.emailVerified, core.displayName, core.givenName,
            core.familyName, core.enabled, passwordHash ?? locked.rows[0].password_hash, core.roles, core.extra],
        );
        await client.query(
          'UPDATE scim_user_resources SET external_id=$3 WHERE realm_name=$1 AND user_id=$2',
          [realm, id, attributes.externalId ?? null],
        );
        await revokeAccounts(client, realm, [id]);
        const result = await client.query(`${userSelect} WHERE users.realm_name=$1 AND users.id=$2`, [realm, id]);
        return rowToUser(result.rows[0]);
      });
    } catch (error) { throw translateConstraint(error, 'User'); }
  }

  async deleteUser(realm, id, expectedVersion) {
    if (!isUuid(id)) throw repositoryError('NOT_FOUND', 'The requested SCIM User does not exist.');
    return withTransaction(this.pool, async (client) => {
      const current = await client.query(`${userSelect} WHERE users.realm_name=$1 AND users.id=$2 FOR UPDATE OF users, resources`, [realm, id]);
      if (!current.rows.length) throw repositoryError('NOT_FOUND', 'The requested SCIM User does not exist.');
      if (Number(current.rows[0].version) !== expectedVersion) throw repositoryError('VERSION_MISMATCH', 'The SCIM User changed since it was read.');
      const memberships = await client.query(
        'SELECT group_id::text FROM scim_group_members WHERE realm_name=$1 AND user_id=$2', [realm, id],
      );
      const groupIds = memberships.rows.map(({ group_id: groupId }) => groupId);
      if (groupIds.length) {
        await client.query(
          `UPDATE scim_groups SET version=version+1
           WHERE realm_name=$1 AND id=ANY($2::uuid[])`, [realm, groupIds],
        );
      }
      await revokeAccounts(client, realm, [id]);
      await client.query('DELETE FROM users WHERE realm_name=$1 AND id=$2', [realm, id]);
      return rowToUser(current.rows[0]);
    });
  }

  async #group(realm, id, client = this.pool) {
    if (!isUuid(id)) return undefined;
    const result = await client.query(
      `SELECT groups.*, COALESCE(member_values.member_ids, '{}'::text[]) AS scim_member_ids
       FROM scim_groups AS groups
       LEFT JOIN (
         SELECT group_id, array_agg(user_id::text ORDER BY user_id) AS member_ids
         FROM scim_group_members
         WHERE realm_name=$1 AND group_id=$2
         GROUP BY group_id
       ) AS member_values ON member_values.group_id=groups.id
       WHERE groups.realm_name=$1 AND groups.id=$2`,
      [realm, id],
    );
    return rowToGroup(result.rows[0], result.rows[0]?.scim_member_ids);
  }

  async listGroups(realm, options) {
    const filter = normalizedFilter(options.filter, 'Group');
    const countNeedsMembers = filterReferences(filter, 'members');
    const countParameters = new SqlParameters(realm);
    const countWhere = filterSql(countParameters, filter, groupSource());
    const count = await this.pool.query(
      `SELECT count(*)::bigint AS total
       FROM (${groupListSource(countNeedsMembers)}) AS listed
       WHERE ${countWhere}`,
      countParameters.values,
    );
    const totalResults = Number(count.rows[0].total);
    const offset = options.startIndex - 1;
    if (options.count === 0 || offset >= totalResults) return { totalResults, resources: [] };

    const pageNeedsMembers = countNeedsMembers || options.sort?.attribute.path.startsWith('members.') === true;
    const pageParameters = new SqlParameters(realm);
    const source = groupSource();
    const pageWhere = filterSql(pageParameters, filter, source);
    const sorting = sortSql(pageParameters, options.sort, source);
    const limit = pageParameters.add(options.count);
    const pageOffset = pageParameters.add(offset);
    const pageSource = groupListSource(pageNeedsMembers);
    let pageSql;
    if (pageNeedsMembers) {
      pageSql = `WITH page AS MATERIALIZED (
          SELECT listed.*, ${sorting.selection}
          FROM (${pageSource}) AS listed
          WHERE ${pageWhere}
          ORDER BY ${sorting.order}
          LIMIT ${limit}::bigint OFFSET ${pageOffset}::bigint
        )
        SELECT page.* FROM page ORDER BY ${sorting.order}`;
    } else {
      pageSql = `WITH page AS MATERIALIZED (
          SELECT listed.*, ${sorting.selection}
          FROM (${pageSource}) AS listed
          WHERE ${pageWhere}
          ORDER BY ${sorting.order}
          LIMIT ${limit}::bigint OFFSET ${pageOffset}::bigint
        ), page_members AS (
          SELECT memberships.group_id,
            array_agg(memberships.user_id::text ORDER BY memberships.user_id) AS member_ids
          FROM scim_group_members AS memberships
          JOIN page ON page.realm_name=memberships.realm_name AND page.id=memberships.group_id
          GROUP BY memberships.group_id
        )
        SELECT page.*, COALESCE(page_members.member_ids, '{}'::text[]) AS scim_member_ids
        FROM page LEFT JOIN page_members ON page_members.group_id=page.id
        ORDER BY ${sorting.order}`;
    }
    const page = await this.pool.query(pageSql, pageParameters.values);
    return {
      totalResults,
      resources: page.rows.map((row) => rowToGroup(row, row.scim_member_ids)),
    };
  }

  async getGroup(realm, id) { return this.#group(realm, id); }

  async #replaceMembers(client, realm, groupId, members) {
    const ids = members.map(({ value }) => value);
    if (ids.some((id) => !isUuid(id)) || new Set(ids).size !== ids.length) {
      throw repositoryError('INVALID_VALUE', 'Group members must be distinct User identifiers.');
    }
    if (ids.length) {
      const found = await client.query('SELECT id::text FROM users WHERE realm_name=$1 AND id=ANY($2::uuid[])', [realm, ids]);
      if (found.rowCount !== ids.length) throw repositoryError('INVALID_VALUE', 'A Group member is not a User in this realm.');
    }
    const previous = await client.query('SELECT user_id::text FROM scim_group_members WHERE realm_name=$1 AND group_id=$2', [realm, groupId]);
    await client.query('DELETE FROM scim_group_members WHERE realm_name=$1 AND group_id=$2', [realm, groupId]);
    for (const userId of ids) {
      await client.query('INSERT INTO scim_group_members (realm_name,group_id,user_id) VALUES ($1,$2,$3)', [realm, groupId, userId]);
    }
    return [...new Set([...previous.rows.map(({ user_id: userId }) => userId), ...ids])];
  }

  async #syncUserGroups(client, realm, userIds) {
    if (!userIds.length) return;
    const changed = await client.query(
      `WITH desired AS (
         SELECT users.id,COALESCE((
           SELECT array_agg('/' || replace(groups.display_name, '/', '-') ORDER BY lower(groups.display_name))
           FROM scim_group_members AS memberships JOIN scim_groups AS groups
             ON groups.realm_name=memberships.realm_name AND groups.id=memberships.group_id
           WHERE memberships.realm_name=users.realm_name AND memberships.user_id=users.id
         ), '{}'::text[]) AS groups
         FROM users WHERE realm_name=$1 AND id=ANY($2::uuid[])
       )
       UPDATE users SET groups=desired.groups,security_version=security_version+1
       FROM desired
       WHERE users.realm_name=$1 AND users.id=desired.id
         AND users.groups IS DISTINCT FROM desired.groups
       RETURNING users.id::text`,
      [realm, userIds],
    );
    await revokeAccounts(client, realm, changed.rows.map(({ id }) => id));
  }

  async createGroup(realm, attributes) {
    const id = randomUUID();
    try {
      return await withTransaction(this.pool, async (client) => {
        await client.query(
          `INSERT INTO scim_groups (realm_name,id,external_id,display_name)
           VALUES ($1,$2,$3,$4)`, [realm, id, attributes.externalId ?? null, attributes.displayName],
        );
        const affected = await this.#replaceMembers(client, realm, id, attributes.members ?? []);
        await this.#syncUserGroups(client, realm, affected);
        return this.#group(realm, id, client);
      });
    } catch (error) { throw translateConstraint(error, 'Group'); }
  }

  async replaceGroup(realm, id, attributes, expectedVersion) {
    if (!isUuid(id)) throw repositoryError('NOT_FOUND', 'The requested SCIM Group does not exist.');
    try {
      return await withTransaction(this.pool, async (client) => {
        const updated = await client.query(
          `UPDATE scim_groups SET external_id=$3,display_name=$4,version=version+1
           WHERE realm_name=$1 AND id=$2 AND version=$5 RETURNING id`,
          [realm, id, attributes.externalId ?? null, attributes.displayName, expectedVersion],
        );
        if (!updated.rows.length) {
          const exists = await client.query('SELECT 1 FROM scim_groups WHERE realm_name=$1 AND id=$2', [realm, id]);
          throw repositoryError(exists.rows.length ? 'VERSION_MISMATCH' : 'NOT_FOUND', `The SCIM Group ${exists.rows.length ? 'changed since it was read' : 'does not exist'}.`);
        }
        const affected = await this.#replaceMembers(client, realm, id, attributes.members ?? []);
        await this.#syncUserGroups(client, realm, affected);
        return this.#group(realm, id, client);
      });
    } catch (error) { throw translateConstraint(error, 'Group'); }
  }

  async deleteGroup(realm, id, expectedVersion) {
    if (!isUuid(id)) throw repositoryError('NOT_FOUND', 'The requested SCIM Group does not exist.');
    return withTransaction(this.pool, async (client) => {
      const locked = await client.query(
        'SELECT * FROM scim_groups WHERE realm_name=$1 AND id=$2 FOR UPDATE', [realm, id],
      );
      if (!locked.rows.length) throw repositoryError('NOT_FOUND', 'The requested SCIM Group does not exist.');
      const members = await client.query(
        'SELECT user_id::text FROM scim_group_members WHERE realm_name=$1 AND group_id=$2 ORDER BY user_id', [realm, id],
      );
      const current = rowToGroup(locked.rows[0], members.rows.map(({ user_id: userId }) => userId));
      if (current.version !== expectedVersion) throw repositoryError('VERSION_MISMATCH', 'The SCIM Group changed since it was read.');
      const affected = current.members.map(({ value }) => value);
      await client.query('DELETE FROM scim_groups WHERE realm_name=$1 AND id=$2', [realm, id]);
      await this.#syncUserGroups(client, realm, affected);
      return current;
    });
  }

  async listUserGroups(realm, userId) {
    if (!isUuid(userId)) return [];
    const result = await this.pool.query(
      `SELECT groups.id::text AS value, groups.display_name AS display
       FROM scim_group_members AS members JOIN scim_groups AS groups
         ON groups.realm_name=members.realm_name AND groups.id=members.group_id
       WHERE members.realm_name=$1 AND members.user_id=$2 ORDER BY lower(groups.display_name)`,
      [realm, userId],
    );
    return result.rows.map((row) => ({ ...row, type: 'direct' }));
  }
}
