import { Router, json } from 'express';
import { isDeepStrictEqual } from 'node:util';
import { GROUP_SCHEMA, SCIM_URNS, USER_SCHEMA, resourceTypes, serviceProviderConfig } from './constants.js';
import { normalizeGroup, normalizeUser } from './attributes.js';
import { ScimError, errorBody, repositoryError } from './errors.js';
import { pagination, parseFilter, parseSort } from './filter.js';
import { applyGroupPatch, applyUserPatch } from './patch.js';
import { processBulk } from './bulk.js';

const realmPattern = /^[a-z][a-z0-9-]{0,62}$/;
const internalFields = new Set(['id', 'version', 'createdAt', 'updatedAt']);

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function attributes(record) {
  return Object.fromEntries(Object.entries(record).filter(([key]) => !internalFields.has(key)));
}

function replacementBody(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return body;
  const copy = { ...body };
  delete copy.id;
  delete copy.meta;
  return copy;
}

function etag(record) {
  return `W/"${record.version}"`;
}

function baseFor(option, req, realm) {
  if (typeof option === 'function') return String(option({ req, realm })).replace(/\/$/, '');
  if (typeof option === 'string' && option) return `${option.replace(/\/$/, '')}/${encodeURIComponent(realm)}`;
  return `${req.baseUrl}/${encodeURIComponent(realm)}`.replace(/\/$/, '');
}

function meta(record, resourceType, location) {
  return {
    resourceType,
    created: record.createdAt,
    lastModified: record.updatedAt,
    version: etag(record),
    location,
  };
}

async function userResource(repository, realm, record, baseUrl) {
  const safe = attributes(record);
  delete safe.password;
  const memberships = typeof repository.listUserGroups === 'function'
    ? await repository.listUserGroups(realm, record.id)
    : [];
  const groups = memberships.map((group) => ({
    value: group.value,
    display: group.display,
    type: group.type ?? 'direct',
    $ref: `${baseUrl}/Groups/${encodeURIComponent(group.value)}`,
  }));
  return {
    schemas: [SCIM_URNS.user],
    id: record.id,
    ...safe,
    ...(groups.length ? { groups } : {}),
    meta: meta(record, 'User', `${baseUrl}/Users/${encodeURIComponent(record.id)}`),
  };
}

async function groupResource(repository, realm, record, baseUrl) {
  const safe = attributes(record);
  const members = [];
  for (const member of safe.members ?? []) {
    const user = await repository.getUser(realm, member.value);
    members.push({
      value: member.value,
      type: 'User',
      ...(user ? { display: user.displayName ?? user.userName } : {}),
      $ref: `${baseUrl}/Users/${encodeURIComponent(member.value)}`,
    });
  }
  return {
    schemas: [SCIM_URNS.group],
    id: record.id,
    ...safe,
    members,
    meta: meta(record, 'Group', `${baseUrl}/Groups/${encodeURIComponent(record.id)}`),
  };
}

function listResponse(resources, totalResults, startIndex) {
  return {
    schemas: [SCIM_URNS.listResponse],
    totalResults,
    startIndex,
    itemsPerPage: resources.length,
    Resources: resources,
  };
}

function tokens(header) {
  return String(header ?? '').split(',').map((value) => value.trim()).filter(Boolean);
}

function conditionalGet(req, res, record) {
  const value = etag(record);
  res.set('ETag', value);
  const candidates = tokens(req.get('if-none-match'));
  if (candidates.includes('*') || candidates.includes(value)) {
    res.status(304).end();
    return true;
  }
  return false;
}

function requireCurrent(record) {
  if (!record) throw new ScimError(404, 'The requested SCIM resource does not exist.');
  return record;
}

function checkIfMatch(req, record) {
  const candidates = tokens(req.get('if-match'));
  if (!candidates.length || candidates.includes('*') || candidates.includes(etag(record))) return;
  throw new ScimError(412, 'The If-Match version does not match the current SCIM resource.');
}

function checkVersion(version, record) {
  if (version == null || version === '*' || version === etag(record)) return;
  throw new ScimError(412, 'The Bulk operation version does not match the current SCIM resource.');
}

function bulkTarget(path, method) {
  const match = method === 'POST'
    ? /^\/(Users|Groups)\/?$/u.exec(path)
    : /^\/(Users|Groups)\/([^/?#]+)$/u.exec(path);
  if (!match) throw new ScimError(400, `Bulk path ${path} is not valid for ${method}.`, 'invalidPath');
  let id;
  if (match[2]) {
    try { id = decodeURIComponent(match[2]); }
    catch { throw new ScimError(400, `Bulk path ${path} is not valid.`, 'invalidPath'); }
    if (!id || id.includes('/')) throw new ScimError(400, `Bulk path ${path} is not valid.`, 'invalidPath');
  }
  return { resourceType: match[1] === 'Users' ? 'User' : 'Group', collection: match[1], id };
}

function sendResource(res, status, resource) {
  res.set('ETag', resource.meta.version);
  res.set('Location', resource.meta.location);
  res.status(status).json(resource);
}

function requireRepository(repository) {
  const methods = [
    'listUsers', 'getUser', 'createUser', 'replaceUser', 'deleteUser',
    'listGroups', 'getGroup', 'createGroup', 'replaceGroup', 'deleteGroup',
    'listUserGroups',
  ];
  if (!repository || methods.some((method) => typeof repository[method] !== 'function')) {
    throw new TypeError(`repository must implement: ${methods.join(', ')}`);
  }
}

/**
 * Creates a realm-scoped SCIM v2 router.
 *
 * Mount at `/scim/v2/realms`; endpoints then use `/:realm/Users`, etc.
 * `authenticate` receives `{ req, realm, token }` and must return an actor
 * object/string or a falsey value. `baseUrl`, when a string, is the collection
 * root (for example `https://id.example/scim/v2/realms`); a function may return
 * the complete realm SCIM base URL. `audit` is awaited for every successful
 * mutation and receives only bounded request metadata (never headers/token).
 * It should be backed by the same transaction/outbox as durable identity
 * writes when atomic audit delivery is required.
 */
export function createScimRouter({
  repository,
  authenticate,
  realmExists = async () => true,
  audit = async () => {},
  baseUrl,
  maxPageSize = 200,
  defaultPageSize = 100,
  bodyLimit = '256kb',
  maxOperations = 1000,
  maxPayloadSize = 1048576,
} = {}) {
  requireRepository(repository);
  if (typeof authenticate !== 'function') throw new TypeError('authenticate must be a function');
  if (typeof realmExists !== 'function' || typeof audit !== 'function') throw new TypeError('realmExists and audit must be functions');
  if (!Number.isSafeInteger(maxPageSize) || maxPageSize < 1) throw new TypeError('maxPageSize must be a positive integer');
  if (!Number.isSafeInteger(defaultPageSize) || defaultPageSize < 0 || defaultPageSize > maxPageSize) {
    throw new TypeError('defaultPageSize must be between zero and maxPageSize');
  }
  if (!Number.isSafeInteger(maxOperations) || maxOperations < 1) throw new TypeError('maxOperations must be a positive integer');
  if (!Number.isSafeInteger(maxPayloadSize) || maxPayloadSize < 1) throw new TypeError('maxPayloadSize must be a positive integer');

  const router = Router();
  router.use('/:realm', asyncRoute(async (req, res, next) => {
    const realm = req.params.realm;
    const match = /^Bearer ([^\s]+)$/i.exec(req.get('authorization') ?? '');
    if (!realmPattern.test(realm)) throw new ScimError(404, 'The requested SCIM realm does not exist.');
    if (!match) {
      res.set('WWW-Authenticate', 'Bearer realm="authme-scim"');
      throw new ScimError(401, 'A bearer token is required.');
    }
    const actor = await authenticate({ req, realm, token: match[1] });
    if (!actor) {
      res.set('WWW-Authenticate', 'Bearer realm="authme-scim", error="invalid_token"');
      throw new ScimError(401, 'The bearer token is invalid.');
    }
    if (!await realmExists(realm)) throw new ScimError(404, 'The requested SCIM realm does not exist.');
    res.locals.scim = { realm, actor, baseUrl: baseFor(baseUrl, req, realm) };
    res.set('Cache-Control', 'no-store');
    res.type('application/scim+json');
    next();
  }));
  const jsonTypes = ['application/scim+json', 'application/json'];
  router.use('/:realm/Bulk', json({ type: jsonTypes, strict: true, limit: maxPayloadSize }));
  router.use(json({ type: jsonTypes, strict: true, limit: bodyLimit }));

  function context(res) { return res.locals.scim; }
  async function writeAudit(req, res, type, resourceType, resourceId, changes = []) {
    const { realm, actor } = context(res);
    await audit({
      realm, actor, type, resourceType, resourceId, changes,
      request: { method: req.method, ip: req.ip, userAgent: req.get('user-agent') ?? null },
    });
  }

  async function executeBulkOperation(req, res, operation) {
    const { realm, baseUrl: root } = context(res);
    const target = bulkTarget(operation.path, operation.method);
    const location = (id) => `${root}/${target.collection}/${encodeURIComponent(id)}`;

    if (operation.method === 'POST') {
      let created;
      if (target.resourceType === 'User') {
        try { created = await repository.createUser(realm, normalizeUser(operation.data)); }
        catch (error) { throw repositoryError(error); }
        await writeAudit(req, res, 'scim.user.created', 'User', created.id, ['create']);
      } else {
        try { created = await repository.createGroup(realm, normalizeGroup(operation.data)); }
        catch (error) { throw repositoryError(error); }
        await writeAudit(req, res, 'scim.group.created', 'Group', created.id, ['create']);
      }
      return { status: 201, id: created.id, location: location(created.id), version: etag(created) };
    }

    const get = target.resourceType === 'User' ? repository.getUser.bind(repository) : repository.getGroup.bind(repository);
    const current = requireCurrent(await get(realm, target.id));
    checkVersion(operation.version, current);

    if (operation.method === 'DELETE') {
      try {
        if (target.resourceType === 'User') await repository.deleteUser(realm, current.id, current.version);
        else await repository.deleteGroup(realm, current.id, current.version);
      } catch (error) { throw repositoryError(error); }
      const prefix = target.resourceType === 'User' ? 'user' : 'group';
      await writeAudit(req, res, `scim.${prefix}.deleted`, target.resourceType, current.id, ['delete']);
      return { status: 204, id: current.id, location: location(current.id) };
    }

    if (operation.data?.id != null && operation.data.id !== current.id) {
      throw new ScimError(400, 'id is immutable.', 'mutability');
    }
    if (operation.method === 'PUT') {
      let updated;
      try {
        if (target.resourceType === 'User') {
          updated = await repository.replaceUser(
            realm, current.id,
            normalizeUser(replacementBody(operation.data), { existingPassword: current.password }),
            current.version,
          );
        } else {
          updated = await repository.replaceGroup(realm, current.id, normalizeGroup(replacementBody(operation.data)), current.version);
        }
      } catch (error) { throw repositoryError(error); }
      const prefix = target.resourceType === 'User' ? 'user' : 'group';
      await writeAudit(req, res, `scim.${prefix}.replaced`, target.resourceType, current.id, ['replace']);
      return { status: 200, id: updated.id, location: location(updated.id), version: etag(updated) };
    }

    let next;
    if (target.resourceType === 'User') {
      next = normalizeUser(applyUserPatch(attributes(current), operation.data), { existingPassword: current.password });
    } else next = normalizeGroup(applyGroupPatch(attributes(current), operation.data));
    if (isDeepStrictEqual(next, attributes(current))) {
      return { status: 200, id: current.id, location: location(current.id), version: etag(current) };
    }
    let updated;
    try {
      if (target.resourceType === 'User') updated = await repository.replaceUser(realm, current.id, next, current.version);
      else updated = await repository.replaceGroup(realm, current.id, next, current.version);
    } catch (error) { throw repositoryError(error); }
    const changes = operation.data.Operations.map(({ path, op }) => `${String(op).toLowerCase()}:${path ?? '*'}`);
    const prefix = target.resourceType === 'User' ? 'user' : 'group';
    await writeAudit(req, res, `scim.${prefix}.patched`, target.resourceType, current.id, changes);
    return { status: 200, id: updated.id, location: location(updated.id), version: etag(updated) };
  }

  router.get('/:realm/ServiceProviderConfig', (req, res) => {
    const { baseUrl: root } = context(res);
    res.json(serviceProviderConfig(root, { maxResults: maxPageSize, maxOperations, maxPayloadSize }));
  });

  router.post('/:realm/Bulk', asyncRoute(async (req, res) => {
    const { baseUrl: root } = context(res);
    const response = await processBulk(req.body, {
      maxOperations,
      execute: (operation) => executeBulkOperation(req, res, operation),
      locationFor(path) {
        const target = bulkTarget(path, 'PUT');
        return `${root}/${target.collection}/${encodeURIComponent(target.id)}`;
      },
      onUnexpectedError(error) { req.log?.error?.({ err: error }, 'SCIM Bulk operation failed'); },
    });
    res.status(200).json(response);
  }));

  router.get('/:realm/Schemas', (req, res) => {
    const { baseUrl: root } = context(res);
    const resources = [USER_SCHEMA, GROUP_SCHEMA].map((schema) => ({
      ...schema, meta: { resourceType: 'Schema', location: `${root}/Schemas/${encodeURIComponent(schema.id)}` },
    }));
    res.json(listResponse(resources, resources.length, 1));
  });

  router.get('/:realm/Schemas/:id', (req, res) => {
    const { baseUrl: root } = context(res);
    const schema = [USER_SCHEMA, GROUP_SCHEMA].find(({ id }) => id === req.params.id);
    if (!schema) throw new ScimError(404, 'The requested SCIM schema does not exist.');
    res.json({ ...schema, meta: { resourceType: 'Schema', location: `${root}/Schemas/${encodeURIComponent(schema.id)}` } });
  });

  router.get('/:realm/ResourceTypes', (req, res) => {
    const resources = resourceTypes(context(res).baseUrl);
    res.json(listResponse(resources, resources.length, 1));
  });

  router.get('/:realm/ResourceTypes/:id', (req, res) => {
    const resource = resourceTypes(context(res).baseUrl).find(({ id }) => id.toLowerCase() === req.params.id.toLowerCase());
    if (!resource) throw new ScimError(404, 'The requested SCIM resource type does not exist.');
    res.json(resource);
  });

  router.get('/:realm/Users', asyncRoute(async (req, res) => {
    const { realm, baseUrl: root } = context(res);
    const page = pagination(req.query, maxPageSize, defaultPageSize);
    const result = await repository.listUsers(realm, {
      ...page, filter: parseFilter(req.query.filter, 'User'), sort: parseSort(req.query, 'User'),
    });
    const resources = await Promise.all(result.resources.map((item) => userResource(repository, realm, item, root)));
    res.json(listResponse(resources, result.totalResults, page.startIndex));
  }));

  router.post('/:realm/Users', asyncRoute(async (req, res) => {
    const { realm, baseUrl: root } = context(res);
    let created;
    try { created = await repository.createUser(realm, normalizeUser(req.body)); } catch (error) { throw repositoryError(error); }
    const resource = await userResource(repository, realm, created, root);
    await writeAudit(req, res, 'scim.user.created', 'User', created.id, ['create']);
    sendResource(res, 201, resource);
  }));

  router.get('/:realm/Users/:id', asyncRoute(async (req, res) => {
    const { realm, baseUrl: root } = context(res);
    const record = requireCurrent(await repository.getUser(realm, req.params.id));
    if (conditionalGet(req, res, record)) return;
    res.json(await userResource(repository, realm, record, root));
  }));

  router.put('/:realm/Users/:id', asyncRoute(async (req, res) => {
    const { realm, baseUrl: root } = context(res);
    const current = requireCurrent(await repository.getUser(realm, req.params.id));
    checkIfMatch(req, current);
    if (req.body?.id != null && req.body.id !== current.id) throw new ScimError(400, 'id is immutable.', 'mutability');
    let updated;
    try {
      updated = await repository.replaceUser(realm, current.id, normalizeUser(replacementBody(req.body), { existingPassword: current.password }), current.version);
    } catch (error) { throw repositoryError(error); }
    await writeAudit(req, res, 'scim.user.replaced', 'User', current.id, ['replace']);
    sendResource(res, 200, await userResource(repository, realm, updated, root));
  }));

  router.patch('/:realm/Users/:id', asyncRoute(async (req, res) => {
    const { realm, baseUrl: root } = context(res);
    const current = requireCurrent(await repository.getUser(realm, req.params.id));
    checkIfMatch(req, current);
    const next = normalizeUser(applyUserPatch(attributes(current), req.body), { existingPassword: current.password });
    if (isDeepStrictEqual(next, attributes(current))) {
      sendResource(res, 200, await userResource(repository, realm, current, root));
      return;
    }
    let updated;
    try { updated = await repository.replaceUser(realm, current.id, next, current.version); }
    catch (error) { throw repositoryError(error); }
    const changes = req.body.Operations.map(({ path, op }) => `${String(op).toLowerCase()}:${path ?? '*'}`);
    await writeAudit(req, res, 'scim.user.patched', 'User', current.id, changes);
    sendResource(res, 200, await userResource(repository, realm, updated, root));
  }));

  router.delete('/:realm/Users/:id', asyncRoute(async (req, res) => {
    const { realm } = context(res);
    const current = requireCurrent(await repository.getUser(realm, req.params.id));
    checkIfMatch(req, current);
    try { await repository.deleteUser(realm, current.id, current.version); } catch (error) { throw repositoryError(error); }
    await writeAudit(req, res, 'scim.user.deleted', 'User', current.id, ['delete']);
    res.status(204).end();
  }));

  router.get('/:realm/Groups', asyncRoute(async (req, res) => {
    const { realm, baseUrl: root } = context(res);
    const page = pagination(req.query, maxPageSize, defaultPageSize);
    const result = await repository.listGroups(realm, {
      ...page, filter: parseFilter(req.query.filter, 'Group'), sort: parseSort(req.query, 'Group'),
    });
    const resources = await Promise.all(result.resources.map((item) => groupResource(repository, realm, item, root)));
    res.json(listResponse(resources, result.totalResults, page.startIndex));
  }));

  router.post('/:realm/Groups', asyncRoute(async (req, res) => {
    const { realm, baseUrl: root } = context(res);
    let created;
    try { created = await repository.createGroup(realm, normalizeGroup(req.body)); } catch (error) { throw repositoryError(error); }
    await writeAudit(req, res, 'scim.group.created', 'Group', created.id, ['create']);
    sendResource(res, 201, await groupResource(repository, realm, created, root));
  }));

  router.get('/:realm/Groups/:id', asyncRoute(async (req, res) => {
    const { realm, baseUrl: root } = context(res);
    const record = requireCurrent(await repository.getGroup(realm, req.params.id));
    if (conditionalGet(req, res, record)) return;
    res.json(await groupResource(repository, realm, record, root));
  }));

  router.put('/:realm/Groups/:id', asyncRoute(async (req, res) => {
    const { realm, baseUrl: root } = context(res);
    const current = requireCurrent(await repository.getGroup(realm, req.params.id));
    checkIfMatch(req, current);
    if (req.body?.id != null && req.body.id !== current.id) throw new ScimError(400, 'id is immutable.', 'mutability');
    let updated;
    try { updated = await repository.replaceGroup(realm, current.id, normalizeGroup(replacementBody(req.body)), current.version); }
    catch (error) { throw repositoryError(error); }
    await writeAudit(req, res, 'scim.group.replaced', 'Group', current.id, ['replace']);
    sendResource(res, 200, await groupResource(repository, realm, updated, root));
  }));

  router.patch('/:realm/Groups/:id', asyncRoute(async (req, res) => {
    const { realm, baseUrl: root } = context(res);
    const current = requireCurrent(await repository.getGroup(realm, req.params.id));
    checkIfMatch(req, current);
    const next = normalizeGroup(applyGroupPatch(attributes(current), req.body));
    if (isDeepStrictEqual(next, attributes(current))) {
      sendResource(res, 200, await groupResource(repository, realm, current, root));
      return;
    }
    let updated;
    try { updated = await repository.replaceGroup(realm, current.id, next, current.version); }
    catch (error) { throw repositoryError(error); }
    const changes = req.body.Operations.map(({ path, op }) => `${String(op).toLowerCase()}:${path ?? '*'}`);
    await writeAudit(req, res, 'scim.group.patched', 'Group', current.id, changes);
    sendResource(res, 200, await groupResource(repository, realm, updated, root));
  }));

  router.delete('/:realm/Groups/:id', asyncRoute(async (req, res) => {
    const { realm } = context(res);
    const current = requireCurrent(await repository.getGroup(realm, req.params.id));
    checkIfMatch(req, current);
    try { await repository.deleteGroup(realm, current.id, current.version); } catch (error) { throw repositoryError(error); }
    await writeAudit(req, res, 'scim.group.deleted', 'Group', current.id, ['delete']);
    res.status(204).end();
  }));

  router.use('/:realm', (req, res) => {
    res.status(404).json(errorBody(404, 'The requested SCIM endpoint does not exist.'));
  });

  router.use((error, req, res, _next) => {
    let resolved = error;
    if (error instanceof SyntaxError && error.status === 400 && 'body' in error) resolved = new ScimError(400, 'The request body is not valid JSON.', 'invalidSyntax');
    if (error?.type === 'entity.too.large') {
      const detail = /\/Bulk(?:\/|$)/u.test(req.originalUrl)
        ? `The Bulk request exceeds maxPayloadSize (${maxPayloadSize}).`
        : 'The SCIM request payload is too large.';
      resolved = new ScimError(413, detail);
    }
    if (!(resolved instanceof ScimError)) {
      req.log?.error?.({ err: resolved }, 'SCIM request failed');
      resolved = new ScimError(500, 'The SCIM request could not be completed.');
    }
    if (res.headersSent) return res.end();
    res.type('application/scim+json').status(resolved.status).json(errorBody(resolved.status, resolved.message, resolved.scimType));
  });

  return router;
}
