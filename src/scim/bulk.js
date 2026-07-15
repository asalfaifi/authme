import { SCIM_URNS } from './constants.js';
import { ScimError, errorBody, repositoryError } from './errors.js';

const methods = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function operationError(detail, scimType = 'invalidValue', status = 400) {
  return new ScimError(status, detail, scimType);
}

function validateOperation(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw operationError('Each Bulk operation must be an object.');
  }
  const method = typeof raw.method === 'string' ? raw.method.toUpperCase() : '';
  if (!methods.has(method)) throw operationError(`Bulk method ${raw.method} is not supported.`);
  if (typeof raw.path !== 'string' || !raw.path.startsWith('/') || raw.path.length > 2048) {
    throw operationError('Each Bulk operation requires a valid relative path.', 'invalidPath');
  }
  if (method === 'POST') {
    if (typeof raw.bulkId !== 'string' || raw.bulkId.length === 0 || raw.bulkId.length > 256) {
      throw operationError('A POST Bulk operation requires a non-empty bulkId of at most 256 characters.');
    }
    if (raw.version != null) throw operationError('version is not valid for a POST Bulk operation.');
  } else if (raw.bulkId != null) throw operationError('bulkId is valid only for POST Bulk operations.');
  if (method === 'DELETE') {
    if (raw.data != null) throw operationError('A DELETE Bulk operation cannot contain data.');
  } else if (!raw.data || typeof raw.data !== 'object' || Array.isArray(raw.data)) {
    throw operationError(`A ${method} Bulk operation requires an object data value.`);
  }
  if (raw.version != null && (typeof raw.version !== 'string' || raw.version.length > 256)) {
    throw operationError('A Bulk operation version must be a string.');
  }
  return { method, path: raw.path, data: raw.data, version: raw.version, bulkId: raw.bulkId };
}

function references(value, found = new Set()) {
  if (typeof value === 'string') {
    const marker = value.indexOf('bulkId:');
    if (marker >= 0 && value.length > marker + 7) found.add(value.slice(marker + 7));
    return found;
  }
  if (Array.isArray(value)) {
    for (const item of value) references(item, found);
    return found;
  }
  if (value && typeof value === 'object') {
    for (const item of Object.values(value)) references(item, found);
  }
  return found;
}

function substitute(value, resolved, failed) {
  if (typeof value === 'string') {
    const marker = value.indexOf('bulkId:');
    if (marker < 0 || value.length <= marker + 7) return value;
    const bulkId = value.slice(marker + 7);
    if (resolved.has(bulkId)) return `${value.slice(0, marker)}${resolved.get(bulkId)}`;
    const detail = failed.has(bulkId)
      ? `The Bulk operation depends on failed bulkId ${bulkId}.`
      : `The Bulk operation references unknown bulkId ${bulkId}.`;
    throw operationError(detail, undefined, 409);
  }
  if (Array.isArray(value)) return value.map((item) => substitute(item, resolved, failed));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, substitute(item, resolved, failed)]));
  }
  return value;
}

function resolvedOperation(operation, resolved, failed) {
  return {
    ...operation,
    path: substitute(operation.path, resolved, failed),
    ...(operation.data === undefined ? {} : { data: substitute(operation.data, resolved, failed) }),
  };
}

function asScimError(error) {
  const converted = repositoryError(error);
  if (converted instanceof ScimError) return converted;
  return new ScimError(500, 'The SCIM Bulk operation could not be completed.');
}

function failedResponse(raw, operation, error, locationFor) {
  const method = operation?.method ?? (typeof raw?.method === 'string' ? raw.method.toUpperCase() : String(raw?.method ?? ''));
  let location;
  if (method !== 'POST' && operation?.path) {
    try { location = locationFor(operation.path); } catch { /* An invalid path has no resource location. */ }
  }
  return {
    method,
    ...(typeof raw?.bulkId === 'string' ? { bulkId: raw.bulkId } : {}),
    ...(location ? { location } : {}),
    status: String(error.status),
    response: errorBody(error.status, error.message, error.scimType),
  };
}

function request(body, maxOperations) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ScimError(400, 'The Bulk request body must be an object.', 'invalidSyntax');
  }
  if (!Array.isArray(body.schemas) || !body.schemas.includes(SCIM_URNS.bulkRequest)) {
    throw new ScimError(400, `Bulk schemas must include ${SCIM_URNS.bulkRequest}.`, 'invalidSyntax');
  }
  if (!Array.isArray(body.Operations) || body.Operations.length === 0) {
    throw new ScimError(400, 'Bulk Operations must be a non-empty array.', 'invalidValue');
  }
  if (body.Operations.length > maxOperations) {
    throw new ScimError(413, `The Bulk request exceeds maxOperations (${maxOperations}).`);
  }
  const failOnErrors = body.failOnErrors ?? 0;
  if (!Number.isSafeInteger(failOnErrors) || failOnErrors < 0) {
    throw new ScimError(400, 'failOnErrors must be a non-negative integer.', 'invalidValue');
  }
  const bulkIds = new Set();
  for (const operation of body.Operations) {
    if (String(operation?.method ?? '').toUpperCase() !== 'POST' || typeof operation?.bulkId !== 'string') continue;
    if (bulkIds.has(operation.bulkId)) throw new ScimError(400, `Bulk bulkId ${operation.bulkId} is duplicated.`, 'invalidValue');
    bulkIds.add(operation.bulkId);
  }
  return { operations: body.Operations, failOnErrors, bulkIds };
}

/**
 * Processes independent, atomic repository operations while resolving POST
 * dependencies. The caller owns HTTP-path dispatch and realm scoping.
 */
export async function processBulk(body, { maxOperations, execute, locationFor, onUnexpectedError = () => {} }) {
  const parsed = request(body, maxOperations);
  const pending = parsed.operations.map((raw, index) => {
    try {
      const operation = validateOperation(raw);
      return { raw, index, operation, references: references([operation.path, operation.data]) };
    } catch (error) { return { raw, index, error: asScimError(error), references: new Set() }; }
  });
  const results = new Array(parsed.operations.length);
  const resolved = new Map();
  const failed = new Set();
  let errors = 0;

  while (pending.length && (!parsed.failOnErrors || errors < parsed.failOnErrors)) {
    let ready = pending.findIndex((item) => item.error || [...item.references].every((bulkId) => (
      !parsed.bulkIds.has(bulkId) || resolved.has(bulkId) || failed.has(bulkId)
    )));
    if (ready < 0) ready = 0;
    const [item] = pending.splice(ready, 1);
    try {
      if (item.error) throw item.error;
      const operation = resolvedOperation(item.operation, resolved, failed);
      const result = await execute(operation);
      results[item.index] = {
        method: operation.method,
        ...(operation.bulkId ? { bulkId: operation.bulkId } : {}),
        ...(result.location ? { location: result.location } : {}),
        ...(result.version ? { version: result.version } : {}),
        status: String(result.status),
      };
      if (operation.method === 'POST') resolved.set(operation.bulkId, result.id);
    } catch (rawError) {
      if (!(repositoryError(rawError) instanceof ScimError)) onUnexpectedError(rawError);
      const error = asScimError(rawError);
      results[item.index] = failedResponse(item.raw, item.operation, error, locationFor);
      if (item.operation?.method === 'POST' && item.operation.bulkId) failed.add(item.operation.bulkId);
      errors += 1;
    }
  }

  return {
    schemas: [SCIM_URNS.bulkResponse],
    Operations: results.filter(Boolean),
  };
}
