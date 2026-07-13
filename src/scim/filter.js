import { ScimError } from './errors.js';

const eqFilter = /^([A-Za-z][A-Za-z0-9$_.-]*)\s+eq\s+"((?:[^"\\]|\\.)*)"$/i;

const supported = Object.freeze({
  User: new Map([
    ['id', 'id'], ['username', 'userName'], ['externalid', 'externalId'], ['active', 'active'],
  ]),
  Group: new Map([
    ['id', 'id'], ['displayname', 'displayName'], ['externalid', 'externalId'], ['members.value', 'members.value'],
  ]),
});

export function parseFilter(input, resourceType) {
  if (input == null || input === '') return null;
  if (typeof input !== 'string' || input.length > 1024) {
    throw new ScimError(400, 'The filter is invalid.', 'invalidFilter');
  }
  const match = eqFilter.exec(input.trim());
  if (!match) throw new ScimError(400, 'Only a single attribute eq "value" filter is supported.', 'invalidFilter');
  const attribute = supported[resourceType]?.get(match[1].toLowerCase());
  if (!attribute) throw new ScimError(400, `Filtering ${resourceType} by ${match[1]} is not supported.`, 'invalidFilter');
  let value;
  try { value = JSON.parse(`"${match[2]}"`); } catch { throw new ScimError(400, 'The filter string is malformed.', 'invalidFilter'); }
  if (attribute === 'active' && !['true', 'false'].includes(value.toLowerCase())) {
    throw new ScimError(400, 'The active filter value must be true or false.', 'invalidFilter');
  }
  return { attribute, value };
}

export function pagination(query, maxPageSize, defaultPageSize) {
  function integer(value, fallback, name, minimum) {
    if (value == null || value === '') return fallback;
    if (!/^\d+$/.test(String(value))) throw new ScimError(400, `${name} must be an integer.`, 'invalidValue');
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed) || parsed < minimum) throw new ScimError(400, `${name} is out of range.`, 'invalidValue');
    return parsed;
  }
  const startIndex = integer(query.startIndex, 1, 'startIndex', 1);
  const requested = integer(query.count, defaultPageSize, 'count', 0);
  return { startIndex, count: Math.min(requested, maxPageSize) };
}
