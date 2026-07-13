import { SCIM_URNS } from './constants.js';
import { canonicalGroupAttribute, canonicalUserAttribute } from './attributes.js';
import { ScimError } from './errors.js';

const pathExpression = /^([A-Za-z][A-Za-z0-9$-]*)(?:\[([A-Za-z][A-Za-z0-9$-]*)\s+eq\s+"((?:[^"\\]|\\.)*)"\])?(?:\.([A-Za-z][A-Za-z0-9$-]*))?$/i;

function clone(value) {
  return structuredClone(value);
}

function operations(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new ScimError(400, 'PATCH body must be an object.', 'invalidSyntax');
  if (!Array.isArray(body.schemas) || !body.schemas.includes(SCIM_URNS.patchOp)) {
    throw new ScimError(400, `PATCH schemas must include ${SCIM_URNS.patchOp}.`, 'invalidSyntax');
  }
  if (!Array.isArray(body.Operations) || body.Operations.length === 0 || body.Operations.length > 100) {
    throw new ScimError(400, 'PATCH Operations must be a non-empty array of at most 100 operations.', 'invalidValue');
  }
  return body.Operations;
}

function parsePath(input, canonical) {
  if (typeof input !== 'string') throw new ScimError(400, 'PATCH path must be a string.', 'invalidPath');
  const match = pathExpression.exec(input.trim());
  if (!match) throw new ScimError(400, `PATCH path ${input} is invalid.`, 'invalidPath');
  const attribute = canonical(match[1]);
  if (!attribute) throw new ScimError(400, `PATCH path ${input} is not supported.`, 'invalidPath');
  let filterValue;
  if (match[3] != null) {
    try { filterValue = JSON.parse(`"${match[3]}"`); } catch { throw new ScimError(400, `PATCH path ${input} is invalid.`, 'invalidPath'); }
  }
  return { attribute, filterAttribute: match[2], filterValue, subAttribute: match[4] };
}

function operationName(value) {
  const name = String(value ?? '').toLowerCase();
  if (!['add', 'replace', 'remove'].includes(name)) throw new ScimError(400, `PATCH op ${value} is not supported.`, 'invalidValue');
  return name;
}

function setSimple(resource, path, op, value) {
  if (path.filterAttribute) throw new ScimError(400, 'Value filters are supported only for multi-valued attributes.', 'invalidPath');
  if (path.subAttribute) {
    if (op === 'remove') {
      if (!resource[path.attribute] || typeof resource[path.attribute] !== 'object'
        || !Object.hasOwn(resource[path.attribute], path.subAttribute)) {
        throw new ScimError(400, 'The PATCH path did not match a value.', 'noTarget');
      }
      delete resource[path.attribute][path.subAttribute];
      return;
    }
    if (!resource[path.attribute] || Array.isArray(resource[path.attribute]) || typeof resource[path.attribute] !== 'object') resource[path.attribute] = {};
    resource[path.attribute][path.subAttribute] = clone(value);
    return;
  }
  if (op === 'remove') {
    if (!Object.hasOwn(resource, path.attribute)) throw new ScimError(400, 'The PATCH path did not match a value.', 'noTarget');
    delete resource[path.attribute];
  }
  else resource[path.attribute] = clone(value);
}

function setMulti(resource, path, op, value) {
  const current = Array.isArray(resource[path.attribute]) ? clone(resource[path.attribute]) : [];
  if (path.filterAttribute) {
    if (path.filterAttribute.toLowerCase() !== 'value' || path.subAttribute) {
      throw new ScimError(400, 'Only a value eq filter is supported for this multi-valued path.', 'invalidPath');
    }
    const retained = current.filter((item) => String(item?.value) !== path.filterValue);
    if (retained.length === current.length && op !== 'add') {
      throw new ScimError(400, 'The PATCH value filter did not match a value.', 'noTarget');
    }
    if (op === 'remove') resource[path.attribute] = retained;
    else {
      const additions = Array.isArray(value) ? value : [value];
      resource[path.attribute] = [...retained, ...clone(additions)];
    }
    return;
  }
  if (path.subAttribute) throw new ScimError(400, 'Sub-attribute updates on multi-valued attributes require a supported value filter.', 'invalidPath');
  if (op === 'remove') {
    if (!Object.hasOwn(resource, path.attribute)) throw new ScimError(400, 'The PATCH path did not match a value.', 'noTarget');
    delete resource[path.attribute];
  } else if (op === 'add') {
    const additions = clone(Array.isArray(value) ? value : [value]);
    const existingValues = new Set(current.map((item) => item?.value).filter((item) => item != null));
    resource[path.attribute] = [...current, ...additions.filter((item) => item?.value == null || !existingValues.has(item.value))];
  }
  else resource[path.attribute] = clone(Array.isArray(value) ? value : [value]);
}

function apply(resource, body, canonical, multiAttributes) {
  const next = clone(resource);
  for (const raw of operations(body)) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new ScimError(400, 'Each PATCH operation must be an object.', 'invalidValue');
    const op = operationName(raw.op);
    if (raw.path == null) {
      if (op === 'remove') throw new ScimError(400, 'A remove operation requires a path.', 'noTarget');
      if (!raw.value || typeof raw.value !== 'object' || Array.isArray(raw.value)) {
        throw new ScimError(400, 'A pathless add/replace operation requires an object value.', 'invalidValue');
      }
      for (const [name, value] of Object.entries(raw.value)) {
        const attribute = canonical(name);
        if (!attribute) throw new ScimError(400, `PATCH attribute ${name} is not supported.`, 'invalidPath');
        if (multiAttributes.has(attribute)) setMulti(next, { attribute }, op, value);
        else setSimple(next, { attribute }, op, value);
      }
      continue;
    }
    const path = parsePath(raw.path, canonical);
    if (op !== 'remove' && !Object.hasOwn(raw, 'value')) throw new ScimError(400, `PATCH ${op} requires a value.`, 'invalidValue');
    if (multiAttributes.has(path.attribute)) setMulti(next, path, op, raw.value);
    else setSimple(next, path, op, raw.value);
  }
  return next;
}

export function applyUserPatch(resource, body) {
  return apply(resource, body, canonicalUserAttribute, new Set([
    'emails', 'phoneNumbers', 'ims', 'photos', 'addresses', 'entitlements', 'roles', 'x509Certificates',
  ]));
}

export function applyGroupPatch(resource, body) {
  return apply(resource, body, canonicalGroupAttribute, new Set(['members']));
}
