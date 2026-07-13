import { SCIM_URNS } from './constants.js';
import { ScimError } from './errors.js';

const userNames = new Map([
  ['externalid', 'externalId'], ['username', 'userName'], ['name', 'name'], ['displayname', 'displayName'],
  ['nickname', 'nickName'], ['profileurl', 'profileUrl'], ['title', 'title'], ['usertype', 'userType'],
  ['preferredlanguage', 'preferredLanguage'], ['locale', 'locale'], ['timezone', 'timezone'], ['active', 'active'],
  ['password', 'password'], ['emails', 'emails'], ['phonenumbers', 'phoneNumbers'], ['ims', 'ims'], ['photos', 'photos'],
  ['addresses', 'addresses'], ['entitlements', 'entitlements'], ['roles', 'roles'], ['x509certificates', 'x509Certificates'],
]);

const groupNames = new Map([
  ['externalid', 'externalId'], ['displayname', 'displayName'], ['members', 'members'],
]);

function object(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ScimError(400, `${name} must be an object.`, 'invalidValue');
  return value;
}

function text(value, name, { required = false, max = 2048 } = {}) {
  if (value == null && !required) return undefined;
  if (typeof value !== 'string' || (required && value.trim() === '') || value.length > max) {
    throw new ScimError(400, `${name} must be ${required ? 'a non-empty' : 'a'} string.`, 'invalidValue');
  }
  return value;
}

function canonicalInput(input, names, schemaUrn) {
  object(input, 'The SCIM resource');
  if (input.schemas != null) {
    if (!Array.isArray(input.schemas) || !input.schemas.includes(schemaUrn)) {
      throw new ScimError(400, `schemas must include ${schemaUrn}.`, 'invalidSyntax');
    }
  }
  const result = {};
  for (const [rawName, value] of Object.entries(input)) {
    const lower = rawName.toLowerCase();
    if (['schemas'].includes(lower)) continue;
    if (['id', 'meta'].includes(lower)) throw new ScimError(400, `${rawName} is readOnly.`, 'mutability');
    if (lower === 'groups') throw new ScimError(400, 'groups is readOnly and is managed through Group membership.', 'mutability');
    const name = names.get(lower);
    if (!name) throw new ScimError(400, `Attribute ${rawName} is not supported by this resource type.`, 'invalidValue');
    result[name] = value;
  }
  return result;
}

function normalizeComplex(value, name) {
  const input = object(value, name);
  const result = {};
  for (const [key, item] of Object.entries(input)) {
    if (item == null) continue;
    if (typeof item !== 'string' || item.length > 2048) throw new ScimError(400, `${name}.${key} must be a string.`, 'invalidValue');
    result[key] = item;
  }
  return result;
}

function normalizeMulti(value, name) {
  if (!Array.isArray(value)) throw new ScimError(400, `${name} must be an array.`, 'invalidValue');
  let primary = 0;
  const result = value.map((entry, index) => {
    const item = object(entry, `${name}[${index}]`);
    const normalized = {};
    for (const [key, child] of Object.entries(item)) {
      if (child == null) continue;
      if (key === 'primary') {
        if (typeof child !== 'boolean') throw new ScimError(400, `${name}[${index}].primary must be a boolean.`, 'invalidValue');
        if (child) primary += 1;
        normalized.primary = child;
      } else {
        normalized[key] = text(child, `${name}[${index}].${key}`);
      }
    }
    return normalized;
  });
  if (primary > 1) throw new ScimError(400, `${name} cannot contain more than one primary value.`, 'invalidValue');
  return result;
}

export function normalizeUser(input, { existingPassword } = {}) {
  const source = canonicalInput(input, userNames, SCIM_URNS.user);
  const result = {};
  result.userName = text(source.userName, 'userName', { required: true, max: 256 }).trim();
  if ('externalId' in source) result.externalId = text(source.externalId, 'externalId', { max: 256 });
  for (const name of ['displayName', 'nickName', 'profileUrl', 'title', 'userType', 'preferredLanguage', 'locale', 'timezone']) {
    if (name in source) result[name] = text(source[name], name);
  }
  if ('active' in source) {
    if (typeof source.active !== 'boolean') throw new ScimError(400, 'active must be a boolean.', 'invalidValue');
    result.active = source.active;
  } else result.active = true;
  if ('password' in source) result.password = text(source.password, 'password', { max: 1024 });
  else if (existingPassword !== undefined) result.password = existingPassword;
  if ('name' in source) result.name = normalizeComplex(source.name, 'name');
  for (const name of ['emails', 'phoneNumbers', 'ims', 'photos', 'addresses', 'entitlements', 'roles', 'x509Certificates']) {
    if (name in source) result[name] = normalizeMulti(source[name], name);
  }
  return result;
}

export function normalizeGroup(input) {
  const source = canonicalInput(input, groupNames, SCIM_URNS.group);
  const result = { displayName: text(source.displayName, 'displayName', { required: true, max: 256 }).trim() };
  if ('externalId' in source) result.externalId = text(source.externalId, 'externalId', { max: 256 });
  if ('members' in source) {
    if (!Array.isArray(source.members)) throw new ScimError(400, 'members must be an array.', 'invalidValue');
    const seen = new Set();
    result.members = source.members.map((entry, index) => {
      const member = object(entry, `members[${index}]`);
      const value = text(member.value, `members[${index}].value`, { required: true, max: 256 });
      if (seen.has(value)) throw new ScimError(400, `members contains duplicate User ${value}.`, 'invalidValue');
      seen.add(value);
      if (member.type != null && String(member.type).toLowerCase() !== 'user') {
        throw new ScimError(400, 'Only User group members are supported.', 'invalidValue');
      }
      return { value, type: 'User' };
    });
  } else result.members = [];
  return result;
}

export function canonicalUserAttribute(name) {
  return userNames.get(String(name).toLowerCase());
}

export function canonicalGroupAttribute(name) {
  return groupNames.get(String(name).toLowerCase());
}
