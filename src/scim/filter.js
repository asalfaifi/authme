import { GROUP_SCHEMA, SCIM_URNS, USER_SCHEMA } from './constants.js';
import { ScimError } from './errors.js';

const maxFilterLength = 4096;
const maxFilterNodes = 100;
const maxFilterDepth = 20;
const comparisonOperators = new Set(['eq', 'ne', 'co', 'sw', 'ew', 'gt', 'ge', 'lt', 'le']);
const stringOperators = new Set(['co', 'sw', 'ew']);
const orderingOperators = new Set(['gt', 'ge', 'lt', 'le']);

const commonAttributes = [
  { name: 'schemas', type: 'string', multiValued: true, caseExact: true },
  { name: 'id', type: 'string', multiValued: false, caseExact: true },
  { name: 'externalId', type: 'string', multiValued: false, caseExact: true },
  {
    name: 'meta', type: 'complex', multiValued: false, subAttributes: [
      { name: 'resourceType', type: 'string', multiValued: false, caseExact: false },
      { name: 'created', type: 'dateTime', multiValued: false },
      { name: 'lastModified', type: 'dateTime', multiValued: false },
      { name: 'location', type: 'reference', multiValued: false, caseExact: true },
      { name: 'version', type: 'string', multiValued: false, caseExact: true },
    ],
  },
];

function descriptor(attribute, segments, multiValued = false) {
  return {
    path: segments.join('.'),
    segments,
    type: attribute.type,
    caseExact: attribute.caseExact === true,
    multiValued: multiValued || attribute.multiValued === true,
    ...(attribute.subAttributes ? { subAttributes: attribute.subAttributes } : {}),
  };
}

function attributeMap(attributes, prefix = [], inheritedMulti = false) {
  const result = new Map();
  for (const attribute of attributes) {
    const segments = [...prefix, attribute.name];
    const current = descriptor(attribute, segments, inheritedMulti);
    result.set(attribute.name.toLowerCase(), current);
    if (attribute.subAttributes) {
      const children = attributeMap(attribute.subAttributes, segments, current.multiValued);
      for (const [name, child] of children) result.set(`${attribute.name.toLowerCase()}.${name}`, child);
    }
  }
  return result;
}

const attributesByType = Object.freeze({
  User: attributeMap([...commonAttributes, ...USER_SCHEMA.attributes]),
  Group: attributeMap([...commonAttributes, ...GROUP_SCHEMA.attributes]),
});

function invalid(detail = 'The filter is invalid.') {
  return new ScimError(400, detail, 'invalidFilter');
}

function stripSchemaPrefix(input, resourceType) {
  const prefixes = [SCIM_URNS.user, SCIM_URNS.group];
  const prefix = prefixes.find((candidate) => input.toLowerCase().startsWith(`${candidate.toLowerCase()}:`));
  if (!prefix) return input;
  const expected = resourceType === 'User' ? SCIM_URNS.user : SCIM_URNS.group;
  if (prefix !== expected) throw invalid(`The filter attribute ${input} is not defined for ${resourceType}.`);
  return input.slice(prefix.length + 1);
}

function resolveAttribute(input, resourceType, relativeAttributes) {
  const raw = stripSchemaPrefix(input, resourceType);
  const found = relativeAttributes
    ? relativeAttributes.get(raw.toLowerCase())
    : attributesByType[resourceType]?.get(raw.toLowerCase());
  if (!found || found.path === 'password') {
    throw invalid(`Filtering ${resourceType} by ${input} is not supported.`);
  }
  return found;
}

function relativeMap(parent) {
  if (!parent.subAttributes) return null;
  return attributeMap(parent.subAttributes);
}

function tokenize(input) {
  const tokens = [];
  let index = 0;
  while (index < input.length) {
    if (/\s/u.test(input[index])) { index += 1; continue; }
    const start = index;
    const character = input[index];
    if ('()[]'.includes(character)) {
      tokens.push({ type: character, value: character, start });
      index += 1;
      continue;
    }
    if (character === '"') {
      index += 1;
      let escaped = false;
      while (index < input.length) {
        const current = input[index];
        index += 1;
        if (escaped) escaped = false;
        else if (current === '\\') escaped = true;
        else if (current === '"') break;
      }
      const source = input.slice(start, index);
      if (!source.endsWith('"') || escaped) throw invalid('The filter string literal is malformed.');
      try { tokens.push({ type: 'literal', value: JSON.parse(source), start }); }
      catch { throw invalid('The filter string literal is malformed.'); }
      continue;
    }
    while (index < input.length && !/\s/u.test(input[index]) && !'()[]"'.includes(input[index])) index += 1;
    const source = input.slice(start, index);
    if (/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/u.test(source)) {
      const value = Number(source);
      if (!Number.isFinite(value)) throw invalid('The filter number is out of range.');
      tokens.push({ type: 'literal', value, start });
    } else if (['true', 'false', 'null'].includes(source.toLowerCase())) {
      tokens.push({ type: 'literal', value: JSON.parse(source.toLowerCase()), start });
    } else tokens.push({ type: 'word', value: source, lower: source.toLowerCase(), start });
  }
  tokens.push({ type: 'end', value: '', start: input.length });
  return tokens;
}

class Parser {
  constructor(input, resourceType) {
    this.tokens = tokenize(input);
    this.resourceType = resourceType;
    this.index = 0;
    this.nodes = 0;
  }

  current() { return this.tokens[this.index]; }

  take(type, value) {
    const token = this.current();
    if (token.type !== type || (value !== undefined && token.lower !== value)) return null;
    this.index += 1;
    return token;
  }

  expect(type, value, detail = 'The filter syntax is invalid.') {
    const token = this.take(type, value);
    if (!token) throw invalid(detail);
    return token;
  }

  node(value, depth) {
    this.nodes += 1;
    if (this.nodes > maxFilterNodes || depth > maxFilterDepth) throw invalid('The filter is too complex.');
    return value;
  }

  parse() {
    const result = this.parseOr(null, 1);
    this.expect('end', undefined, `Unexpected filter token ${this.current().value}.`);
    return result;
  }

  parseOr(relative, depth) {
    let left = this.parseAnd(relative, depth + 1);
    while (this.take('word', 'or')) {
      left = this.node({ type: 'logical', operator: 'or', left, right: this.parseAnd(relative, depth + 1) }, depth);
    }
    return left;
  }

  parseAnd(relative, depth) {
    let left = this.parseUnary(relative, depth + 1);
    while (this.take('word', 'and')) {
      left = this.node({ type: 'logical', operator: 'and', left, right: this.parseUnary(relative, depth + 1) }, depth);
    }
    return left;
  }

  parseUnary(relative, depth) {
    if (this.take('word', 'not')) {
      this.expect('(', undefined, 'The not operator must be followed by a parenthesised filter.');
      const expression = this.parseOr(relative, depth + 1);
      this.expect(')', undefined, 'The parenthesised filter is not closed.');
      return this.node({ type: 'not', expression }, depth);
    }
    if (this.take('(')) {
      const expression = this.parseOr(relative, depth + 1);
      this.expect(')', undefined, 'The parenthesised filter is not closed.');
      return expression;
    }
    return this.parseAttributeExpression(relative, depth + 1);
  }

  parseAttributeExpression(relative, depth) {
    const name = this.expect('word', undefined, 'A filter expression must begin with an attribute name.').value;
    const attribute = resolveAttribute(name, this.resourceType, relative);
    if (this.take('[')) {
      if (!attribute.multiValued || attribute.type !== 'complex') {
        throw invalid(`The attribute ${name} does not support a complex value filter.`);
      }
      const expression = this.parseOr(relativeMap(attribute), depth + 1);
      this.expect(']', undefined, 'The complex value filter is not closed.');
      return this.node({ type: 'valuePath', attribute, expression }, depth);
    }
    const operator = this.expect('word', undefined, `The filter for ${name} is missing an operator.`).lower;
    if (operator === 'pr') return this.node({ type: 'presence', attribute }, depth);
    if (!comparisonOperators.has(operator)) throw invalid(`The filter operator ${operator} is not supported.`);
    const token = this.expect('literal', undefined, `The ${operator} operator requires a JSON comparison value.`);
    if (stringOperators.has(operator) && !['string', 'reference', 'complex'].includes(attribute.type)) {
      throw invalid(`The ${operator} operator is not valid for ${name}.`);
    }
    if (orderingOperators.has(operator) && ['boolean', 'binary', 'complex'].includes(attribute.type)) {
      throw invalid(`The ${operator} operator is not valid for ${name}.`);
    }
    if (attribute.type === 'boolean' && ![true, false, 'true', 'false'].includes(token.value)) {
      throw invalid(`The filter value for ${name} must be boolean.`);
    }
    if (stringOperators.has(operator) && typeof token.value !== 'string') {
      throw invalid(`The filter value for ${name} must be a string.`);
    }
    if (['string', 'reference', 'dateTime', 'complex'].includes(attribute.type)
      && token.value !== null && typeof token.value !== 'string') {
      throw invalid(`The filter value for ${name} must be a string or null.`);
    }
    return this.node({ type: 'comparison', operator, attribute, value: token.value }, depth);
  }
}

export function parseFilter(input, resourceType) {
  if (input == null || input === '') return null;
  if (typeof input !== 'string' || input.length > maxFilterLength || !attributesByType[resourceType]) throw invalid();
  if (!input.trim()) throw invalid('The filter must contain an expression.');
  return new Parser(input, resourceType).parse();
}

function synthesizedValue(resource, attribute, resourceType) {
  if (attribute.path === 'schemas') return [resourceType === 'User' ? SCIM_URNS.user : SCIM_URNS.group];
  if (attribute.path === 'meta.resourceType') return resourceType;
  if (attribute.path === 'meta.created') return resource.createdAt;
  if (attribute.path === 'meta.lastModified') return resource.updatedAt;
  if (attribute.path === 'meta.version') return resource.version == null ? undefined : `W/"${resource.version}"`;
  return undefined;
}

function valuesAt(value, segments) {
  if (!segments.length) return Array.isArray(value) ? value : [value];
  if (Array.isArray(value)) return value.flatMap((item) => valuesAt(item, segments));
  if (!value || typeof value !== 'object') return [];
  const [head, ...tail] = segments;
  return valuesAt(value[head], tail);
}

function primitiveValues(value) {
  if (Array.isArray(value)) return value.flatMap(primitiveValues);
  if (value && typeof value === 'object') return Object.values(value).flatMap(primitiveValues);
  return value == null ? [] : [value];
}

function attributeValues(resource, attribute, resourceType) {
  const synthesized = synthesizedValue(resource, attribute, resourceType);
  const raw = synthesized === undefined ? valuesAt(resource, attribute.segments) : valuesAt(synthesized, []);
  return attribute.type === 'complex' ? raw.flatMap(primitiveValues) : raw.filter((value) => value != null);
}

function present(value) {
  if (value == null || value === '') return false;
  if (Array.isArray(value)) return value.some(present);
  if (typeof value === 'object') return Object.values(value).some(present);
  return true;
}

function comparable(value, attribute) {
  if (attribute.type === 'boolean') {
    if (typeof value === 'string' && ['true', 'false'].includes(value.toLowerCase())) return value.toLowerCase() === 'true';
    return value;
  }
  if (attribute.type === 'dateTime') {
    const time = Date.parse(value);
    return Number.isNaN(time) ? value : time;
  }
  if (typeof value === 'string' && !attribute.caseExact) return value.toLowerCase();
  return value;
}

function compare(actual, expected, operator, attribute) {
  const left = comparable(actual, attribute);
  const right = comparable(expected, attribute);
  if (operator === 'eq') return left === right;
  if (operator === 'ne') return left !== right;
  if (operator === 'co') return typeof left === 'string' && typeof right === 'string' && left.includes(right);
  if (operator === 'sw') return typeof left === 'string' && typeof right === 'string' && left.startsWith(right);
  if (operator === 'ew') return typeof left === 'string' && typeof right === 'string' && left.endsWith(right);
  if (operator === 'gt') return left > right;
  if (operator === 'ge') return left >= right;
  if (operator === 'lt') return left < right;
  return left <= right;
}

function evaluate(expression, resource, resourceType) {
  if (expression.type === 'logical') {
    if (expression.operator === 'and') return evaluate(expression.left, resource, resourceType) && evaluate(expression.right, resource, resourceType);
    return evaluate(expression.left, resource, resourceType) || evaluate(expression.right, resource, resourceType);
  }
  if (expression.type === 'not') return !evaluate(expression.expression, resource, resourceType);
  if (expression.type === 'presence') {
    const synthesized = synthesizedValue(resource, expression.attribute, resourceType);
    const values = synthesized === undefined ? valuesAt(resource, expression.attribute.segments) : [synthesized];
    return values.some(present);
  }
  if (expression.type === 'valuePath') {
    const candidates = valuesAt(resource, expression.attribute.segments);
    return candidates.some((candidate) => candidate && typeof candidate === 'object'
      && evaluate(expression.expression, candidate, resourceType));
  }
  const values = attributeValues(resource, expression.attribute, resourceType);
  return values.length > 0 && values.some((actual) => compare(actual, expression.value, expression.operator, expression.attribute));
}

function legacyFilter(filter, resourceType) {
  if (!filter?.attribute || filter.type) return filter;
  const attribute = resolveAttribute(filter.attribute, resourceType);
  return { type: 'comparison', operator: 'eq', attribute, value: filter.value };
}

export function parseSort(query, resourceType) {
  const sortBy = query.sortBy;
  const rawOrder = query.sortOrder;
  if ((sortBy == null || sortBy === '') && (rawOrder == null || rawOrder === '')) return null;
  if (typeof sortBy !== 'string' || !sortBy.trim() || sortBy.length > 512) {
    throw new ScimError(400, 'sortBy must name a supported attribute.', 'invalidValue');
  }
  let attribute;
  try { attribute = resolveAttribute(sortBy.trim(), resourceType); }
  catch (error) {
    if (error instanceof ScimError) throw new ScimError(400, error.message, 'invalidValue');
    throw error;
  }
  if (attribute.type === 'complex') {
    throw new ScimError(400, `sortBy ${sortBy} must identify a complex sub-attribute.`, 'invalidValue');
  }
  const order = rawOrder == null || rawOrder === '' ? 'ascending' : String(rawOrder).toLowerCase();
  if (!['ascending', 'descending'].includes(order)) {
    throw new ScimError(400, 'sortOrder must be ascending or descending.', 'invalidValue');
  }
  return { attribute, order };
}

function sortValue(resource, sort, resourceType) {
  const { attribute } = sort;
  if (!attribute.multiValued) return attributeValues(resource, attribute, resourceType)[0];
  if (attribute.segments.length > 1) {
    const parent = resource[attribute.segments[0]];
    if (Array.isArray(parent)) {
      const selected = parent.find((item) => item?.primary === true) ?? parent[0];
      return valuesAt(selected, attribute.segments.slice(1)).find((value) => value != null);
    }
  }
  return attributeValues(resource, attribute, resourceType)[0];
}

function orderValues(left, right, attribute) {
  const a = comparable(left, attribute);
  const b = comparable(right, attribute);
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

export function queryResources(resources, options, resourceType) {
  const filter = legacyFilter(options.filter, resourceType);
  const selected = resources.filter((item) => !filter || evaluate(filter, item, resourceType));
  selected.sort((left, right) => {
    if (options.sort) {
      const a = sortValue(left, options.sort, resourceType);
      const b = sortValue(right, options.sort, resourceType);
      const aMissing = a == null || a === '';
      const bMissing = b == null || b === '';
      if (aMissing !== bMissing) return options.sort.order === 'ascending' ? (aMissing ? 1 : -1) : (aMissing ? -1 : 1);
      const ordered = aMissing ? 0 : orderValues(a, b, options.sort.attribute);
      if (ordered) return options.sort.order === 'ascending' ? ordered : -ordered;
    }
    return String(left.id).localeCompare(String(right.id));
  });
  return {
    totalResults: selected.length,
    resources: selected.slice(options.startIndex - 1, options.startIndex - 1 + options.count),
  };
}

export function pagination(query, maxPageSize, defaultPageSize) {
  function integer(value, fallback, name, minimum) {
    if (value == null || value === '') return fallback;
    if (!/^\d+$/u.test(String(value))) throw new ScimError(400, `${name} must be an integer.`, 'invalidValue');
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed) || parsed < minimum) throw new ScimError(400, `${name} is out of range.`, 'invalidValue');
    return parsed;
  }
  const startIndex = integer(query.startIndex, 1, 'startIndex', 1);
  const requested = integer(query.count, defaultPageSize, 'count', 0);
  return { startIndex, count: Math.min(requested, maxPageSize) };
}
