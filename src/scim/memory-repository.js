import { randomUUID } from 'node:crypto';
import { ScimRepositoryError } from './errors.js';

function clone(value) {
  return value == null ? value : structuredClone(value);
}

function timestamp() {
  return new Date().toISOString();
}

function record(attributes) {
  const now = timestamp();
  return { ...clone(attributes), id: randomUUID(), version: 1, createdAt: now, updatedAt: now };
}

function replaceRecord(current, attributes) {
  return {
    ...clone(attributes), id: current.id, version: current.version + 1,
    createdAt: current.createdAt, updatedAt: timestamp(),
  };
}

function matches(resource, filter) {
  if (!filter) return true;
  if (filter.attribute === 'members.value') return (resource.members ?? []).some(({ value }) => value === filter.value);
  const actual = resource[filter.attribute];
  if (filter.attribute === 'active') return Boolean(actual) === (filter.value.toLowerCase() === 'true');
  if (['userName', 'displayName'].includes(filter.attribute)) {
    return String(actual ?? '').toLowerCase() === filter.value.toLowerCase();
  }
  return String(actual ?? '') === filter.value;
}

function page(resources, { filter, startIndex, count }) {
  const selected = resources.filter((item) => matches(item, filter)).sort((a, b) => a.id.localeCompare(b.id));
  return {
    totalResults: selected.length,
    resources: selected.slice(startIndex - 1, startIndex - 1 + count).map(clone),
  };
}

/**
 * Realm-scoped in-memory implementation of the SCIM repository contract for
 * protocol tests only. It is not durable and may retain write-only password
 * input in process memory; never use it as a production identity store.
 *
 * A durable adapter must provide the same methods and atomically enforce the
 * supplied expectedVersion in replace/delete operations. It must also map
 * User.active=false to the identity system's disabled-account state so a
 * disabled SCIM user cannot authenticate or receive new tokens. Password
 * input must be hashed immediately and must never be returned or stored raw.
 */
export class MemoryScimRepository {
  #realms = new Map();

  #realm(name) {
    let value = this.#realms.get(name);
    if (!value) {
      value = { users: new Map(), groups: new Map() };
      this.#realms.set(name, value);
    }
    return value;
  }

  #assertVersion(current, expectedVersion) {
    if (!current) throw new ScimRepositoryError('NOT_FOUND', 'The requested SCIM resource does not exist.');
    if (expectedVersion != null && current.version !== expectedVersion) {
      throw new ScimRepositoryError('VERSION_MISMATCH', 'The SCIM resource changed since it was read.');
    }
  }

  #assertUserUnique(realm, attributes, excludeId) {
    for (const user of this.#realm(realm).users.values()) {
      if (user.id === excludeId) continue;
      if (user.userName.toLowerCase() === attributes.userName.toLowerCase()) {
        throw new ScimRepositoryError('UNIQUENESS', 'userName already exists in this realm.');
      }
      if (attributes.externalId != null && user.externalId === attributes.externalId) {
        throw new ScimRepositoryError('UNIQUENESS', 'externalId already exists for a User in this realm.');
      }
    }
  }

  #assertGroupUnique(realm, attributes, excludeId) {
    if (attributes.externalId == null) return;
    for (const group of this.#realm(realm).groups.values()) {
      if (group.id !== excludeId && group.externalId === attributes.externalId) {
        throw new ScimRepositoryError('UNIQUENESS', 'externalId already exists for a Group in this realm.');
      }
    }
  }

  #assertMembers(realm, members = []) {
    const users = this.#realm(realm).users;
    for (const member of members) {
      if (!users.has(member.value)) {
        throw new ScimRepositoryError('INVALID_VALUE', `Group member ${member.value} is not a User in this realm.`);
      }
    }
  }

  async listUsers(realm, options) {
    return page([...this.#realm(realm).users.values()], options);
  }

  async getUser(realm, id) {
    return clone(this.#realm(realm).users.get(id));
  }

  async createUser(realm, attributes) {
    this.#assertUserUnique(realm, attributes);
    const created = record(attributes);
    this.#realm(realm).users.set(created.id, created);
    return clone(created);
  }

  async replaceUser(realm, id, attributes, expectedVersion) {
    const users = this.#realm(realm).users;
    const current = users.get(id);
    this.#assertVersion(current, expectedVersion);
    this.#assertUserUnique(realm, attributes, id);
    const updated = replaceRecord(current, attributes);
    users.set(id, updated);
    return clone(updated);
  }

  async deleteUser(realm, id, expectedVersion) {
    const data = this.#realm(realm);
    const current = data.users.get(id);
    this.#assertVersion(current, expectedVersion);
    data.users.delete(id);
    for (const [groupId, group] of data.groups) {
      const members = (group.members ?? []).filter(({ value }) => value !== id);
      if (members.length !== (group.members ?? []).length) data.groups.set(groupId, replaceRecord(group, { ...group, members }));
    }
    return clone(current);
  }

  async listGroups(realm, options) {
    return page([...this.#realm(realm).groups.values()], options);
  }

  async getGroup(realm, id) {
    return clone(this.#realm(realm).groups.get(id));
  }

  async createGroup(realm, attributes) {
    this.#assertGroupUnique(realm, attributes);
    this.#assertMembers(realm, attributes.members);
    const created = record(attributes);
    this.#realm(realm).groups.set(created.id, created);
    return clone(created);
  }

  async replaceGroup(realm, id, attributes, expectedVersion) {
    const groups = this.#realm(realm).groups;
    const current = groups.get(id);
    this.#assertVersion(current, expectedVersion);
    this.#assertGroupUnique(realm, attributes, id);
    this.#assertMembers(realm, attributes.members);
    const updated = replaceRecord(current, attributes);
    groups.set(id, updated);
    return clone(updated);
  }

  async deleteGroup(realm, id, expectedVersion) {
    const groups = this.#realm(realm).groups;
    const current = groups.get(id);
    this.#assertVersion(current, expectedVersion);
    groups.delete(id);
    return clone(current);
  }

  async listUserGroups(realm, userId) {
    return [...this.#realm(realm).groups.values()]
      .filter((group) => (group.members ?? []).some(({ value }) => value === userId))
      .map((group) => ({ value: group.id, display: group.displayName, type: 'direct' }));
  }

  async isUserActive(realm, id) {
    const user = this.#realm(realm).users.get(id);
    return Boolean(user && user.active !== false);
  }
}
