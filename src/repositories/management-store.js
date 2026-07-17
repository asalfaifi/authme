import { randomUUID } from 'node:crypto';
import { assertAuthenticationFlowConfiguration } from '../authentication/flow-policy.js';

export const organizationInvitationPreviousRoles = Symbol('organizationInvitationPreviousRoles');

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function iso(value) {
  return value?.toISOString?.() ?? value ?? null;
}

function key(...parts) {
  return parts.join('\u0000');
}

function nowIso() {
  return new Date().toISOString();
}

function publicRealm(row) {
  if (!row) return undefined;
  return {
    name: row.name ?? row.realm_name,
    displayName: row.displayName ?? row.display_name,
    enabled: row.enabled,
    settings: clone(row.settings ?? {}),
    createdAt: iso(row.createdAt ?? row.created_at),
    updatedAt: iso(row.updatedAt ?? row.updated_at),
  };
}

function publicRole(row) {
  if (!row) return undefined;
  return {
    name: row.name,
    description: row.description ?? '',
    composites: [...(row.composites ?? [])],
    attributes: clone(row.attributes ?? {}),
    createdAt: iso(row.createdAt ?? row.created_at),
    updatedAt: iso(row.updatedAt ?? row.updated_at),
  };
}

function publicClientRole(row) {
  if (!row) return undefined;
  return {
    clientId: row.clientId ?? row.client_id,
    ...publicRole(row),
  };
}

function groupPaths(rows) {
  const byId = new Map(rows.map((row) => [String(row.id), row]));
  const paths = new Map();
  function pathFor(row, visiting = new Set()) {
    if (paths.has(String(row.id))) return paths.get(String(row.id));
    if (visiting.has(String(row.id))) throw new Error('Group hierarchy contains a cycle');
    visiting.add(String(row.id));
    const parent = row.parentId ? byId.get(String(row.parentId)) : null;
    if (row.parentId && !parent) throw new Error('Group parent does not exist in this realm');
    const path = `${parent ? pathFor(parent, visiting) : ''}/${row.name}`;
    visiting.delete(String(row.id));
    paths.set(String(row.id), path);
    return path;
  }
  return rows.map((row) => ({ ...row, path: pathFor(row) }));
}

function publicGroup(row) {
  if (!row) return undefined;
  return {
    id: String(row.id),
    name: row.name,
    parentId: row.parentId ?? row.parent_id ?? null,
    roles: [...(row.roles ?? [])],
    attributes: clone(row.attributes ?? {}),
    createdAt: iso(row.createdAt ?? row.created_at),
    updatedAt: iso(row.updatedAt ?? row.updated_at),
  };
}

function publicClientScope(row) {
  if (!row) return undefined;
  return {
    id: String(row.id),
    name: row.name,
    description: row.description ?? '',
    protocol: row.protocol ?? 'openid-connect',
    attributes: clone(row.attributes ?? {}),
    createdAt: iso(row.createdAt ?? row.created_at),
    updatedAt: iso(row.updatedAt ?? row.updated_at),
  };
}

function publicMapper(row) {
  if (!row) return undefined;
  return {
    id: String(row.id),
    ownerType: row.ownerType ?? row.owner_type,
    ownerId: row.ownerId ?? row.owner_id,
    name: row.name,
    mapperType: row.mapperType ?? row.mapper_type,
    config: clone(row.config ?? {}),
    createdAt: iso(row.createdAt ?? row.created_at),
    updatedAt: iso(row.updatedAt ?? row.updated_at),
  };
}

function publicFlow(row) {
  if (!row) return undefined;
  return {
    id: String(row.id),
    alias: row.alias,
    description: row.description ?? '',
    enabled: row.enabled,
    priority: Number(row.priority),
    clientIds: [...(row.clientIds ?? row.client_ids ?? [])],
    acr: row.acr,
    maxAgeSeconds: row.maxAgeSeconds ?? row.max_age_seconds ?? null,
    steps: clone(row.steps),
    createdAt: iso(row.createdAt ?? row.created_at),
    updatedAt: iso(row.updatedAt ?? row.updated_at),
  };
}

function publicOrganization(row, domains = []) {
  if (!row) return undefined;
  return {
    id: String(row.id),
    name: row.name,
    alias: row.alias,
    enabled: row.enabled,
    domains: domains.map((entry) => ({ domain: entry.domain, verified: entry.verified })),
    identityProviderIds: [...(row.identityProviderIds ?? row.identity_provider_ids ?? [])],
    attributes: clone(row.attributes ?? {}),
    createdAt: iso(row.createdAt ?? row.created_at),
    updatedAt: iso(row.updatedAt ?? row.updated_at),
  };
}

function publicMembership(row) {
  if (!row) return undefined;
  return {
    organizationId: String(row.organizationId ?? row.organization_id),
    userId: String(row.userId ?? row.user_id),
    roles: [...(row.roles ?? [])],
    createdAt: iso(row.createdAt ?? row.created_at),
    updatedAt: iso(row.updatedAt ?? row.updated_at),
  };
}

function publicInvitation(row) {
  if (!row) return undefined;
  return {
    id: String(row.id),
    organizationId: String(row.organizationId ?? row.organization_id),
    email: row.email,
    roles: [...(row.roles ?? [])],
    expiresAt: iso(row.expiresAt ?? row.expires_at),
    acceptedAt: iso(row.acceptedAt ?? row.accepted_at),
    createdAt: iso(row.createdAt ?? row.created_at),
  };
}

function publicSigningKey(row) {
  if (!row) return undefined;
  return {
    keyId: row.keyId ?? row.key_id,
    provider: row.provider,
    status: row.status,
    algorithm: row.algorithm,
    materialReference: row.materialReference ?? row.material_reference,
    publicJwk: clone(row.publicJwk ?? row.public_jwk),
    activatedAt: iso(row.activatedAt ?? row.activated_at),
    retireAfter: iso(row.retireAfter ?? row.retire_after),
    createdAt: iso(row.createdAt ?? row.created_at),
    updatedAt: iso(row.updatedAt ?? row.updated_at),
  };
}

export function expandCompositeRoles(assigned, roles) {
  const definitions = new Map(roles.map((role) => [role.name, role]));
  const expanded = new Set();
  const visiting = new Set();
  function visit(name) {
    if (expanded.has(name)) return;
    if (visiting.has(name)) throw new Error(`Composite role cycle detected at ${name}`);
    visiting.add(name);
    for (const composite of definitions.get(name)?.composites ?? []) visit(composite);
    visiting.delete(name);
    expanded.add(name);
  }
  for (const role of assigned ?? []) visit(role);
  return [...expanded].sort();
}

export function validateRoleGraph(candidate, roles) {
  const next = roles.filter((role) => role.name !== candidate.name).concat(candidate);
  const names = new Set(next.map((role) => role.name));
  const missing = candidate.composites.filter((name) => !names.has(name));
  if (missing.length) throw Object.assign(new Error(`Unknown composite role: ${missing[0]}`), { code: 'ROLE_COMPOSITE_NOT_FOUND' });
  expandCompositeRoles(next.map((role) => role.name), next);
}

export function applyClaimMappers({ user, organizations = [], mappers = [] }) {
  const claims = {};
  const readPath = (source) => String(source).split('.').reduce((value, part) => value?.[part], user);
  for (const mapper of mappers) {
    const config = mapper.config ?? {};
    const claim = config.claim;
    if (typeof claim !== 'string' || !claim || ['iss', 'sub', 'aud', 'exp', 'iat', 'nonce', 'sid'].includes(claim)) continue;
    let value;
    switch (mapper.mapperType) {
      case 'user-attribute': value = readPath(config.source); break;
      case 'hardcoded': value = clone(config.value); break;
      case 'realm-roles': value = [...(user.roles ?? [])]; break;
      case 'client-roles': value = clone(user.clientRoles ?? {}); break;
      case 'groups': value = [...(user.groups ?? [])]; break;
      case 'organization': value = organizations.map((organization) => ({
        id: organization.id,
        alias: organization.alias,
        roles: organization.roles,
      })); break;
      default: value = undefined;
    }
    if (value !== undefined) claims[claim] = value;
  }
  return claims;
}

async function withPostgresAdvisoryTransaction(pool, namespace, operation) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const namespaces = [...new Set(Array.isArray(namespace) ? namespace : [namespace])].sort();
    for (const lock of namespaces) {
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [lock]);
    }
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

export class MemoryManagementStore {
  constructor(realms = []) {
    this.realms = new Map();
    this.roles = new Map();
    this.clientRoleDefinitions = new Map();
    this.groups = new Map();
    this.clientScopes = new Map();
    this.scopeAssignments = new Map();
    this.claimMappers = new Map();
    this.flows = new Map();
    this.organizations = new Map();
    this.organizationDomains = new Map();
    this.memberships = new Map();
    this.invitations = new Map();
    this.signingKeys = new Map();
    for (const name of realms) {
      const timestamp = nowIso();
      this.realms.set(name, { name, displayName: name === 'master' ? 'Master' : name, enabled: true, settings: {}, createdAt: timestamp, updatedAt: timestamp });
    }
  }

  async listRealms() { return [...this.realms.values()].map(publicRealm).sort((a, b) => a.name.localeCompare(b.name)); }
  async findRealm(name) { return publicRealm(this.realms.get(name)); }
  async updateRealm(name, patch) {
    const current = this.realms.get(name);
    if (!current) return undefined;
    const next = { ...current, ...clone(patch), name, updatedAt: nowIso() };
    this.realms.set(name, next);
    return publicRealm(next);
  }

  async listRoles(realm) {
    return [...this.roles.entries()].filter(([entry]) => entry.startsWith(`${realm}\u0000`)).map(([, role]) => publicRole(role)).sort((a, b) => a.name.localeCompare(b.name));
  }

  async putRole(realm, input) {
    const roles = [...this.roles.entries()]
      .filter(([entry]) => entry.startsWith(`${realm}\u0000`))
      .map(([, role]) => publicRole(role));
    validateRoleGraph(input, roles);
    const existing = this.roles.get(key(realm, input.name));
    const timestamp = nowIso();
    const role = { ...clone(input), createdAt: existing?.createdAt ?? timestamp, updatedAt: timestamp };
    this.roles.set(key(realm, input.name), role);
    return publicRole(role);
  }

  async deleteRole(realm, name) {
    const deleted = this.roles.delete(key(realm, name));
    if (!deleted) return false;
    for (const [entry, role] of this.roles) {
      if (entry.startsWith(`${realm}\u0000`) && role.composites.includes(name)) {
        this.roles.set(entry, { ...role, composites: role.composites.filter((item) => item !== name), updatedAt: nowIso() });
      }
    }
    for (const [entry, group] of this.groups) {
      if (entry.startsWith(`${realm}\u0000`) && group.roles.includes(name)) {
        this.groups.set(entry, { ...group, roles: group.roles.filter((item) => item !== name), updatedAt: nowIso() });
      }
    }
    return true;
  }

  async listClientRoles(realm, clientId) {
    return [...this.clientRoleDefinitions.entries()]
      .filter(([entry]) => entry.startsWith(`${realm}\u0000${clientId}\u0000`))
      .map(([, definition]) => publicClientRole(definition))
      .sort((left, right) => left.name.localeCompare(right.name));
  }

  async putClientRole(realm, clientId, input) {
    const definitions = [...this.clientRoleDefinitions.entries()]
      .filter(([entry]) => entry.startsWith(`${realm}\u0000${clientId}\u0000`))
      .map(([, definition]) => publicClientRole(definition));
    validateRoleGraph(input, definitions);
    const entry = key(realm, clientId, input.name);
    const existing = this.clientRoleDefinitions.get(entry);
    const timestamp = nowIso();
    const definition = {
      ...clone(input), clientId,
      createdAt: existing?.createdAt ?? timestamp, updatedAt: timestamp,
    };
    this.clientRoleDefinitions.set(entry, definition);
    return publicClientRole(definition);
  }

  async deleteClientRole(realm, clientId, name) {
    const deleted = this.clientRoleDefinitions.delete(key(realm, clientId, name));
    if (!deleted) return false;
    for (const [entry, definition] of this.clientRoleDefinitions) {
      if (entry.startsWith(`${realm}\u0000${clientId}\u0000`) && definition.composites.includes(name)) {
        this.clientRoleDefinitions.set(entry, {
          ...definition,
          composites: definition.composites.filter((item) => item !== name),
          updatedAt: nowIso(),
        });
      }
    }
    return true;
  }

  async listGroups(realm) {
    const groups = [...this.groups.entries()].filter(([entry]) => entry.startsWith(`${realm}\u0000`)).map(([, group]) => publicGroup(group));
    return groupPaths(groups).sort((a, b) => a.path.localeCompare(b.path));
  }

  async createGroup(realm, input) {
    const id = input.id ?? randomUUID();
    const existing = groupPaths([...this.groups.entries()]
      .filter(([entry]) => entry.startsWith(`${realm}\u0000`))
      .map(([, group]) => publicGroup(group)));
    if (input.parentId && !existing.some((group) => group.id === input.parentId)) throw Object.assign(new Error('Parent group not found'), { code: 'GROUP_PARENT_NOT_FOUND' });
    if (existing.some((group) => group.parentId === (input.parentId ?? null) && group.name.toLowerCase() === input.name.toLowerCase())) throw Object.assign(new Error('A sibling group already uses this name'), { code: 'GROUP_EXISTS' });
    const timestamp = nowIso();
    const group = { ...clone(input), id, parentId: input.parentId ?? null, createdAt: timestamp, updatedAt: timestamp };
    this.groups.set(key(realm, id), group);
    return (await this.listGroups(realm)).find((item) => item.id === id);
  }

  async updateGroup(realm, id, patch) {
    const current = this.groups.get(key(realm, id));
    if (!current) return undefined;
    const groups = groupPaths([...this.groups.entries()]
      .filter(([entry]) => entry.startsWith(`${realm}\u0000`))
      .map(([, group]) => publicGroup(group)));
    const parentId = patch.parentId === undefined ? current.parentId : patch.parentId;
    if (parentId === id) throw Object.assign(new Error('A group cannot be its own parent'), { code: 'GROUP_CYCLE' });
    if (parentId && !groups.some((group) => group.id === parentId)) throw Object.assign(new Error('Parent group not found'), { code: 'GROUP_PARENT_NOT_FOUND' });
    const descendants = new Set();
    const queue = [id];
    while (queue.length) {
      const parent = queue.shift();
      for (const group of groups.filter((candidate) => candidate.parentId === parent)) { descendants.add(group.id); queue.push(group.id); }
    }
    if (parentId && descendants.has(parentId)) throw Object.assign(new Error('Group hierarchy would contain a cycle'), { code: 'GROUP_CYCLE' });
    const name = patch.name ?? current.name;
    if (groups.some((group) => group.id !== id && group.parentId === (parentId ?? null) && group.name.toLowerCase() === name.toLowerCase())) throw Object.assign(new Error('A sibling group already uses this name'), { code: 'GROUP_EXISTS' });
    this.groups.set(key(realm, id), { ...current, ...clone(patch), parentId: parentId ?? null, updatedAt: nowIso() });
    return (await this.listGroups(realm)).find((group) => group.id === id);
  }

  async deleteGroup(realm, id) {
    if ([...this.groups.entries()].some(([entry, group]) => (
      entry.startsWith(`${realm}\u0000`) && group.parentId === id
    ))) throw Object.assign(new Error('Move or delete child groups first'), { code: 'GROUP_NOT_EMPTY' });
    return this.groups.delete(key(realm, id));
  }

  async listClientScopes(realm) { return [...this.clientScopes.entries()].filter(([entry]) => entry.startsWith(`${realm}\u0000`)).map(([, item]) => publicClientScope(item)).sort((a, b) => a.name.localeCompare(b.name)); }
  async createClientScope(realm, input) {
    if ([...this.clientScopes.entries()].some(([entry, scope]) => (
      entry.startsWith(`${realm}\u0000`) && scope.name.toLowerCase() === input.name.toLowerCase()
    ))) throw Object.assign(new Error('Client scope already exists'), { code: 'CLIENT_SCOPE_EXISTS' });
    const timestamp = nowIso();
    const scope = { ...clone(input), id: input.id ?? randomUUID(), createdAt: timestamp, updatedAt: timestamp };
    this.clientScopes.set(key(realm, scope.id), scope);
    return publicClientScope(scope);
  }
  async updateClientScope(realm, id, patch) {
    const current = this.clientScopes.get(key(realm, id));
    if (!current) return undefined;
    const next = { ...current, ...clone(patch), id, updatedAt: nowIso() };
    if ([...this.clientScopes.entries()].some(([entry, scope]) => (
      entry.startsWith(`${realm}\u0000`) && scope.id !== id
        && scope.name.toLowerCase() === next.name.toLowerCase()
    ))) throw Object.assign(new Error('Client scope already exists'), { code: 'CLIENT_SCOPE_EXISTS' });
    this.clientScopes.set(key(realm, id), next);
    return publicClientScope(next);
  }
  async deleteClientScope(realm, id) {
    const deleted = this.clientScopes.delete(key(realm, id));
    if (deleted) {
      for (const entry of this.scopeAssignments.keys()) if (entry.startsWith(`${realm}\u0000`) && entry.endsWith(`\u0000${id}`)) this.scopeAssignments.delete(entry);
      for (const [entry, mapper] of this.claimMappers) if (entry.startsWith(`${realm}\u0000`) && mapper.ownerType === 'client-scope' && mapper.ownerId === id) this.claimMappers.delete(entry);
    }
    return deleted;
  }
  async setClientScopeAssignment(realm, clientId, scopeId, assignmentType) {
    if (!this.clientScopes.has(key(realm, scopeId))) return false;
    this.scopeAssignments.set(key(realm, clientId, scopeId), { clientId, scopeId, assignmentType });
    return true;
  }
  async deleteClientScopeAssignment(realm, clientId, scopeId) { return this.scopeAssignments.delete(key(realm, clientId, scopeId)); }
  async listClientScopeAssignments(realm, clientId) { return [...this.scopeAssignments.entries()].filter(([entry]) => entry.startsWith(`${realm}\u0000${clientId}\u0000`)).map(([, item]) => clone(item)); }

  async listClaimMappers(realm, ownerType, ownerId) { return [...this.claimMappers.entries()].filter(([entry, mapper]) => entry.startsWith(`${realm}\u0000`) && (!ownerType || (mapper.ownerType === ownerType && mapper.ownerId === ownerId))).map(([, mapper]) => publicMapper(mapper)).sort((a, b) => a.name.localeCompare(b.name)); }
  async createClaimMapper(realm, input) {
    if ([...this.claimMappers.entries()].some(([entry, mapper]) => (
      entry.startsWith(`${realm}\u0000`) && mapper.ownerType === input.ownerType
        && mapper.ownerId === input.ownerId && mapper.name.toLowerCase() === input.name.toLowerCase()
    ))) throw Object.assign(new Error('Claim mapper already exists'), { code: 'CLAIM_MAPPER_EXISTS' });
    const timestamp = nowIso();
    const mapper = { ...clone(input), id: input.id ?? randomUUID(), createdAt: timestamp, updatedAt: timestamp };
    this.claimMappers.set(key(realm, mapper.id), mapper);
    return publicMapper(mapper);
  }
  async updateClaimMapper(realm, id, patch) {
    const current = this.claimMappers.get(key(realm, id));
    if (!current) return undefined;
    const next = { ...current, ...clone(patch), id, updatedAt: nowIso() };
    if ([...this.claimMappers.entries()].some(([entry, mapper]) => (
      entry.startsWith(`${realm}\u0000`) && mapper.ownerType === current.ownerType
        && mapper.ownerId === current.ownerId && mapper.id !== id
        && mapper.name.toLowerCase() === next.name.toLowerCase()
    ))) throw Object.assign(new Error('Claim mapper already exists'), { code: 'CLAIM_MAPPER_EXISTS' });
    this.claimMappers.set(key(realm, id), next);
    return publicMapper(next);
  }
  async deleteClaimMapper(realm, id) { return this.claimMappers.delete(key(realm, id)); }
  async deleteClientPolicy(realm, clientId) {
    let assignments = 0;
    let claimMappers = 0;
    let clientRoles = 0;
    let authenticationFlows = 0;
    for (const entry of this.scopeAssignments.keys()) {
      if (entry.startsWith(`${realm}\u0000${clientId}\u0000`)) {
        this.scopeAssignments.delete(entry);
        assignments += 1;
      }
    }
    for (const [entry, mapper] of this.claimMappers) {
      if (entry.startsWith(`${realm}\u0000`) && mapper.ownerType === 'client' && mapper.ownerId === clientId) {
        this.claimMappers.delete(entry);
        claimMappers += 1;
      }
    }
    for (const entry of this.clientRoleDefinitions.keys()) {
      if (entry.startsWith(`${realm}\u0000${clientId}\u0000`)) {
        this.clientRoleDefinitions.delete(entry);
        clientRoles += 1;
      }
    }
    for (const [entry, flow] of this.flows) {
      if (!entry.startsWith(`${realm}\u0000`) || !flow.clientIds.includes(clientId)) continue;
      if (flow.clientIds.length === 1) this.flows.delete(entry);
      else this.flows.set(entry, {
        ...flow, clientIds: flow.clientIds.filter((id) => id !== clientId), updatedAt: nowIso(),
      });
      authenticationFlows += 1;
    }
    return { assignments, claimMappers, clientRoles, authenticationFlows };
  }
  async effectiveClaimMappers(realm, clientId, grantedScopes = []) {
    const direct = await this.listClaimMappers(realm, 'client', clientId);
    const granted = new Set(grantedScopes);
    const scopes = await this.listClientScopes(realm);
    const assignments = (await this.listClientScopeAssignments(realm, clientId)).filter((assignment) => (
      assignment.assignmentType === 'default'
      || granted.has(scopes.find((scope) => scope.id === assignment.scopeId)?.name)
    ));
    const inherited = [];
    for (const assignment of assignments) inherited.push(...await this.listClaimMappers(realm, 'client-scope', assignment.scopeId));
    return [...direct, ...inherited];
  }

  async listAuthenticationFlows(realm) { return [...this.flows.entries()].filter(([entry]) => entry.startsWith(`${realm}\u0000`)).map(([, flow]) => publicFlow(flow)).sort((a, b) => a.priority - b.priority || a.alias.localeCompare(b.alias)); }
  async createAuthenticationFlow(realm, input) {
    assertAuthenticationFlowConfiguration(input.steps);
    if ([...this.flows.entries()].some(([entry, flow]) => (
      entry.startsWith(`${realm}\u0000`) && flow.alias.toLowerCase() === input.alias.toLowerCase()
    ))) throw Object.assign(new Error('Authentication flow already exists'), { code: 'AUTH_FLOW_EXISTS' });
    const timestamp = nowIso();
    const flow = { ...clone(input), id: input.id ?? randomUUID(), createdAt: timestamp, updatedAt: timestamp };
    this.flows.set(key(realm, flow.id), flow);
    return publicFlow(flow);
  }
  async updateAuthenticationFlow(realm, id, patch) {
    const current = this.flows.get(key(realm, id));
    if (!current) return undefined;
    const next = { ...current, ...clone(patch), id, updatedAt: nowIso() };
    assertAuthenticationFlowConfiguration(next.steps);
    if ([...this.flows.entries()].some(([entry, flow]) => (
      entry.startsWith(`${realm}\u0000`) && flow.id !== id
        && flow.alias.toLowerCase() === next.alias.toLowerCase()
    ))) throw Object.assign(new Error('Authentication flow already exists'), { code: 'AUTH_FLOW_EXISTS' });
    this.flows.set(key(realm, id), next);
    return publicFlow(next);
  }
  async deleteAuthenticationFlow(realm, id) { return this.flows.delete(key(realm, id)); }
  async resolveAuthenticationFlow(realm, { clientId, requestedAcrs = [] } = {}) {
    const flows = (await this.listAuthenticationFlows(realm)).filter((flow) => flow.enabled && (!flow.clientIds.length || flow.clientIds.includes(clientId)));
    if (!requestedAcrs.length) return clone(flows[0]);
    for (const acr of requestedAcrs) {
      const flow = flows.find((candidate) => candidate.acr === acr);
      if (flow) return clone(flow);
    }
    return undefined;
  }

  async listOrganizations(realm) { return [...this.organizations.entries()].filter(([entry]) => entry.startsWith(`${realm}\u0000`)).map(([, organization]) => publicOrganization(organization, this.organizationDomains.get(key(realm, organization.id)) ?? [])).sort((a, b) => a.name.localeCompare(b.name)); }
  async findOrganization(realm, idOrAlias) {
    const organizations = await this.listOrganizations(realm);
    return organizations.find((organization) => organization.id === idOrAlias)
      ?? organizations.find((organization) => organization.alias === idOrAlias);
  }
  async createOrganization(realm, input) {
    const organizations = [...this.organizations.entries()]
      .filter(([entry]) => entry.startsWith(`${realm}\u0000`))
      .map(([, organization]) => publicOrganization(
        organization, this.organizationDomains.get(key(realm, organization.id)) ?? [],
      ));
    if (organizations.some((organization) => organization.alias.toLowerCase() === input.alias.toLowerCase())) throw Object.assign(new Error('Organization alias already exists'), { code: 'ORGANIZATION_EXISTS' });
    const claimed = new Set(organizations.flatMap((organization) => organization.domains.map(({ domain }) => domain)));
    if (input.domains.some(({ domain }) => claimed.has(domain))) throw Object.assign(new Error('Organization domain already exists'), { code: 'ORGANIZATION_DOMAIN_EXISTS' });
    const timestamp = nowIso();
    const organization = { ...clone(input), domains: undefined, id: input.id ?? randomUUID(), createdAt: timestamp, updatedAt: timestamp };
    this.organizations.set(key(realm, organization.id), organization);
    this.organizationDomains.set(key(realm, organization.id), clone(input.domains));
    return publicOrganization(organization, input.domains);
  }
  async updateOrganization(realm, id, patch) {
    const current = this.organizations.get(key(realm, id));
    if (!current) return undefined;
    const organizations = [...this.organizations.entries()]
      .filter(([entry, organization]) => entry.startsWith(`${realm}\u0000`) && organization.id !== id)
      .map(([, organization]) => publicOrganization(
        organization, this.organizationDomains.get(key(realm, organization.id)) ?? [],
      ));
    const alias = patch.alias ?? current.alias;
    if (organizations.some((organization) => organization.alias.toLowerCase() === alias.toLowerCase())) {
      throw Object.assign(new Error('Organization alias already exists'), { code: 'ORGANIZATION_EXISTS' });
    }
    const domains = patch.domains ?? this.organizationDomains.get(key(realm, id)) ?? [];
    const normalizedDomains = domains.map(({ domain }) => domain.toLowerCase());
    if (new Set(normalizedDomains).size !== normalizedDomains.length) {
      throw Object.assign(new Error('Organization domain already exists'), { code: 'ORGANIZATION_DOMAIN_EXISTS' });
    }
    const claimed = new Set(organizations.flatMap((organization) => (
      organization.domains.map(({ domain }) => domain.toLowerCase())
    )));
    if (normalizedDomains.some((domain) => claimed.has(domain))) {
      throw Object.assign(new Error('Organization domain already exists'), { code: 'ORGANIZATION_DOMAIN_EXISTS' });
    }
    const next = { ...current, ...clone(patch), domains: undefined, id, updatedAt: nowIso() };
    this.organizations.set(key(realm, id), next);
    if (patch.domains) this.organizationDomains.set(key(realm, id), clone(patch.domains));
    return publicOrganization(next, this.organizationDomains.get(key(realm, id)) ?? []);
  }
  async deleteOrganization(realm, id) {
    const deleted = this.organizations.delete(key(realm, id));
    if (!deleted) return false;
    this.organizationDomains.delete(key(realm, id));
    for (const entry of [...this.memberships.keys(), ...this.invitations.keys()]) if (entry.startsWith(`${realm}\u0000${id}\u0000`)) { this.memberships.delete(entry); this.invitations.delete(entry); }
    return true;
  }
  async listOrganizationMemberships(realm, organizationId) { return [...this.memberships.entries()].filter(([entry]) => entry.startsWith(`${realm}\u0000${organizationId}\u0000`)).map(([, membership]) => publicMembership(membership)); }
  async upsertOrganizationMembership(realm, organizationId, userId, roles = []) {
    if (!this.organizations.has(key(realm, organizationId))) return undefined;
    const existing = this.memberships.get(key(realm, organizationId, userId));
    const timestamp = nowIso();
    const membership = { organizationId, userId, roles: [...roles], createdAt: existing?.createdAt ?? timestamp, updatedAt: timestamp };
    this.memberships.set(key(realm, organizationId, userId), membership);
    return publicMembership(membership);
  }
  async deleteOrganizationMembership(realm, organizationId, userId) { return this.memberships.delete(key(realm, organizationId, userId)); }
  async listUserOrganizations(realm, userId) {
    const result = [];
    for (const membership of await this.listOrganizationMembershipsForUser(realm, userId)) {
      const organization = await this.findOrganization(realm, membership.organizationId);
      if (organization?.enabled) result.push({ ...organization, roles: membership.roles });
    }
    return result;
  }
  async listOrganizationMembershipsForUser(realm, userId) { return [...this.memberships.entries()].filter(([entry, membership]) => entry.startsWith(`${realm}\u0000`) && membership.userId === userId).map(([, membership]) => publicMembership(membership)); }
  async createOrganizationInvitation(realm, input) {
    if (!this.organizations.has(key(realm, input.organizationId))) return undefined;
    const timestamp = nowIso();
    const invitation = { ...clone(input), id: input.id ?? randomUUID(), createdAt: timestamp, acceptedAt: null };
    this.invitations.set(key(realm, input.organizationId, invitation.id), invitation);
    return publicInvitation(invitation);
  }
  async listOrganizationInvitations(realm, organizationId) { return [...this.invitations.entries()].filter(([entry]) => entry.startsWith(`${realm}\u0000${organizationId}\u0000`)).map(([, invitation]) => publicInvitation(invitation)); }
  async deleteOrganizationInvitation(realm, organizationId, invitationId) {
    return this.invitations.delete(key(realm, organizationId, invitationId));
  }
  async consumeOrganizationInvitation(realm, tokenDigest, user) {
    const match = [...this.invitations.entries()].find(([entry, invitation]) => entry.startsWith(`${realm}\u0000`) && invitation.tokenDigest === tokenDigest && !invitation.acceptedAt && new Date(invitation.expiresAt).getTime() > Date.now());
    if (!match || match[1].email.toLowerCase() !== user.email.toLowerCase()) return undefined;
    const [entry, invitation] = match;
    if (!this.organizations.get(key(realm, invitation.organizationId))?.enabled) return undefined;
    const previous = this.memberships.get(key(realm, invitation.organizationId, user.id));
    invitation.acceptedAt = nowIso();
    this.invitations.set(entry, invitation);
    await this.upsertOrganizationMembership(realm, invitation.organizationId, user.id, invitation.roles);
    const accepted = publicInvitation(invitation);
    Object.defineProperty(accepted, organizationInvitationPreviousRoles, {
      value: previous ? [...previous.roles] : undefined,
    });
    return accepted;
  }
  async rollbackOrganizationInvitationAcceptance(
    realm,
    organizationId,
    invitationId,
    userId,
    { previousRoles, restoreMembership = true } = {},
  ) {
    const invitationKey = key(realm, organizationId, invitationId);
    const invitation = this.invitations.get(invitationKey);
    if (!invitation?.acceptedAt) return false;
    this.invitations.set(invitationKey, { ...invitation, acceptedAt: null });
    if (restoreMembership && previousRoles !== undefined) {
      await this.upsertOrganizationMembership(realm, organizationId, userId, previousRoles);
    } else {
      await this.deleteOrganizationMembership(realm, organizationId, userId);
    }
    return true;
  }

  async listSigningKeys(realm) { return [...this.signingKeys.entries()].filter(([entry]) => entry.startsWith(`${realm}\u0000`)).map(([, signingKey]) => publicSigningKey(signingKey)).sort((a, b) => a.createdAt.localeCompare(b.createdAt)); }
  async putSigningKey(realm, input) {
    const existing = this.signingKeys.get(key(realm, input.keyId));
    if (input.status === 'active') for (const [entry, signingKey] of this.signingKeys) if (entry.startsWith(`${realm}\u0000`) && signingKey.status === 'active' && signingKey.keyId !== input.keyId) this.signingKeys.set(entry, { ...signingKey, status: 'retiring', retireAfter: input.retireAfter ?? null, updatedAt: nowIso() });
    const timestamp = nowIso();
    const signingKey = { ...clone(input), createdAt: existing?.createdAt ?? timestamp, updatedAt: timestamp };
    this.signingKeys.set(key(realm, input.keyId), signingKey);
    return publicSigningKey(signingKey);
  }
}

export class PostgresManagementStore {
  constructor(pool) {
    if (!pool?.query) throw new TypeError('PostgresManagementStore requires a PostgreSQL queryable');
    this.pool = pool;
  }

  async listRealms() { return (await this.pool.query('SELECT * FROM realms ORDER BY name')).rows.map(publicRealm); }
  async findRealm(name) { return publicRealm((await this.pool.query('SELECT * FROM realms WHERE name=$1', [name])).rows[0]); }
  async updateRealm(name, patch) {
    const result = await this.pool.query(
      `UPDATE realms SET display_name=COALESCE($2, display_name), enabled=COALESCE($3, enabled),
         settings=COALESCE($4::jsonb, settings) WHERE name=$1 RETURNING *`,
      [name, patch.displayName ?? null, patch.enabled ?? null, patch.settings === undefined ? null : patch.settings],
    );
    return publicRealm(result.rows[0]);
  }
  async listRoles(realm) { return (await this.pool.query('SELECT * FROM realm_roles WHERE realm_name=$1 ORDER BY name', [realm])).rows.map(publicRole); }
  async putRole(realm, input) {
    return withPostgresAdvisoryTransaction(this.pool, `authme:realm-roles:${realm}`, async (client) => {
      const roles = (await client.query('SELECT * FROM realm_roles WHERE realm_name=$1 ORDER BY name', [realm])).rows.map(publicRole);
      validateRoleGraph(input, roles);
      const result = await client.query(
        `INSERT INTO realm_roles (realm_name,name,description,composites,attributes) VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (realm_name,name) DO UPDATE SET description=EXCLUDED.description, composites=EXCLUDED.composites, attributes=EXCLUDED.attributes
         RETURNING *`, [realm, input.name, input.description, input.composites, input.attributes],
      );
      return publicRole(result.rows[0]);
    });
  }
  async deleteRole(realm, name) {
    return withPostgresAdvisoryTransaction(this.pool, `authme:realm-roles:${realm}`, async (client) => {
      const result = await client.query(
        `WITH deleted AS (DELETE FROM realm_roles WHERE realm_name=$1 AND name=$2 RETURNING name),
         roles_updated AS (UPDATE realm_roles SET composites=array_remove(composites,$2) WHERE realm_name=$1 AND $2=ANY(composites)),
         groups_updated AS (UPDATE realm_groups SET roles=array_remove(roles,$2) WHERE realm_name=$1 AND $2=ANY(roles)),
         users_updated AS (UPDATE users SET roles=array_remove(roles,$2) WHERE realm_name=$1 AND $2=ANY(roles))
         SELECT name FROM deleted`, [realm, name],
      );
      return result.rowCount === 1;
    });
  }
  async listClientRoles(realm, clientId) { return (await this.pool.query('SELECT * FROM client_roles WHERE realm_name=$1 AND client_id=$2 ORDER BY name', [realm, clientId])).rows.map(publicClientRole); }
  async putClientRole(realm, clientId, input) {
    return withPostgresAdvisoryTransaction(this.pool, `authme:client-roles:${realm}:${clientId}`, async (client) => {
      const definitions = (await client.query(
        'SELECT * FROM client_roles WHERE realm_name=$1 AND client_id=$2 ORDER BY name', [realm, clientId],
      )).rows.map(publicClientRole);
      validateRoleGraph(input, definitions);
      return publicClientRole((await client.query(
        `INSERT INTO client_roles (realm_name,client_id,name,description,composites,attributes) VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (realm_name,client_id,name) DO UPDATE SET description=EXCLUDED.description,composites=EXCLUDED.composites,attributes=EXCLUDED.attributes RETURNING *`,
        [realm, clientId, input.name, input.description, input.composites, input.attributes],
      )).rows[0]);
    });
  }
  async deleteClientRole(realm, clientId, name) {
    return withPostgresAdvisoryTransaction(this.pool, `authme:client-roles:${realm}:${clientId}`, async (client) => {
      const result = await client.query(
        `WITH deleted AS (DELETE FROM client_roles WHERE realm_name=$1 AND client_id=$2 AND name=$3 RETURNING name),
         updated AS (UPDATE client_roles SET composites=array_remove(composites,$3) WHERE realm_name=$1 AND client_id=$2 AND $3=ANY(composites))
         SELECT name FROM deleted`,
        [realm, clientId, name],
      );
      return result.rowCount === 1;
    });
  }
  async listGroups(realm) { return groupPaths((await this.pool.query('SELECT * FROM realm_groups WHERE realm_name=$1', [realm])).rows.map(publicGroup)).sort((a, b) => a.path.localeCompare(b.path)); }
  async createGroup(realm, input) {
    return withPostgresAdvisoryTransaction(this.pool, `authme:groups:${realm}`, async (client) => {
      const result = await client.query(
        `INSERT INTO realm_groups (realm_name,id,name,parent_id,roles,attributes) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
        [realm, input.id ?? randomUUID(), input.name, input.parentId ?? null, input.roles, input.attributes],
      );
      const groups = groupPaths((await client.query(
        'SELECT * FROM realm_groups WHERE realm_name=$1', [realm],
      )).rows.map(publicGroup));
      return groups.find((group) => group.id === String(result.rows[0].id));
    });
  }
  async updateGroup(realm, id, patch) {
    return withPostgresAdvisoryTransaction(this.pool, `authme:groups:${realm}`, async (client) => {
      const rows = (await client.query('SELECT * FROM realm_groups WHERE realm_name=$1', [realm])).rows;
      const current = rows.find((row) => String(row.id) === id);
      if (!current) return undefined;
      const groups = groupPaths(rows.map(publicGroup));
      const parentId = Object.hasOwn(patch, 'parentId') ? patch.parentId : current.parent_id && String(current.parent_id);
      if (parentId) {
        if (!groups.some((group) => group.id === parentId)) {
          throw Object.assign(new Error('Parent group not found'), { code: 'GROUP_PARENT_NOT_FOUND' });
        }
        const descendants = new Set();
        const queue = [id];
        while (queue.length) {
          const parent = queue.shift();
          for (const group of groups.filter((candidate) => candidate.parentId === parent)) {
            descendants.add(group.id);
            queue.push(group.id);
          }
        }
        if (parentId === id || descendants.has(parentId)) {
          throw Object.assign(new Error('Group hierarchy would contain a cycle'), { code: 'GROUP_CYCLE' });
        }
      }
      const result = await client.query(
        `UPDATE realm_groups SET name=COALESCE($3,name), parent_id=CASE WHEN $4 THEN $5::uuid ELSE parent_id END,
           roles=COALESCE($6::text[],roles), attributes=COALESCE($7::jsonb,attributes)
         WHERE realm_name=$1 AND id=$2 RETURNING *`,
        [realm, id, patch.name ?? null, Object.hasOwn(patch, 'parentId'), patch.parentId ?? null, patch.roles ?? null, patch.attributes ?? null],
      );
      const updated = groupPaths((await client.query(
        'SELECT * FROM realm_groups WHERE realm_name=$1', [realm],
      )).rows.map(publicGroup));
      return updated.find((group) => group.id === String(result.rows[0].id));
    });
  }
  async deleteGroup(realm, id) {
    return withPostgresAdvisoryTransaction(this.pool, `authme:groups:${realm}`, async (client) => (
      (await client.query('DELETE FROM realm_groups WHERE realm_name=$1 AND id=$2', [realm, id])).rowCount === 1
    ));
  }
  async listClientScopes(realm) { return (await this.pool.query('SELECT * FROM client_scopes WHERE realm_name=$1 ORDER BY name', [realm])).rows.map(publicClientScope); }
  async createClientScope(realm, input) { return publicClientScope((await this.pool.query('INSERT INTO client_scopes (realm_name,id,name,description,protocol,attributes) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *', [realm, input.id ?? randomUUID(), input.name, input.description, input.protocol, input.attributes])).rows[0]); }
  async updateClientScope(realm, id, patch) { return publicClientScope((await this.pool.query('UPDATE client_scopes SET name=COALESCE($3,name), description=COALESCE($4,description), attributes=COALESCE($5::jsonb,attributes) WHERE realm_name=$1 AND id=$2 RETURNING *', [realm, id, patch.name ?? null, patch.description ?? null, patch.attributes ?? null])).rows[0]); }
  async deleteClientScope(realm, id) {
    return withPostgresAdvisoryTransaction(this.pool, `authme:client-scope:${realm}:${id}`, async (client) => {
      const result = await client.query(
        `WITH deleted_scope AS (
           DELETE FROM client_scopes WHERE realm_name=$1 AND id=$2 RETURNING id
         ), deleted_mappers AS (
           DELETE FROM claim_mappers
           WHERE realm_name=$1 AND owner_type='client-scope' AND owner_id=$2::text
             AND EXISTS (SELECT 1 FROM deleted_scope)
         ) SELECT id FROM deleted_scope`,
        [realm, id],
      );
      return result.rowCount === 1;
    });
  }
  async setClientScopeAssignment(realm, clientId, scopeId, assignmentType) {
    return withPostgresAdvisoryTransaction(this.pool, [
      `authme:client-roles:${realm}:${clientId}`,
      `authme:client-scope:${realm}:${scopeId}`,
    ], async (client) => (await client.query(
      `INSERT INTO client_scope_assignments (realm_name,client_id,scope_id,assignment_type)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (realm_name,client_id,scope_id)
       DO UPDATE SET assignment_type=EXCLUDED.assignment_type`,
      [realm, clientId, scopeId, assignmentType],
    )).rowCount === 1);
  }
  async deleteClientScopeAssignment(realm, clientId, scopeId) { return (await this.pool.query('DELETE FROM client_scope_assignments WHERE realm_name=$1 AND client_id=$2 AND scope_id=$3', [realm, clientId, scopeId])).rowCount === 1; }
  async listClientScopeAssignments(realm, clientId) { return (await this.pool.query('SELECT client_id AS "clientId", scope_id AS "scopeId", assignment_type AS "assignmentType" FROM client_scope_assignments WHERE realm_name=$1 AND client_id=$2 ORDER BY assignment_type,scope_id', [realm, clientId])).rows; }
  async listClaimMappers(realm, ownerType, ownerId) {
    const result = ownerType ? await this.pool.query('SELECT * FROM claim_mappers WHERE realm_name=$1 AND owner_type=$2 AND owner_id=$3 ORDER BY name', [realm, ownerType, ownerId]) : await this.pool.query('SELECT * FROM claim_mappers WHERE realm_name=$1 ORDER BY owner_type,owner_id,name', [realm]);
    return result.rows.map(publicMapper);
  }
  async createClaimMapper(realm, input) {
    const namespace = input.ownerType === 'client'
      ? `authme:client-roles:${realm}:${input.ownerId}`
      : `authme:client-scope:${realm}:${input.ownerId}`;
    return withPostgresAdvisoryTransaction(this.pool, namespace, async (client) => publicMapper((await client.query(
      `INSERT INTO claim_mappers (realm_name,id,owner_type,owner_id,name,mapper_type,config)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [realm, input.id ?? randomUUID(), input.ownerType, input.ownerId, input.name, input.mapperType, input.config],
    )).rows[0]));
  }
  async updateClaimMapper(realm, id, patch) {
    const current = (await this.pool.query(
      'SELECT owner_type,owner_id FROM claim_mappers WHERE realm_name=$1 AND id=$2', [realm, id],
    )).rows[0];
    if (!current) return undefined;
    const namespace = current.owner_type === 'client'
      ? `authme:client-roles:${realm}:${current.owner_id}`
      : `authme:client-scope:${realm}:${current.owner_id}`;
    return withPostgresAdvisoryTransaction(this.pool, namespace, async (client) => publicMapper((await client.query(
      `UPDATE claim_mappers SET name=COALESCE($3,name), mapper_type=COALESCE($4,mapper_type),
         config=COALESCE($5::jsonb,config) WHERE realm_name=$1 AND id=$2 RETURNING *`,
      [realm, id, patch.name ?? null, patch.mapperType ?? null, patch.config ?? null],
    )).rows[0]));
  }
  async deleteClaimMapper(realm, id) { return (await this.pool.query('DELETE FROM claim_mappers WHERE realm_name=$1 AND id=$2', [realm, id])).rowCount === 1; }
  async deleteClientPolicy(realm, clientId) {
    return withPostgresAdvisoryTransaction(this.pool, `authme:client-roles:${realm}:${clientId}`, async (client) => {
      const result = await client.query(
        `WITH deleted_assignments AS (
           DELETE FROM client_scope_assignments WHERE realm_name=$1 AND client_id=$2 RETURNING 1
         ), deleted_mappers AS (
           DELETE FROM claim_mappers WHERE realm_name=$1 AND owner_type='client' AND owner_id=$2 RETURNING 1
         ), deleted_roles AS (
           DELETE FROM client_roles WHERE realm_name=$1 AND client_id=$2 RETURNING 1
         ), updated_flows AS (
           UPDATE authentication_flows SET client_ids=array_remove(client_ids,$2)
           WHERE realm_name=$1 AND $2=ANY(client_ids) AND cardinality(client_ids)>1 RETURNING 1
         ), deleted_flows AS (
           DELETE FROM authentication_flows
           WHERE realm_name=$1 AND $2=ANY(client_ids) AND cardinality(client_ids)=1 RETURNING 1
         )
         SELECT (SELECT count(*)::integer FROM deleted_assignments) AS assignments,
                (SELECT count(*)::integer FROM deleted_mappers) AS claim_mappers,
                (SELECT count(*)::integer FROM deleted_roles) AS client_roles,
                (SELECT count(*)::integer FROM updated_flows)
                  + (SELECT count(*)::integer FROM deleted_flows) AS authentication_flows`,
        [realm, clientId],
      );
      return {
        assignments: result.rows[0].assignments,
        claimMappers: result.rows[0].claim_mappers,
        clientRoles: result.rows[0].client_roles,
        authenticationFlows: result.rows[0].authentication_flows,
      };
    });
  }
  async effectiveClaimMappers(realm, clientId, grantedScopes = []) { return (await this.pool.query(`SELECT DISTINCT m.* FROM claim_mappers m LEFT JOIN client_scope_assignments a ON a.realm_name=m.realm_name AND m.owner_type='client-scope' AND m.owner_id=a.scope_id::text LEFT JOIN client_scopes s ON s.realm_name=a.realm_name AND s.id=a.scope_id WHERE m.realm_name=$1 AND ((m.owner_type='client' AND m.owner_id=$2) OR (a.client_id=$2 AND (a.assignment_type='default' OR s.name=ANY($3::text[])))) ORDER BY m.name`, [realm, clientId, [...grantedScopes]])).rows.map(publicMapper); }
  async listAuthenticationFlows(realm) { return (await this.pool.query('SELECT * FROM authentication_flows WHERE realm_name=$1 ORDER BY priority,alias', [realm])).rows.map(publicFlow); }
  async createAuthenticationFlow(realm, input) {
    assertAuthenticationFlowConfiguration(input.steps);
    const locks = input.clientIds.map((clientId) => `authme:client-roles:${realm}:${clientId}`);
    return withPostgresAdvisoryTransaction(this.pool, locks, async (client) => publicFlow((await client.query(
      `INSERT INTO authentication_flows
        (realm_name,id,alias,description,enabled,priority,client_ids,acr,max_age_seconds,steps)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb) RETURNING *`,
      [realm, input.id ?? randomUUID(), input.alias, input.description, input.enabled, input.priority,
        input.clientIds, input.acr, input.maxAgeSeconds, JSON.stringify(input.steps)],
    )).rows[0]));
  }
  async updateAuthenticationFlow(realm, id, patch) {
    const current = (await this.pool.query(
      'SELECT * FROM authentication_flows WHERE realm_name=$1 AND id=$2', [realm, id],
    )).rows[0];
    if (!current) return undefined;
    assertAuthenticationFlowConfiguration(patch.steps ?? current.steps);
    const locks = [...new Set([
      ...current.client_ids,
      ...(patch.clientIds ?? current.client_ids),
    ])].map((clientId) => `authme:client-roles:${realm}:${clientId}`);
    return withPostgresAdvisoryTransaction(this.pool, locks, async (client) => publicFlow((await client.query(
      `UPDATE authentication_flows SET alias=COALESCE($3,alias),description=COALESCE($4,description),
         enabled=COALESCE($5,enabled),priority=COALESCE($6,priority),client_ids=COALESCE($7::text[],client_ids),
         acr=COALESCE($8,acr),max_age_seconds=CASE WHEN $9 THEN $10::integer ELSE max_age_seconds END,
         steps=COALESCE($11::jsonb,steps) WHERE realm_name=$1 AND id=$2 RETURNING *`,
      [realm, id, patch.alias ?? null, patch.description ?? null, patch.enabled ?? null,
        patch.priority ?? null, patch.clientIds ?? null, patch.acr ?? null,
        Object.hasOwn(patch, 'maxAgeSeconds'), patch.maxAgeSeconds ?? null,
        patch.steps ? JSON.stringify(patch.steps) : null],
    )).rows[0]));
  }
  async deleteAuthenticationFlow(realm, id) { return (await this.pool.query('DELETE FROM authentication_flows WHERE realm_name=$1 AND id=$2', [realm, id])).rowCount === 1; }
  async resolveAuthenticationFlow(realm, { clientId, requestedAcrs = [] } = {}) {
    const flows = (await this.listAuthenticationFlows(realm)).filter((flow) => flow.enabled && (!flow.clientIds.length || flow.clientIds.includes(clientId)));
    if (!requestedAcrs.length) return clone(flows[0]);
    for (const acr of requestedAcrs) {
      const flow = flows.find((candidate) => candidate.acr === acr);
      if (flow) return clone(flow);
    }
    return undefined;
  }
  async listOrganizations(realm) { const organizations = (await this.pool.query('SELECT * FROM organizations WHERE realm_name=$1 ORDER BY name', [realm])).rows; const domains = (await this.pool.query('SELECT * FROM organization_domains WHERE realm_name=$1 ORDER BY domain', [realm])).rows; return organizations.map((organization) => publicOrganization(organization, domains.filter((domain) => String(domain.organization_id) === String(organization.id)))); }
  async findOrganization(realm, idOrAlias) {
    const organizations = await this.listOrganizations(realm);
    return organizations.find((organization) => organization.id === idOrAlias)
      ?? organizations.find((organization) => organization.alias === idOrAlias);
  }
  async createOrganization(realm, input) {
    const client = await this.pool.connect();
    try { await client.query('BEGIN'); const organization = (await client.query('INSERT INTO organizations (realm_name,id,name,alias,enabled,identity_provider_ids,attributes) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [realm, input.id ?? randomUUID(), input.name, input.alias, input.enabled, input.identityProviderIds, input.attributes])).rows[0]; for (const domain of input.domains) await client.query('INSERT INTO organization_domains (realm_name,organization_id,domain,verified) VALUES ($1,$2,$3,$4)', [realm, organization.id, domain.domain, domain.verified]); await client.query('COMMIT'); return publicOrganization(organization, input.domains); } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; } finally { client.release(); }
  }
  async updateOrganization(realm, id, patch) {
    const client = await this.pool.connect();
    try { await client.query('BEGIN'); const organization = (await client.query('UPDATE organizations SET name=COALESCE($3,name),alias=COALESCE($4,alias),enabled=COALESCE($5,enabled),identity_provider_ids=COALESCE($6::text[],identity_provider_ids),attributes=COALESCE($7::jsonb,attributes) WHERE realm_name=$1 AND id=$2 RETURNING *', [realm, id, patch.name ?? null, patch.alias ?? null, patch.enabled ?? null, patch.identityProviderIds ?? null, patch.attributes ?? null])).rows[0]; if (!organization) { await client.query('ROLLBACK'); return undefined; } if (patch.domains) { await client.query('DELETE FROM organization_domains WHERE realm_name=$1 AND organization_id=$2', [realm, id]); for (const domain of patch.domains) await client.query('INSERT INTO organization_domains (realm_name,organization_id,domain,verified) VALUES ($1,$2,$3,$4)', [realm, id, domain.domain, domain.verified]); } const domains = (await client.query('SELECT * FROM organization_domains WHERE realm_name=$1 AND organization_id=$2 ORDER BY domain', [realm, id])).rows; await client.query('COMMIT'); return publicOrganization(organization, domains); } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; } finally { client.release(); }
  }
  async deleteOrganization(realm, id) { return (await this.pool.query('DELETE FROM organizations WHERE realm_name=$1 AND id=$2', [realm, id])).rowCount === 1; }
  async listOrganizationMemberships(realm, organizationId) { return (await this.pool.query('SELECT * FROM organization_memberships WHERE realm_name=$1 AND organization_id=$2 ORDER BY created_at', [realm, organizationId])).rows.map(publicMembership); }
  async listOrganizationMembershipsForUser(realm, userId) { return (await this.pool.query('SELECT * FROM organization_memberships WHERE realm_name=$1 AND user_id=$2 ORDER BY created_at', [realm, userId])).rows.map(publicMembership); }
  async upsertOrganizationMembership(realm, organizationId, userId, roles = []) { return publicMembership((await this.pool.query(`INSERT INTO organization_memberships (realm_name,organization_id,user_id,roles) VALUES ($1,$2,$3,$4) ON CONFLICT (realm_name,organization_id,user_id) DO UPDATE SET roles=EXCLUDED.roles RETURNING *`, [realm, organizationId, userId, roles])).rows[0]); }
  async deleteOrganizationMembership(realm, organizationId, userId) { return (await this.pool.query('DELETE FROM organization_memberships WHERE realm_name=$1 AND organization_id=$2 AND user_id=$3', [realm, organizationId, userId])).rowCount === 1; }
  async listUserOrganizations(realm, userId) { const memberships = await this.listOrganizationMembershipsForUser(realm, userId); const organizations = await this.listOrganizations(realm); return memberships.flatMap((membership) => { const organization = organizations.find((item) => item.id === membership.organizationId); return organization?.enabled ? [{ ...organization, roles: membership.roles }] : []; }); }
  async createOrganizationInvitation(realm, input) { return publicInvitation((await this.pool.query('INSERT INTO organization_invitations (realm_name,id,organization_id,email,roles,token_digest,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [realm, input.id ?? randomUUID(), input.organizationId, input.email, input.roles, input.tokenDigest, input.expiresAt])).rows[0]); }
  async listOrganizationInvitations(realm, organizationId) { return (await this.pool.query('SELECT * FROM organization_invitations WHERE realm_name=$1 AND organization_id=$2 ORDER BY created_at DESC', [realm, organizationId])).rows.map(publicInvitation); }
  async deleteOrganizationInvitation(realm, organizationId, invitationId) { return (await this.pool.query('DELETE FROM organization_invitations WHERE realm_name=$1 AND organization_id=$2 AND id=$3', [realm, organizationId, invitationId])).rowCount === 1; }
  async consumeOrganizationInvitation(realm, tokenDigest, user) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const lockedUser = (await client.query(
        'SELECT email FROM users WHERE realm_name=$1 AND id=$2 FOR UPDATE',
        [realm, user.id],
      )).rows[0];
      if (!lockedUser || lockedUser.email.toLowerCase() !== user.email.toLowerCase()) {
        await client.query('ROLLBACK');
        return undefined;
      }
      const invitation = (await client.query(
        `SELECT invitation.* FROM organization_invitations AS invitation
         JOIN organizations AS organization
           ON organization.realm_name=invitation.realm_name
          AND organization.id=invitation.organization_id
         WHERE invitation.realm_name=$1 AND invitation.token_digest=$2
           AND invitation.accepted_at IS NULL AND invitation.expires_at>CURRENT_TIMESTAMP
           AND lower(invitation.email)=lower($3) AND organization.enabled
         FOR UPDATE OF invitation,organization`,
        [realm, tokenDigest, lockedUser.email],
      )).rows[0];
      if (!invitation) {
        await client.query('ROLLBACK');
        return undefined;
      }
      const previous = (await client.query(
        `SELECT roles FROM organization_memberships
         WHERE realm_name=$1 AND organization_id=$2 AND user_id=$3 FOR UPDATE`,
        [realm, invitation.organization_id, user.id],
      )).rows[0];
      await client.query(
        `UPDATE organization_invitations SET accepted_at=CURRENT_TIMESTAMP
         WHERE realm_name=$1 AND id=$2`,
        [realm, invitation.id],
      );
      await client.query(
        `INSERT INTO organization_memberships (realm_name,organization_id,user_id,roles)
         VALUES ($1,$2,$3,$4)
         ON CONFLICT (realm_name,organization_id,user_id) DO UPDATE SET roles=EXCLUDED.roles`,
        [realm, invitation.organization_id, user.id, invitation.roles],
      );
      const accepted = publicInvitation({ ...invitation, accepted_at: new Date() });
      Object.defineProperty(accepted, organizationInvitationPreviousRoles, {
        value: previous ? [...previous.roles] : undefined,
      });
      await client.query('COMMIT');
      return accepted;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally { client.release(); }
  }
  async rollbackOrganizationInvitationAcceptance(
    realm,
    organizationId,
    invitationId,
    userId,
    { previousRoles, restoreMembership = true } = {},
  ) {
    return withPostgresAdvisoryTransaction(
      this.pool,
      `authme:organization-invitation:${realm}:${invitationId}`,
      async (client) => {
        const result = await client.query(
          `UPDATE organization_invitations SET accepted_at=NULL
           WHERE realm_name=$1 AND organization_id=$2 AND id=$3 AND accepted_at IS NOT NULL
           RETURNING id`,
          [realm, organizationId, invitationId],
        );
        if (result.rowCount !== 1) return false;
        if (restoreMembership && previousRoles !== undefined) {
          await client.query(
            `INSERT INTO organization_memberships (realm_name,organization_id,user_id,roles)
             SELECT $1::varchar(63),$2::uuid,$3::uuid,$4::text[]
             FROM users,organizations
             WHERE users.realm_name=$1 AND users.id=$3
               AND organizations.realm_name=$1 AND organizations.id=$2
             ON CONFLICT (realm_name,organization_id,user_id) DO UPDATE SET roles=EXCLUDED.roles`,
            [realm, organizationId, userId, previousRoles],
          );
        } else {
          await client.query(
            `DELETE FROM organization_memberships
             WHERE realm_name=$1 AND organization_id=$2 AND user_id=$3`,
            [realm, organizationId, userId],
          );
        }
        return true;
      },
    );
  }
  async listSigningKeys(realm) { return (await this.pool.query('SELECT * FROM signing_key_versions WHERE realm_name=$1 ORDER BY created_at', [realm])).rows.map(publicSigningKey); }
  async putSigningKey(realm, input) {
    const client = await this.pool.connect();
    try { await client.query('BEGIN'); if (input.status === 'active') await client.query(`UPDATE signing_key_versions SET status='retiring',retire_after=COALESCE($3,retire_after) WHERE realm_name=$1 AND status='active' AND key_id<>$2`, [realm, input.keyId, input.retireAfter ?? null]); const signingKey = (await client.query(`INSERT INTO signing_key_versions (realm_name,key_id,provider,status,algorithm,material_reference,public_jwk,activated_at,retire_after) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (realm_name,key_id) DO UPDATE SET provider=EXCLUDED.provider,status=EXCLUDED.status,algorithm=EXCLUDED.algorithm,material_reference=EXCLUDED.material_reference,public_jwk=EXCLUDED.public_jwk,activated_at=EXCLUDED.activated_at,retire_after=EXCLUDED.retire_after RETURNING *`, [realm, input.keyId, input.provider, input.status, input.algorithm, input.materialReference, input.publicJwk, input.activatedAt ?? null, input.retireAfter ?? null])).rows[0]; await client.query('COMMIT'); return publicSigningKey(signingKey); } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; } finally { client.release(); }
  }
}
