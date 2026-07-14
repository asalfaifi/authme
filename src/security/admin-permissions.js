export const ADMIN_PERMISSIONS = Object.freeze([
  'realms.read',
  'configuration.read',
  'users.read',
  'users.write',
  'users.delete',
  'credentials.manage',
  'sessions.revoke',
  'federation.manage',
  'clients.register',
  'administrators.manage',
  'audit.read',
  'metrics.read',
]);

const allowed = new Set(ADMIN_PERMISSIONS);

export function normalizeAdminPermissions(permissions) {
  if (!Array.isArray(permissions) || permissions.length === 0 || permissions.length > 64) {
    throw new TypeError('Administrator permissions must be a non-empty array with at most 64 entries');
  }
  const normalized = [...new Set(permissions.map((permission) => String(permission).trim()))];
  if (normalized.includes('*')) return Object.freeze(['*']);
  if (normalized.some((permission) => !allowed.has(permission))) {
    throw new TypeError('Administrator permissions contain an unsupported value');
  }
  return Object.freeze(normalized);
}

export function hasAdminPermission(grant, permission) {
  return Boolean(grant?.enabled && (grant.permissions.includes('*') || grant.permissions.includes(permission)));
}
