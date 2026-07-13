import { AUTHME_EXTENSION_API_VERSION } from '../authentication/registry.js';
import { createScimRouter } from './router.js';

/**
 * Wraps the SCIM router in AuthMe's versioned provisioning-extension contract.
 * Router options may be supplied at construction and/or createRouter time; the
 * latter take precedence so the application can inject realm/config/runtime
 * dependencies without storing them in extension metadata.
 */
export function createScimExtension({ enabledFor, routerOptions = {} } = {}) {
  if (enabledFor !== undefined && typeof enabledFor !== 'function') throw new TypeError('enabledFor must be a function');
  return {
    manifest: {
      apiVersion: AUTHME_EXTENSION_API_VERSION,
      id: 'builtin.scim2',
      kind: 'provisioning',
      displayName: 'SCIM 2.0 Provisioning',
      capabilities: ['groups', 'scim2', 'users'],
    },
    implementation: {
      ...(enabledFor ? { enabledFor } : {}),
      createRouter(overrides = {}) {
        return createScimRouter({ ...routerOptions, ...overrides });
      },
    },
  };
}
