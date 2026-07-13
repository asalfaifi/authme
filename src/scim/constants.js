export const SCIM_URNS = Object.freeze({
  user: 'urn:ietf:params:scim:schemas:core:2.0:User',
  group: 'urn:ietf:params:scim:schemas:core:2.0:Group',
  serviceProviderConfig: 'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig',
  resourceType: 'urn:ietf:params:scim:schemas:core:2.0:ResourceType',
  schema: 'urn:ietf:params:scim:schemas:core:2.0:Schema',
  listResponse: 'urn:ietf:params:scim:api:messages:2.0:ListResponse',
  patchOp: 'urn:ietf:params:scim:api:messages:2.0:PatchOp',
  error: 'urn:ietf:params:scim:api:messages:2.0:Error',
});

const stringAttribute = (name, options = {}) => ({
  name, type: 'string', multiValued: false, required: false,
  caseExact: false, mutability: 'readWrite', returned: 'default', uniqueness: 'none',
  ...options,
});

const complexAttribute = (name, subAttributes, options = {}) => ({
  name, type: 'complex', multiValued: false, required: false,
  mutability: 'readWrite', returned: 'default', subAttributes, ...options,
});

const multiComplex = (name, subAttributes, options = {}) => complexAttribute(name, subAttributes, {
  multiValued: true,
  ...options,
});

const typedValue = [
  stringAttribute('value'),
  stringAttribute('display'),
  stringAttribute('type'),
  { name: 'primary', type: 'boolean', multiValued: false, required: false, mutability: 'readWrite', returned: 'default' },
];

export const USER_SCHEMA = Object.freeze({
  schemas: [SCIM_URNS.schema],
  id: SCIM_URNS.user,
  name: 'User',
  description: 'AuthMe SCIM 2.0 User',
  attributes: [
    stringAttribute('userName', { required: true, uniqueness: 'server' }),
    complexAttribute('name', [
      stringAttribute('formatted'), stringAttribute('familyName'), stringAttribute('givenName'),
      stringAttribute('middleName'), stringAttribute('honorificPrefix'), stringAttribute('honorificSuffix'),
    ]),
    stringAttribute('displayName'), stringAttribute('nickName'),
    stringAttribute('profileUrl', { type: 'reference', referenceTypes: ['external'] }),
    stringAttribute('title'), stringAttribute('userType'), stringAttribute('preferredLanguage'),
    stringAttribute('locale'), stringAttribute('timezone'),
    { name: 'active', type: 'boolean', multiValued: false, required: false, mutability: 'readWrite', returned: 'default' },
    stringAttribute('password', { caseExact: true, mutability: 'writeOnly', returned: 'never' }),
    multiComplex('emails', typedValue), multiComplex('phoneNumbers', typedValue),
    multiComplex('ims', typedValue), multiComplex('photos', typedValue),
    multiComplex('addresses', [
      stringAttribute('formatted'), stringAttribute('streetAddress'), stringAttribute('locality'),
      stringAttribute('region'), stringAttribute('postalCode'), stringAttribute('country'),
      stringAttribute('type'), { name: 'primary', type: 'boolean', multiValued: false, required: false, mutability: 'readWrite', returned: 'default' },
    ]),
    multiComplex('groups', [
      stringAttribute('value', { mutability: 'readOnly' }),
      stringAttribute('$ref', { type: 'reference', mutability: 'readOnly', referenceTypes: ['Group'] }),
      stringAttribute('display', { mutability: 'readOnly' }),
      stringAttribute('type', { mutability: 'readOnly' }),
    ], { mutability: 'readOnly' }),
    multiComplex('entitlements', typedValue), multiComplex('roles', typedValue),
    multiComplex('x509Certificates', [stringAttribute('value', { caseExact: true })]),
  ],
});

export const GROUP_SCHEMA = Object.freeze({
  schemas: [SCIM_URNS.schema],
  id: SCIM_URNS.group,
  name: 'Group',
  description: 'AuthMe SCIM 2.0 Group',
  attributes: [
    stringAttribute('displayName', { required: true }),
    multiComplex('members', [
      stringAttribute('value', { mutability: 'immutable' }),
      stringAttribute('$ref', { type: 'reference', mutability: 'immutable', referenceTypes: ['User'] }),
      stringAttribute('display', { mutability: 'readOnly' }),
      stringAttribute('type', { mutability: 'immutable', canonicalValues: ['User'] }),
    ]),
  ],
});

export function serviceProviderConfig(baseUrl, maxResults) {
  return {
    schemas: [SCIM_URNS.serviceProviderConfig],
    documentationUri: 'https://www.rfc-editor.org/rfc/rfc7644',
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults },
    changePassword: { supported: false },
    sort: { supported: false },
    etag: { supported: true },
    authenticationSchemes: [{
      type: 'oauthbearertoken',
      name: 'Bearer Token',
      description: 'Bearer token supplied by the AuthMe SCIM integration',
      specUri: 'https://www.rfc-editor.org/rfc/rfc6750',
      primary: true,
    }],
    meta: { resourceType: 'ServiceProviderConfig', location: `${baseUrl}/ServiceProviderConfig` },
  };
}

export function resourceTypes(baseUrl) {
  return [
    {
      schemas: [SCIM_URNS.resourceType], id: 'User', name: 'User', endpoint: '/Users',
      description: 'AuthMe user account', schema: SCIM_URNS.user,
      schemaExtensions: [], meta: { resourceType: 'ResourceType', location: `${baseUrl}/ResourceTypes/User` },
    },
    {
      schemas: [SCIM_URNS.resourceType], id: 'Group', name: 'Group', endpoint: '/Groups',
      description: 'AuthMe group', schema: SCIM_URNS.group,
      schemaExtensions: [], meta: { resourceType: 'ResourceType', location: `${baseUrl}/ResourceTypes/Group` },
    },
  ];
}
