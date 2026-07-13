import { SCIM_URNS } from './constants.js';

export class ScimError extends Error {
  constructor(status, detail, scimType) {
    super(detail);
    this.name = 'ScimError';
    this.status = status;
    this.scimType = scimType;
  }
}

export class ScimRepositoryError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ScimRepositoryError';
    this.code = code;
  }
}

export function errorBody(status, detail, scimType) {
  return {
    schemas: [SCIM_URNS.error],
    ...(scimType ? { scimType } : {}),
    detail,
    status: String(status),
  };
}

export function repositoryError(error) {
  if (!(error instanceof ScimRepositoryError)) return error;
  if (error.code === 'NOT_FOUND') return new ScimError(404, error.message);
  if (error.code === 'UNIQUENESS') return new ScimError(409, error.message, 'uniqueness');
  if (error.code === 'VERSION_MISMATCH') return new ScimError(412, error.message);
  if (error.code === 'INVALID_VALUE') return new ScimError(400, error.message, 'invalidValue');
  return error;
}
