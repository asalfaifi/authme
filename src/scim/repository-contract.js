/**
 * SCIM repository contract (documentation-only typedef).
 *
 * Every method MUST scope all reads, uniqueness checks, membership checks, and
 * writes by `realm`. User userName and User/Group externalId values are unique
 * within their resource type and realm. replace/delete MUST compare
 * `expectedVersion` atomically and throw ScimRepositoryError with code
 * VERSION_MISMATCH when it loses a race.
 *
 * @typedef {object} ScimRepository
 * @property {(realm:string, options:object) => Promise<{totalResults:number, resources:object[]}>} listUsers
 * @property {(realm:string, id:string) => Promise<object|undefined>} getUser
 * @property {(realm:string, attributes:object) => Promise<object>} createUser
 * @property {(realm:string, id:string, attributes:object, expectedVersion:number) => Promise<object>} replaceUser
 * @property {(realm:string, id:string, expectedVersion:number) => Promise<object>} deleteUser
 * @property {(realm:string, options:object) => Promise<{totalResults:number, resources:object[]}>} listGroups
 * @property {(realm:string, id:string) => Promise<object|undefined>} getGroup
 * @property {(realm:string, attributes:object) => Promise<object>} createGroup
 * @property {(realm:string, id:string, attributes:object, expectedVersion:number) => Promise<object>} replaceGroup
 * @property {(realm:string, id:string, expectedVersion:number) => Promise<object>} deleteGroup
 * @property {(realm:string, userId:string) => Promise<object[]>} listUserGroups
 *
 * User records contain id, version, createdAt, updatedAt, and normalized SCIM
 * attributes. A durable identity adapter must translate active=false into the
 * core account's disabled state and revoke/deny active authentication state as
 * required by AuthMe policy. Group membership writes must validate referenced
 * Users in the same realm and deleteUser must remove dangling memberships.
 * Password input is write-only and must be hashed immediately rather than
 * persisted in this record shape.
 */

export const SCIM_REPOSITORY_CONTRACT_VERSION = 1;
