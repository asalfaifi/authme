-- v1.0 mutable administration, organizations, authentication flows, claim policy,
-- and signing-key lifecycle state. Realm names remain immutable issuer identifiers.

ALTER TABLE oidc_records
  DROP CONSTRAINT oidc_records_ciba_poll_interval,
  ADD CONSTRAINT oidc_records_ciba_poll_interval CHECK (
    ciba_poll_interval_seconds IS NULL
    OR (model = 'BackchannelAuthenticationRequest' AND ciba_poll_interval_seconds > 0)
  );

CREATE TABLE realm_roles (
  realm_name VARCHAR(63) NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
  name VARCHAR(128) NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  composites TEXT[] NOT NULL DEFAULT '{}'::text[],
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (realm_name, name),
  CONSTRAINT realm_roles_name_present CHECK (length(btrim(name)) > 0),
  CONSTRAINT realm_roles_no_self_composite CHECK (NOT (name = ANY(composites))),
  CONSTRAINT realm_roles_attributes_object CHECK (jsonb_typeof(attributes) = 'object')
);

CREATE TABLE realm_groups (
  realm_name VARCHAR(63) NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
  id UUID NOT NULL,
  name VARCHAR(128) NOT NULL,
  parent_id UUID,
  roles TEXT[] NOT NULL DEFAULT '{}'::text[],
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (realm_name, id),
  FOREIGN KEY (realm_name, parent_id) REFERENCES realm_groups(realm_name, id) ON DELETE RESTRICT,
  CONSTRAINT realm_groups_name_present CHECK (length(btrim(name)) > 0),
  CONSTRAINT realm_groups_no_self_parent CHECK (parent_id IS NULL OR parent_id <> id),
  CONSTRAINT realm_groups_attributes_object CHECK (jsonb_typeof(attributes) = 'object')
);

CREATE UNIQUE INDEX realm_groups_sibling_name_unique
  ON realm_groups (realm_name, COALESCE(parent_id, '00000000-0000-0000-0000-000000000000'::uuid), lower(name));
CREATE INDEX realm_groups_parent_idx ON realm_groups (realm_name, parent_id);

CREATE TABLE client_scopes (
  realm_name VARCHAR(63) NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
  id UUID NOT NULL,
  name VARCHAR(128) NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  protocol VARCHAR(32) NOT NULL DEFAULT 'openid-connect',
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (realm_name, id),
  CONSTRAINT client_scopes_name_present CHECK (length(btrim(name)) > 0),
  CONSTRAINT client_scopes_protocol CHECK (protocol = 'openid-connect'),
  CONSTRAINT client_scopes_attributes_object CHECK (jsonb_typeof(attributes) = 'object')
);
CREATE UNIQUE INDEX client_scopes_realm_name_unique ON client_scopes (realm_name, lower(name));

CREATE TABLE client_scope_assignments (
  realm_name VARCHAR(63) NOT NULL,
  client_id TEXT NOT NULL,
  scope_id UUID NOT NULL,
  assignment_type VARCHAR(16) NOT NULL DEFAULT 'default',
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (realm_name, client_id, scope_id),
  FOREIGN KEY (realm_name, scope_id) REFERENCES client_scopes(realm_name, id) ON DELETE CASCADE,
  FOREIGN KEY (realm_name) REFERENCES realms(name) ON DELETE CASCADE,
  CONSTRAINT client_scope_assignment_type CHECK (assignment_type IN ('default', 'optional'))
);

CREATE TABLE claim_mappers (
  realm_name VARCHAR(63) NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
  id UUID NOT NULL,
  owner_type VARCHAR(16) NOT NULL,
  owner_id TEXT NOT NULL,
  name VARCHAR(128) NOT NULL,
  mapper_type VARCHAR(32) NOT NULL,
  config JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (realm_name, id),
  CONSTRAINT claim_mappers_owner_type CHECK (owner_type IN ('client', 'client-scope')),
  CONSTRAINT claim_mappers_owner_present CHECK (length(owner_id) > 0),
  CONSTRAINT claim_mappers_name_present CHECK (length(btrim(name)) > 0),
  CONSTRAINT claim_mappers_type CHECK (mapper_type IN ('user-attribute', 'hardcoded', 'realm-roles', 'client-roles', 'groups', 'organization')),
  CONSTRAINT claim_mappers_config_object CHECK (jsonb_typeof(config) = 'object')
);
CREATE UNIQUE INDEX claim_mappers_owner_name_unique
  ON claim_mappers (realm_name, owner_type, owner_id, lower(name));
CREATE INDEX claim_mappers_owner_idx ON claim_mappers (realm_name, owner_type, owner_id);

CREATE TABLE authentication_flows (
  realm_name VARCHAR(63) NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
  id UUID NOT NULL,
  alias VARCHAR(128) NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  priority INTEGER NOT NULL DEFAULT 100,
  client_ids TEXT[] NOT NULL DEFAULT '{}'::text[],
  acr VARCHAR(255) NOT NULL,
  max_age_seconds INTEGER,
  steps JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (realm_name, id),
  CONSTRAINT authentication_flows_alias_present CHECK (length(btrim(alias)) > 0),
  CONSTRAINT authentication_flows_priority_nonnegative CHECK (priority >= 0),
  CONSTRAINT authentication_flows_acr_present CHECK (length(acr) > 0),
  CONSTRAINT authentication_flows_max_age_positive CHECK (max_age_seconds IS NULL OR max_age_seconds > 0),
  CONSTRAINT authentication_flows_steps_array CHECK (jsonb_typeof(steps) = 'array' AND jsonb_array_length(steps) > 0)
);
CREATE UNIQUE INDEX authentication_flows_realm_alias_unique
  ON authentication_flows (realm_name, lower(alias));
CREATE INDEX authentication_flows_resolution_idx
  ON authentication_flows (realm_name, enabled, priority, created_at);

CREATE TABLE organizations (
  realm_name VARCHAR(63) NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
  id UUID NOT NULL,
  name VARCHAR(255) NOT NULL,
  alias VARCHAR(128) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  identity_provider_ids TEXT[] NOT NULL DEFAULT '{}'::text[],
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (realm_name, id),
  CONSTRAINT organizations_name_present CHECK (length(btrim(name)) > 0),
  CONSTRAINT organizations_alias_present CHECK (length(btrim(alias)) > 0),
  CONSTRAINT organizations_attributes_object CHECK (jsonb_typeof(attributes) = 'object')
);
CREATE UNIQUE INDEX organizations_realm_alias_unique ON organizations (realm_name, lower(alias));

CREATE TABLE organization_domains (
  realm_name VARCHAR(63) NOT NULL,
  organization_id UUID NOT NULL,
  domain VARCHAR(253) NOT NULL,
  verified BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (realm_name, organization_id, domain),
  FOREIGN KEY (realm_name, organization_id) REFERENCES organizations(realm_name, id) ON DELETE CASCADE,
  CONSTRAINT organization_domains_lowercase CHECK (domain = lower(domain)),
  CONSTRAINT organization_domains_present CHECK (length(domain) > 0)
);
CREATE UNIQUE INDEX organization_domains_realm_domain_unique ON organization_domains (realm_name, lower(domain));

CREATE TABLE organization_memberships (
  realm_name VARCHAR(63) NOT NULL,
  organization_id UUID NOT NULL,
  user_id UUID NOT NULL,
  roles TEXT[] NOT NULL DEFAULT '{}'::text[],
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (realm_name, organization_id, user_id),
  FOREIGN KEY (realm_name, organization_id) REFERENCES organizations(realm_name, id) ON DELETE CASCADE,
  FOREIGN KEY (realm_name, user_id) REFERENCES users(realm_name, id) ON DELETE CASCADE
);
CREATE INDEX organization_memberships_user_idx ON organization_memberships (realm_name, user_id);

CREATE TABLE organization_invitations (
  realm_name VARCHAR(63) NOT NULL,
  id UUID NOT NULL,
  organization_id UUID NOT NULL,
  email TEXT NOT NULL,
  roles TEXT[] NOT NULL DEFAULT '{}'::text[],
  token_digest CHAR(43) NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  accepted_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (realm_name, id),
  FOREIGN KEY (realm_name, organization_id) REFERENCES organizations(realm_name, id) ON DELETE CASCADE,
  CONSTRAINT organization_invitations_digest_format CHECK (token_digest ~ '^[A-Za-z0-9_-]{43}$'),
  CONSTRAINT organization_invitations_expiry CHECK (expires_at > created_at)
);
CREATE UNIQUE INDEX organization_invitations_token_unique ON organization_invitations (token_digest);
CREATE INDEX organization_invitations_expiry_idx ON organization_invitations (expires_at) WHERE accepted_at IS NULL;

CREATE TABLE signing_key_versions (
  realm_name VARCHAR(63) NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
  key_id VARCHAR(255) NOT NULL,
  provider VARCHAR(32) NOT NULL,
  status VARCHAR(16) NOT NULL,
  algorithm VARCHAR(16) NOT NULL,
  material_reference TEXT NOT NULL,
  public_jwk JSONB NOT NULL,
  activated_at TIMESTAMPTZ,
  retire_after TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (realm_name, key_id),
  CONSTRAINT signing_key_provider CHECK (provider IN ('file', 'aws-kms', 'gcp-kms', 'azure-key-vault', 'pkcs11')),
  CONSTRAINT signing_key_status CHECK (status IN ('pending', 'active', 'retiring', 'retired')),
  CONSTRAINT signing_key_algorithm CHECK (algorithm IN ('RS256', 'PS256', 'ES256')),
  CONSTRAINT signing_key_reference_present CHECK (length(material_reference) > 0),
  CONSTRAINT signing_key_public_jwk_object CHECK (jsonb_typeof(public_jwk) = 'object')
);
CREATE UNIQUE INDEX signing_key_versions_one_active
  ON signing_key_versions (realm_name) WHERE status = 'active';

CREATE TRIGGER realm_roles_set_updated_at BEFORE UPDATE ON realm_roles
FOR EACH ROW EXECUTE FUNCTION authme_set_updated_at();
CREATE TRIGGER realm_groups_set_updated_at BEFORE UPDATE ON realm_groups
FOR EACH ROW EXECUTE FUNCTION authme_set_updated_at();
CREATE TRIGGER client_scopes_set_updated_at BEFORE UPDATE ON client_scopes
FOR EACH ROW EXECUTE FUNCTION authme_set_updated_at();
CREATE TRIGGER claim_mappers_set_updated_at BEFORE UPDATE ON claim_mappers
FOR EACH ROW EXECUTE FUNCTION authme_set_updated_at();
CREATE TRIGGER authentication_flows_set_updated_at BEFORE UPDATE ON authentication_flows
FOR EACH ROW EXECUTE FUNCTION authme_set_updated_at();
CREATE TRIGGER organizations_set_updated_at BEFORE UPDATE ON organizations
FOR EACH ROW EXECUTE FUNCTION authme_set_updated_at();
CREATE TRIGGER organization_memberships_set_updated_at BEFORE UPDATE ON organization_memberships
FOR EACH ROW EXECUTE FUNCTION authme_set_updated_at();
CREATE TRIGGER signing_key_versions_set_updated_at BEFORE UPDATE ON signing_key_versions
FOR EACH ROW EXECUTE FUNCTION authme_set_updated_at();
