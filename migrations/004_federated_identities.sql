CREATE TABLE federated_identities (
  realm_name VARCHAR(63) NOT NULL,
  provider_id VARCHAR(64) NOT NULL,
  issuer TEXT NOT NULL,
  external_subject TEXT NOT NULL,
  user_id UUID NOT NULL,
  profile JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login_at TIMESTAMPTZ,
  PRIMARY KEY (realm_name, provider_id, issuer, external_subject),
  FOREIGN KEY (realm_name, user_id) REFERENCES users(realm_name, id) ON DELETE CASCADE,
  CONSTRAINT federated_identities_provider_format CHECK (provider_id ~ '^[a-z][a-z0-9-]{1,63}$'),
  CONSTRAINT federated_identities_issuer_size CHECK (length(issuer) BETWEEN 1 AND 2048),
  CONSTRAINT federated_identities_subject_size CHECK (length(external_subject) BETWEEN 1 AND 2048),
  CONSTRAINT federated_identities_issuer_no_controls CHECK (issuer !~ '[[:cntrl:]]'),
  CONSTRAINT federated_identities_subject_no_controls CHECK (external_subject !~ '[[:cntrl:]]'),
  CONSTRAINT federated_identities_profile_object CHECK (jsonb_typeof(profile) = 'object')
);

CREATE UNIQUE INDEX federated_identities_user_provider_unique
  ON federated_identities (realm_name, user_id, provider_id, issuer);
CREATE INDEX federated_identities_user_idx ON federated_identities (realm_name, user_id);

CREATE TRIGGER federated_identities_set_updated_at
BEFORE UPDATE ON federated_identities
FOR EACH ROW EXECUTE FUNCTION authme_set_updated_at();
