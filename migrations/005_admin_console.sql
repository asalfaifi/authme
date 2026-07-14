CREATE TABLE admin_grants (
  realm_name VARCHAR(63) NOT NULL,
  user_id UUID NOT NULL,
  permissions TEXT[] NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  version BIGINT NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (realm_name, user_id),
  FOREIGN KEY (realm_name, user_id) REFERENCES users(realm_name, id) ON DELETE CASCADE,
  CONSTRAINT admin_grants_permissions_present CHECK (cardinality(permissions) BETWEEN 1 AND 64),
  CONSTRAINT admin_grants_version_positive CHECK (version > 0)
);

CREATE INDEX admin_grants_realm_enabled_idx
  ON admin_grants (realm_name, enabled) WHERE enabled;

CREATE TABLE admin_sessions (
  id_digest CHAR(43) PRIMARY KEY,
  realm_name VARCHAR(63) NOT NULL,
  user_id UUID NOT NULL,
  grant_version BIGINT NOT NULL,
  security_version BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  idle_expires_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  FOREIGN KEY (realm_name, user_id) REFERENCES users(realm_name, id) ON DELETE CASCADE,
  CONSTRAINT admin_sessions_digest_format CHECK (id_digest ~ '^[A-Za-z0-9_-]{43}$'),
  CONSTRAINT admin_sessions_versions_nonnegative CHECK (grant_version > 0 AND security_version >= 0),
  CONSTRAINT admin_sessions_expiry_order CHECK (idle_expires_at > created_at AND expires_at > created_at)
);

CREATE INDEX admin_sessions_user_idx ON admin_sessions (realm_name, user_id);
CREATE INDEX admin_sessions_expiry_idx ON admin_sessions (expires_at);
CREATE INDEX admin_sessions_idle_expiry_idx ON admin_sessions (idle_expires_at);

CREATE TRIGGER admin_grants_set_updated_at
BEFORE UPDATE ON admin_grants
FOR EACH ROW EXECUTE FUNCTION authme_set_updated_at();
