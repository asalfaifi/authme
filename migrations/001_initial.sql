CREATE TABLE realms (
  name VARCHAR(63) PRIMARY KEY,
  display_name VARCHAR(255) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  settings JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT realms_name_format CHECK (name ~ '^[a-z][a-z0-9-]{0,62}$'),
  CONSTRAINT realms_settings_object CHECK (jsonb_typeof(settings) = 'object')
);

CREATE TABLE users (
  realm_name VARCHAR(63) NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
  id UUID NOT NULL,
  username TEXT NOT NULL,
  email TEXT NOT NULL,
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  display_name TEXT NOT NULL,
  given_name TEXT NOT NULL DEFAULT '',
  family_name TEXT NOT NULL DEFAULT '',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  security_version BIGINT NOT NULL DEFAULT 0,
  password_hash TEXT NOT NULL,
  roles TEXT[] NOT NULL DEFAULT '{}'::text[],
  groups TEXT[] NOT NULL DEFAULT '{}'::text[],
  client_roles JSONB NOT NULL DEFAULT '{}'::jsonb,
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
  totp_secret TEXT,
  totp_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
  pending_totp_secret TEXT,
  pending_totp_created_at TIMESTAMPTZ,
  recovery_code_hashes TEXT[] NOT NULL DEFAULT '{}'::text[],
  last_totp_step BIGINT,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (realm_name, id),
  CONSTRAINT users_username_present CHECK (length(btrim(username)) > 0),
  CONSTRAINT users_email_present CHECK (length(btrim(email)) > 0),
  CONSTRAINT users_display_name_present CHECK (length(btrim(display_name)) > 0),
  CONSTRAINT users_failed_attempts_nonnegative CHECK (failed_attempts >= 0),
  CONSTRAINT users_security_version_nonnegative CHECK (security_version >= 0),
  CONSTRAINT users_client_roles_object CHECK (jsonb_typeof(client_roles) = 'object'),
  CONSTRAINT users_attributes_object CHECK (jsonb_typeof(attributes) = 'object'),
  CONSTRAINT users_totp_consistent CHECK (NOT totp_confirmed OR totp_secret IS NOT NULL),
  CONSTRAINT users_pending_totp_consistent CHECK ((pending_totp_secret IS NULL) = (pending_totp_created_at IS NULL))
);

-- Case-insensitive identities are unique only inside their realm.
CREATE UNIQUE INDEX users_realm_username_unique
  ON users (realm_name, lower(username));
CREATE UNIQUE INDEX users_realm_email_unique
  ON users (realm_name, lower(email));
CREATE INDEX users_realm_enabled_idx ON users (realm_name, enabled);
CREATE INDEX users_realm_locked_idx
  ON users (realm_name, locked_until) WHERE locked_until IS NOT NULL;
CREATE INDEX users_roles_gin_idx ON users USING GIN (roles);
CREATE INDEX users_groups_gin_idx ON users USING GIN (groups);
CREATE INDEX users_client_roles_gin_idx ON users USING GIN (client_roles);

CREATE TABLE oidc_records (
  realm_name VARCHAR(63) NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
  model VARCHAR(100) NOT NULL,
  id TEXT NOT NULL,
  payload JSONB NOT NULL,
  expires_at TIMESTAMPTZ,
  consumed_at TIMESTAMPTZ,
  grant_id TEXT,
  user_code TEXT,
  uid TEXT,
  account_security_version BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (realm_name, model, id),
  CONSTRAINT oidc_records_model_present CHECK (length(model) > 0),
  CONSTRAINT oidc_records_id_present CHECK (length(id) > 0),
  CONSTRAINT oidc_records_payload_object CHECK (jsonb_typeof(payload) = 'object')
);

CREATE INDEX oidc_records_grant_idx
  ON oidc_records (realm_name, model, grant_id) WHERE grant_id IS NOT NULL;
CREATE INDEX oidc_records_realm_grant_idx
  ON oidc_records (realm_name, grant_id) WHERE grant_id IS NOT NULL;
CREATE UNIQUE INDEX oidc_records_user_code_unique
  ON oidc_records (realm_name, model, user_code) WHERE user_code IS NOT NULL;
CREATE UNIQUE INDEX oidc_records_uid_unique
  ON oidc_records (realm_name, model, uid) WHERE uid IS NOT NULL;
CREATE INDEX oidc_records_expiry_idx
  ON oidc_records (realm_name, expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX oidc_records_expiry_global_idx
  ON oidc_records (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX oidc_records_account_idx
  ON oidc_records (realm_name, (payload->>'accountId')) WHERE payload ? 'accountId';

-- Audit records intentionally retain actor/subject UUIDs after users are removed.
CREATE TABLE audit_events (
  realm_name VARCHAR(63) NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
  id UUID NOT NULL,
  event_type TEXT NOT NULL,
  actor_id UUID,
  subject_id UUID,
  client_id TEXT,
  ip_address INET,
  user_agent TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (realm_name, id),
  CONSTRAINT audit_events_type_present CHECK (length(btrim(event_type)) > 0),
  CONSTRAINT audit_events_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX audit_events_realm_created_idx
  ON audit_events (realm_name, created_at DESC);
CREATE INDEX audit_events_realm_type_created_idx
  ON audit_events (realm_name, event_type, created_at DESC);
CREATE INDEX audit_events_realm_actor_idx
  ON audit_events (realm_name, actor_id, created_at DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX audit_events_realm_subject_idx
  ON audit_events (realm_name, subject_id, created_at DESC) WHERE subject_id IS NOT NULL;
CREATE INDEX audit_events_realm_client_idx
  ON audit_events (realm_name, client_id, created_at DESC) WHERE client_id IS NOT NULL;
CREATE INDEX audit_events_created_idx ON audit_events (created_at);

CREATE FUNCTION authme_set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$;

CREATE FUNCTION authme_enforce_login_namespace()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  -- Serialize identity-name allocation within a realm so a username can never
  -- race another user's email address (or vice versa).
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.realm_name, 0));
  IF EXISTS (
    SELECT 1 FROM users AS existing
    WHERE existing.realm_name = NEW.realm_name
      AND existing.id <> NEW.id
      AND (
        lower(existing.username) IN (lower(NEW.username), lower(NEW.email))
        OR lower(existing.email) IN (lower(NEW.username), lower(NEW.email))
      )
  ) THEN
    RAISE EXCEPTION 'username and email must be unique in the realm login namespace'
      USING ERRCODE = 'unique_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER users_enforce_login_namespace
BEFORE INSERT OR UPDATE OF username, email ON users
FOR EACH ROW EXECUTE FUNCTION authme_enforce_login_namespace();

CREATE TRIGGER realms_set_updated_at
BEFORE UPDATE ON realms
FOR EACH ROW EXECUTE FUNCTION authme_set_updated_at();

CREATE TRIGGER users_set_updated_at
BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION authme_set_updated_at();

CREATE TRIGGER oidc_records_set_updated_at
BEFORE UPDATE ON oidc_records
FOR EACH ROW EXECUTE FUNCTION authme_set_updated_at();
