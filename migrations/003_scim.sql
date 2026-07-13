CREATE TABLE scim_user_resources (
  realm_name VARCHAR(63) NOT NULL,
  user_id UUID NOT NULL,
  external_id TEXT,
  version BIGINT NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (realm_name, user_id),
  FOREIGN KEY (realm_name, user_id) REFERENCES users(realm_name, id) ON DELETE CASCADE,
  CONSTRAINT scim_user_resources_version_positive CHECK (version > 0),
  CONSTRAINT scim_user_resources_external_id_size CHECK (external_id IS NULL OR length(external_id) <= 256)
);

CREATE UNIQUE INDEX scim_user_external_id_unique
  ON scim_user_resources (realm_name, external_id) WHERE external_id IS NOT NULL;

INSERT INTO scim_user_resources (realm_name, user_id, created_at, updated_at)
SELECT realm_name, id, created_at, updated_at FROM users;

CREATE FUNCTION authme_scim_user_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO scim_user_resources (realm_name, user_id, created_at, updated_at)
  VALUES (NEW.realm_name, NEW.id, NEW.created_at, NEW.updated_at)
  ON CONFLICT (realm_name, user_id) DO NOTHING;
  RETURN NEW;
END;
$$;

CREATE FUNCTION authme_scim_user_version()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  UPDATE scim_user_resources
  SET version=version+1, updated_at=NEW.updated_at
  WHERE realm_name=NEW.realm_name AND user_id=NEW.id;
  RETURN NEW;
END;
$$;

CREATE TRIGGER users_create_scim_resource
AFTER INSERT ON users
FOR EACH ROW EXECUTE FUNCTION authme_scim_user_insert();

CREATE TRIGGER users_version_scim_resource
AFTER UPDATE OF username, email, email_verified, display_name, given_name,
  family_name, enabled, roles, groups, attributes ON users
FOR EACH ROW EXECUTE FUNCTION authme_scim_user_version();

CREATE TABLE scim_groups (
  realm_name VARCHAR(63) NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
  id UUID NOT NULL,
  external_id TEXT,
  display_name TEXT NOT NULL,
  version BIGINT NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (realm_name, id),
  CONSTRAINT scim_groups_display_name_present CHECK (length(btrim(display_name)) BETWEEN 1 AND 256),
  CONSTRAINT scim_groups_external_id_size CHECK (external_id IS NULL OR length(external_id) <= 256),
  CONSTRAINT scim_groups_version_positive CHECK (version > 0)
);

CREATE UNIQUE INDEX scim_groups_display_name_unique ON scim_groups (realm_name, lower(display_name));
CREATE UNIQUE INDEX scim_groups_external_id_unique
  ON scim_groups (realm_name, external_id) WHERE external_id IS NOT NULL;

CREATE TABLE scim_group_members (
  realm_name VARCHAR(63) NOT NULL,
  group_id UUID NOT NULL,
  user_id UUID NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (realm_name, group_id, user_id),
  FOREIGN KEY (realm_name, group_id) REFERENCES scim_groups(realm_name, id) ON DELETE CASCADE,
  FOREIGN KEY (realm_name, user_id) REFERENCES users(realm_name, id) ON DELETE CASCADE
);

CREATE INDEX scim_group_members_user_idx ON scim_group_members (realm_name, user_id, group_id);

CREATE TRIGGER scim_groups_set_updated_at
BEFORE UPDATE ON scim_groups
FOR EACH ROW EXECUTE FUNCTION authme_set_updated_at();
