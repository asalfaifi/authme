-- Mutable client-role definitions and same-client composite graphs.

CREATE TABLE client_roles (
  realm_name VARCHAR(63) NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
  client_id TEXT NOT NULL,
  name VARCHAR(128) NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  composites TEXT[] NOT NULL DEFAULT '{}'::text[],
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (realm_name, client_id, name),
  CONSTRAINT client_roles_client_present CHECK (length(btrim(client_id)) > 0),
  CONSTRAINT client_roles_name_present CHECK (length(btrim(name)) > 0),
  CONSTRAINT client_roles_no_self_composite CHECK (NOT (name = ANY(composites))),
  CONSTRAINT client_roles_attributes_object CHECK (jsonb_typeof(attributes) = 'object')
);

CREATE INDEX client_roles_client_idx ON client_roles (realm_name, client_id, name);

CREATE TRIGGER client_roles_set_updated_at BEFORE UPDATE ON client_roles
FOR EACH ROW EXECUTE FUNCTION authme_set_updated_at();
