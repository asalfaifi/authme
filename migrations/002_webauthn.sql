CREATE TABLE webauthn_credentials (
  realm_name VARCHAR(63) NOT NULL,
  user_id UUID NOT NULL,
  credential_id TEXT NOT NULL,
  user_handle TEXT NOT NULL,
  public_key BYTEA NOT NULL,
  counter BIGINT NOT NULL,
  transports TEXT[] NOT NULL DEFAULT '{}'::text[],
  credential_device_type TEXT NOT NULL,
  backed_up BOOLEAN NOT NULL,
  aaguid UUID NOT NULL,
  display_name TEXT NOT NULL,
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (realm_name, credential_id),
  FOREIGN KEY (realm_name, user_id) REFERENCES users(realm_name, id) ON DELETE CASCADE,
  CONSTRAINT webauthn_credentials_id_format CHECK (
    length(credential_id) BETWEEN 1 AND 2048 AND credential_id ~ '^[A-Za-z0-9_-]+$'
  ),
  CONSTRAINT webauthn_credentials_user_handle_format CHECK (
    length(user_handle) BETWEEN 1 AND 128 AND user_handle ~ '^[A-Za-z0-9_-]+$'
  ),
  CONSTRAINT webauthn_credentials_public_key_size CHECK (
    octet_length(public_key) BETWEEN 1 AND 8192
  ),
  CONSTRAINT webauthn_credentials_counter_range CHECK (counter BETWEEN 0 AND 4294967295),
  CONSTRAINT webauthn_credentials_transports_known CHECK (
    transports <@ ARRAY['ble','cable','hybrid','internal','nfc','smart-card','usb']::text[]
  ),
  CONSTRAINT webauthn_credentials_device_type_known CHECK (
    credential_device_type IN ('singleDevice', 'multiDevice')
  ),
  CONSTRAINT webauthn_credentials_name_present CHECK (
    length(btrim(display_name)) BETWEEN 1 AND 100
  )
);

CREATE INDEX webauthn_credentials_user_idx
  ON webauthn_credentials (realm_name, user_id, created_at);

CREATE TABLE webauthn_challenges (
  realm_name VARCHAR(63) NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
  id UUID NOT NULL,
  purpose TEXT NOT NULL,
  user_id UUID,
  interaction_uid TEXT,
  user_handle TEXT,
  challenge TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (realm_name, id),
  FOREIGN KEY (realm_name, user_id) REFERENCES users(realm_name, id) ON DELETE CASCADE,
  CONSTRAINT webauthn_challenges_purpose_known CHECK (purpose IN ('registration', 'authentication')),
  CONSTRAINT webauthn_challenges_context_consistent CHECK (
    (purpose = 'registration' AND user_id IS NOT NULL AND interaction_uid IS NULL AND user_handle IS NOT NULL)
    OR
    (purpose = 'authentication' AND user_id IS NULL AND interaction_uid IS NOT NULL AND user_handle IS NULL)
  ),
  CONSTRAINT webauthn_challenges_uid_size CHECK (
    interaction_uid IS NULL OR length(interaction_uid) BETWEEN 1 AND 255
  ),
  CONSTRAINT webauthn_challenges_user_handle_format CHECK (
    user_handle IS NULL OR (length(user_handle) BETWEEN 1 AND 128 AND user_handle ~ '^[A-Za-z0-9_-]+$')
  ),
  CONSTRAINT webauthn_challenges_value_format CHECK (
    length(challenge) BETWEEN 32 AND 512 AND challenge ~ '^[A-Za-z0-9_-]+$'
  ),
  UNIQUE (realm_name, challenge)
);

CREATE INDEX webauthn_challenges_expiry_idx ON webauthn_challenges (expires_at);

CREATE TRIGGER webauthn_credentials_set_updated_at
BEFORE UPDATE ON webauthn_credentials
FOR EACH ROW EXECUTE FUNCTION authme_set_updated_at();
