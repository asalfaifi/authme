CREATE TABLE account_sessions (
  id_digest CHAR(43) PRIMARY KEY,
  realm_name VARCHAR(63) NOT NULL,
  user_id UUID NOT NULL,
  security_version BIGINT NOT NULL,
  authentication_methods TEXT[] NOT NULL DEFAULT '{}'::text[],
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  idle_expires_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  ip_address INET,
  user_agent TEXT,
  FOREIGN KEY (realm_name, user_id) REFERENCES users(realm_name, id) ON DELETE CASCADE,
  CONSTRAINT account_sessions_digest_format CHECK (id_digest ~ '^[A-Za-z0-9_-]{43}$'),
  CONSTRAINT account_sessions_version_nonnegative CHECK (security_version >= 0),
  CONSTRAINT account_sessions_expiry_order CHECK (idle_expires_at > created_at AND expires_at > created_at)
);

CREATE INDEX account_sessions_user_idx
  ON account_sessions (realm_name, user_id, last_seen_at DESC);
CREATE INDEX account_sessions_expiry_idx ON account_sessions (expires_at);
CREATE INDEX account_sessions_idle_expiry_idx ON account_sessions (idle_expires_at);

CREATE TABLE account_action_tokens (
  realm_name VARCHAR(63) NOT NULL,
  token_digest CHAR(43) NOT NULL,
  user_id UUID NOT NULL,
  token_type TEXT NOT NULL,
  target_email TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (realm_name, token_digest),
  UNIQUE (realm_name, token_type, user_id),
  FOREIGN KEY (realm_name, user_id) REFERENCES users(realm_name, id) ON DELETE CASCADE,
  CONSTRAINT account_action_tokens_digest_format CHECK (token_digest ~ '^[A-Za-z0-9_-]{43}$'),
  CONSTRAINT account_action_tokens_type_known CHECK (token_type IN ('email-verification', 'password-reset')),
  CONSTRAINT account_action_tokens_context CHECK (
    (token_type = 'email-verification' AND target_email IS NOT NULL AND length(btrim(target_email)) > 0)
    OR (token_type = 'password-reset' AND target_email IS NULL)
  )
);

CREATE INDEX account_action_tokens_expiry_idx ON account_action_tokens (expires_at);
