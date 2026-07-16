ALTER TABLE users
  ADD COLUMN has_local_password BOOLEAN NOT NULL DEFAULT TRUE,
  ADD COLUMN ldap_sync_disable_provider_id VARCHAR(64),
  ADD COLUMN ldap_sync_disable_issuer TEXT,
  ADD CONSTRAINT users_ldap_sync_disable_owner_consistent CHECK (
    (ldap_sync_disable_provider_id IS NULL) = (ldap_sync_disable_issuer IS NULL)
    AND (NOT enabled OR ldap_sync_disable_provider_id IS NULL)
  ),
  ADD CONSTRAINT users_ldap_sync_disable_provider_format CHECK (
    ldap_sync_disable_provider_id IS NULL
    OR ldap_sync_disable_provider_id ~ '^[a-z][a-z0-9-]{1,63}$'
  ),
  ADD CONSTRAINT users_ldap_sync_disable_issuer_valid CHECK (
    ldap_sync_disable_issuer IS NULL
    OR (length(ldap_sync_disable_issuer) BETWEEN 1 AND 2048
      AND ldap_sync_disable_issuer !~ '[[:cntrl:]]')
  );

ALTER TABLE federated_identities
  ADD COLUMN last_sync_id UUID,
  ADD COLUMN last_synced_at TIMESTAMPTZ,
  ADD COLUMN sync_created_user BOOLEAN NOT NULL DEFAULT FALSE,
  ADD CONSTRAINT federated_identities_sync_marker_consistent CHECK (
    (last_sync_id IS NULL) = (last_synced_at IS NULL)
  );

CREATE INDEX federated_identities_sync_reconciliation_idx
  ON federated_identities
    (realm_name, provider_id, issuer, last_sync_id, external_subject);
