ALTER TABLE oidc_records
  ADD COLUMN ciba_poll_interval_seconds INTEGER,
  ADD COLUMN ciba_next_poll_at TIMESTAMPTZ,
  ADD CONSTRAINT oidc_records_ciba_poll_interval CHECK (
    ciba_poll_interval_seconds IS NULL
    OR (model = 'BackchannelAuthenticationRequest' AND ciba_poll_interval_seconds BETWEEN 1 AND 300)
  ),
  ADD CONSTRAINT oidc_records_ciba_poll_state CHECK (
    (ciba_poll_interval_seconds IS NULL) = (ciba_next_poll_at IS NULL)
  );
