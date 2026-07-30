ALTER TABLE users
    ADD COLUMN credential_identifier VARCHAR(256) NOT NULL DEFAULT '' COMMENT 'Base64 encoded credential identifier for OPAQUE lookup'
    AFTER id;

ALTER TABLE users
    ADD UNIQUE INDEX idx_users_credential_identifier (credential_identifier);

UPDATE users SET credential_identifier = CONCAT('legacy-', id) WHERE credential_identifier = '';
