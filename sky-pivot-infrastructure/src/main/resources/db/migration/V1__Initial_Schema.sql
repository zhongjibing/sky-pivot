-- Sky Pivot V1 Migration: Initial schema
-- MySQL 8.0+

CREATE TABLE IF NOT EXISTS users (
    id                                  BIGINT          AUTO_INCREMENT PRIMARY KEY,
    openid                              VARCHAR(64)     NOT NULL,
    nickname                            VARCHAR(128)    NULL,
    avatar_url                          VARCHAR(512)    NULL,
    master_password_salt                VARCHAR(128)    NULL COMMENT 'Salt for KEK derivation (Base64)',
    master_password_hash                VARCHAR(256)    NULL COMMENT 'Master password BCrypt hash',
    last_master_password_verified_at    DATETIME        NULL COMMENT 'Last master password verification time',
    encrypted_dek                       VARCHAR(512)    NULL COMMENT 'DEK encrypted by KEK (AES-256-GCM, Base64)',
    kek_verification                    VARCHAR(512)    NULL COMMENT 'Encrypted VERIFICATION string by KEK',
    biometric_token_salt                VARCHAR(128)    NULL COMMENT 'Salt for biometric token key derivation (Base64)',
    encrypted_kek_for_biometric         VARCHAR(512)    NULL COMMENT 'KEK encrypted by biometric token key (AES-256-GCM, Base64)',
    sync_version                        BIGINT          NOT NULL DEFAULT 0,
    last_sync_at                        DATETIME        NULL,
    status                              TINYINT         NOT NULL DEFAULT 0 COMMENT '0-active 1-disabled 2-deleted',
    created_at                          DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                          DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE INDEX idx_users_openid (openid),
    INDEX idx_users_status (status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS passwords (
    id                      BIGINT          AUTO_INCREMENT PRIMARY KEY,
    user_id                 BIGINT          NOT NULL,
    title                   VARCHAR(256)    NOT NULL,
    url                     VARCHAR(2048)   NULL,
    account                 VARCHAR(256)    NOT NULL,
    encrypted_password      TEXT            NOT NULL COMMENT 'Password encrypted with AES-256-GCM (Base64)',
    notes                   TEXT            NULL COMMENT 'Notes (plaintext)',
    health_score            TINYINT         NULL COMMENT 'Password health score 0-100',
    health_level            VARCHAR(16)     NULL COMMENT 'WEAK/FAIR/STRONG/VERY_STRONG',
    created_at              DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at              DATETIME        NULL COMMENT 'Soft delete flag',
    INDEX idx_passwords_user_id (user_id),
    INDEX idx_passwords_user_active (user_id, deleted_at),
    INDEX idx_passwords_user_trash (user_id, deleted_at),
    INDEX idx_passwords_health (user_id, health_level),
    INDEX idx_passwords_deleted_at (deleted_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS sync_versions (
    id          BIGINT      AUTO_INCREMENT PRIMARY KEY,
    user_id     BIGINT      NOT NULL,
    version     BIGINT      NOT NULL DEFAULT 0,
    updated_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE INDEX idx_sync_user (user_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS login_history (
    id              BIGINT          AUTO_INCREMENT PRIMARY KEY,
    user_id         BIGINT          NOT NULL,
    login_type      VARCHAR(16)     NOT NULL COMMENT 'MINIAPP/PC',
    ip_address      VARCHAR(45)     NULL,
    device_info     VARCHAR(256)    NULL,
    login_at        DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_login_user (user_id, login_at)
) ENGINE=InnoDB;
