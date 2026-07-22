-- Sky Pivot V2: E2EE Schema (TASK-002)
-- Replaces V1 server-side encryption schema with zero-trust E2EE design
-- Design reference: doc/DESIGN_V5_4_E2EE.md §11
-- Requires: MySQL 8.0+ with event_scheduler privilege

-- Drop old server-side encryption tables (reverse FK order)
DROP TABLE IF EXISTS sync_versions;
DROP TABLE IF EXISTS passwords;
DROP TABLE IF EXISTS login_history;
DROP TABLE IF EXISTS users;

-- ============================================================================
-- 1. users — OPAQUE records, encrypted DEK, recovery materials
-- ============================================================================
CREATE TABLE users (
    id                      BIGINT          AUTO_INCREMENT PRIMARY KEY,
    opaque_server_record    BLOB            NOT NULL COMMENT 'Hofmann OPAQUE 服务端记录',
    opaque_client_record    BLOB            NOT NULL COMMENT 'Hofmann OPAQUE 客户端记录',
    salt                    VARCHAR(128)    NOT NULL COMMENT 'URK 派生盐值',
    encrypted_dek           VARCHAR(1024)   NOT NULL COMMENT 'URK 加密的 DEK',
    encrypted_urk_recovery  VARCHAR(1024)   NOT NULL COMMENT 'Recovery Key 加密的 URK',
    recovery_salt           VARCHAR(128)    NOT NULL COMMENT 'Recovery Key 派生盐值',
    recovery_key_hash       VARCHAR(128)    NOT NULL COMMENT 'SHA-256(RecoveryKey)',
    encrypted_profile       TEXT            NULL COMMENT '用户资料密文',
    sync_version            BIGINT          NOT NULL DEFAULT 0,
    status                  TINYINT         NOT NULL DEFAULT 0 COMMENT '0-正常 1-禁用 2-已注销',
    created_at              DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_users_status (status)
) ENGINE=InnoDB;

-- ============================================================================
-- 2. devices — Device public keys, authorization status
-- ============================================================================
CREATE TABLE devices (
    id                  BIGINT          AUTO_INCREMENT PRIMARY KEY,
    user_id             BIGINT          NOT NULL,
    device_id           VARCHAR(64)     NOT NULL,
    device_name         VARCHAR(128)    NOT NULL,
    device_type         VARCHAR(16)     NOT NULL COMMENT 'PC/MINIAPP',
    ed25519_public_key  VARCHAR(128)    NOT NULL COMMENT 'Ed25519 公钥（验证 AT 签名 + 设备签名）',
    authorized          BOOLEAN         NOT NULL DEFAULT FALSE,
    revoked             BOOLEAN         NOT NULL DEFAULT FALSE,
    revoked_at          DATETIME        NULL,
    last_seen           DATETIME        NULL,
    created_at          DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_devices_user (user_id),
    UNIQUE INDEX idx_devices_user_device (user_id, device_id),
    CONSTRAINT fk_devices_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ============================================================================
-- 3. vault_items — Encrypted blob, version, soft delete
-- ============================================================================
CREATE TABLE vault_items (
    id              BIGINT          AUTO_INCREMENT PRIMARY KEY,
    user_id         BIGINT          NOT NULL,
    item_id         VARCHAR(64)     NOT NULL COMMENT '客户端生成的条目UUID',
    encrypted_blob  LONGTEXT        NOT NULL COMMENT '完整加密条目JSON（含 encrypted_rk）',
    version         BIGINT          NOT NULL DEFAULT 0 COMMENT 'Lamport 逻辑时钟',
    created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at      DATETIME        NULL COMMENT '软删除标记',
    INDEX idx_vault_user (user_id),
    INDEX idx_vault_user_active (user_id, deleted_at),
    UNIQUE INDEX idx_vault_user_item (user_id, item_id),
    CONSTRAINT fk_vault_items_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ============================================================================
-- 4. sync_log — Partitioned by day (via server_timestamp), auto partition maintenance
-- ============================================================================
CREATE TABLE sync_log (
    id                  BIGINT          AUTO_INCREMENT,
    user_id             BIGINT          NOT NULL,
    device_id           VARCHAR(64)     NOT NULL,
    op_id               VARCHAR(64)     NOT NULL,
    operation           VARCHAR(16)     NOT NULL,
    target_type         VARCHAR(16)     NOT NULL DEFAULT 'VAULT_ITEM',
    target_id           VARCHAR(64)     NOT NULL,
    target_version      BIGINT          NOT NULL,
    client_timestamp    BIGINT          NOT NULL,
    server_timestamp    BIGINT          NOT NULL,
    lamport_clock       BIGINT          NOT NULL DEFAULT 0 COMMENT '逻辑时钟',
    device_signature    VARCHAR(256)    NOT NULL,
    PRIMARY KEY (id, server_timestamp),
    INDEX idx_sync_user_time (user_id, client_timestamp),
    CONSTRAINT fk_sync_log_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB
PARTITION BY RANGE (FLOOR(server_timestamp / 86400000)) (
    PARTITION p2026 VALUES LESS THAN (FLOOR(UNIX_TIMESTAMP('2027-01-01') / 86400)),
    PARTITION p2027 VALUES LESS THAN (FLOOR(UNIX_TIMESTAMP('2028-01-01') / 86400)),
    PARTITION p2028 VALUES LESS THAN (FLOOR(UNIX_TIMESTAMP('2029-01-01') / 86400)),
    PARTITION p_future VALUES LESS THAN MAXVALUE
);

-- ============================================================================
-- 5. sync_log_archive — Mirror of sync_log for archival
-- ============================================================================
CREATE TABLE sync_log_archive LIKE sync_log;

-- ============================================================================
-- 6. audit_log — Partitioned by year, auto partition maintenance
-- ============================================================================
CREATE TABLE audit_log (
    id              BIGINT          AUTO_INCREMENT,
    user_id         BIGINT          NOT NULL,
    device_id       VARCHAR(64)     NULL,
    action          VARCHAR(32)     NOT NULL,
    target_id       VARCHAR(64)     NULL,
    target_type     VARCHAR(32)     NULL,
    ip_address      VARCHAR(45)     NULL,
    user_agent      VARCHAR(512)    NULL,
    result          VARCHAR(16)     NOT NULL DEFAULT 'SUCCESS',
    reason          VARCHAR(256)    NULL,
    request_id      VARCHAR(64)     NULL COMMENT '关联请求ID',
    latency_ms      INT             NULL COMMENT '请求响应耗时(ms)',
    session_id      VARCHAR(64)     NULL COMMENT 'JWT jti',
    data_before     VARCHAR(256)    NULL COMMENT '变更前数据哈希',
    data_after      VARCHAR(256)    NULL COMMENT '变更后数据哈希',
    created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, created_at),
    INDEX idx_audit_user_time (user_id, created_at),
    INDEX idx_audit_action (action, created_at),
    INDEX idx_audit_request (request_id),
    CONSTRAINT fk_audit_log_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB
PARTITION BY RANGE (YEAR(created_at)) (
    PARTITION p2026 VALUES LESS THAN (2027),
    PARTITION p2027 VALUES LESS THAN (2028),
    PARTITION p2028 VALUES LESS THAN (2029),
    PARTITION p_future VALUES LESS THAN MAXVALUE
);

-- ============================================================================
-- 7. login_history — Login history with device_id
-- ============================================================================
CREATE TABLE login_history (
    id              BIGINT          AUTO_INCREMENT PRIMARY KEY,
    user_id         BIGINT          NOT NULL,
    device_id       VARCHAR(64)     NULL,
    login_type      VARCHAR(16)     NOT NULL COMMENT 'OPAQUE/REFRESH/RECOVERY',
    ip_address      VARCHAR(45)     NULL,
    device_info     VARCHAR(256)    NULL,
    login_at        DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_login_user (user_id, login_at),
    CONSTRAINT fk_login_history_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ============================================================================
-- 8. shared_vaults + shared_vault_members — Reserved for sharing (Phase 4+)
-- ============================================================================
CREATE TABLE shared_vaults (
    id              BIGINT          AUTO_INCREMENT PRIMARY KEY,
    vault_id        VARCHAR(64)     NOT NULL,
    owner_id        BIGINT          NOT NULL,
    encrypted_name  VARCHAR(512)    NOT NULL COMMENT '加密名称',
    created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_shared_owner (owner_id),
    CONSTRAINT fk_shared_vaults_owner FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE shared_vault_members (
    id              BIGINT          AUTO_INCREMENT PRIMARY KEY,
    vault_id        VARCHAR(64)     NOT NULL,
    user_id         BIGINT          NOT NULL,
    encrypted_sdek  VARCHAR(1024)   NOT NULL COMMENT 'SDEK 用成员公钥加密',
    role            VARCHAR(16)     NOT NULL DEFAULT 'MEMBER' COMMENT 'OWNER/ADMIN/MEMBER',
    created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_shared_member (user_id),
    CONSTRAINT fk_shared_members_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ============================================================================
-- Partition maintenance events (auto-create next year's partition)
-- Requires: SET GLOBAL event_scheduler = ON (MySQL SUPER/SYSTEM_VARIABLES_ADMIN)
-- ============================================================================
DELIMITER //

CREATE EVENT IF NOT EXISTS sync_log_create_partition
ON SCHEDULE EVERY 1 YEAR
STARTS '2027-01-01 00:00:00'
DO
BEGIN
    DECLARE next_year INT;
    DECLARE partition_name VARCHAR(10);
    DECLARE boundary_date VARCHAR(10);
    SET next_year = YEAR(CURDATE()) + 1;
    SET partition_name = CONCAT('p', next_year);
    SET boundary_date = CONCAT(next_year + 1, '-01-01');
    SET @sql = CONCAT(
        'ALTER TABLE sync_log REORGANIZE PARTITION p_future INTO (',
        'PARTITION ', partition_name, ' VALUES LESS THAN (FLOOR(UNIX_TIMESTAMP("', boundary_date, '") / 86400)),',
        'PARTITION p_future VALUES LESS THAN MAXVALUE',
        ')'
    );
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END//

CREATE EVENT IF NOT EXISTS audit_log_create_partition
ON SCHEDULE EVERY 1 YEAR
STARTS '2027-01-01 00:00:00'
DO
BEGIN
    DECLARE next_year INT;
    DECLARE partition_name VARCHAR(10);
    SET next_year = YEAR(CURDATE()) + 1;
    SET partition_name = CONCAT('p', next_year);
    SET @sql = CONCAT(
        'ALTER TABLE audit_log REORGANIZE PARTITION p_future INTO (',
        'PARTITION ', partition_name, ' VALUES LESS THAN (', next_year + 1, '),',
        'PARTITION p_future VALUES LESS THAN MAXVALUE',
        ')'
    );
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END//

DELIMITER ;

-- Enabled in application config or by DBA: SET GLOBAL event_scheduler = ON;
