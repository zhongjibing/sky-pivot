package com.icezhg.sky.pivot.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@Table(name = "users", indexes = {
    @Index(name = "idx_users_openid", columnList = "openid", unique = true),
    @Index(name = "idx_users_status", columnList = "status")
})
@EntityListeners(AuditingEntityListener.class)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 64)
    private String openid;

    @Column(length = 128)
    private String nickname;

    @Column(length = 512)
    private String avatarUrl;

    @Column(name = "master_password_salt", nullable = false, length = 128)
    private String masterPasswordSalt = "";

    @Column(name = "master_password_hash", nullable = false, length = 256)
    private String masterPasswordHash = "";

    @Column(name = "last_master_password_verified_at")
    private LocalDateTime lastMasterPasswordVerifiedAt;

    @Column(name = "encrypted_dek", nullable = false, length = 512)
    private String encryptedDek = "";

    @Column(name = "kek_verification", nullable = false, length = 512)
    private String kekVerification = "";

    @Column(name = "biometric_token_salt", length = 128)
    private String biometricTokenSalt;

    @Column(name = "encrypted_kek_for_biometric", length = 512)
    private String encryptedKekForBiometric;

    @Column(name = "sync_version", nullable = false)
    private Long syncVersion = 0L;

    @Column(name = "last_sync_at")
    private LocalDateTime lastSyncAt;

    @Column(nullable = false, columnDefinition = "TINYINT")
    private Integer status = 0;

    @CreatedDate
    @Setter(AccessLevel.NONE)
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Setter(AccessLevel.NONE)
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    public boolean isMasterPasswordSet() {
        return masterPasswordHash != null && !masterPasswordHash.isEmpty();
    }
}
