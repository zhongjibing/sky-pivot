package com.icezhg.sky.pivot.entity;

import jakarta.persistence.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
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
    private String masterPasswordSalt;

    @Column(name = "master_password_hash", nullable = false, length = 256)
    private String masterPasswordHash;

    @Column(name = "last_master_password_verified_at")
    private LocalDateTime lastMasterPasswordVerifiedAt;

    @Column(name = "encrypted_dek", nullable = false, length = 512)
    private String encryptedDek;

    @Column(name = "kek_verification", nullable = false, length = 512)
    private String kekVerification;

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
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getOpenid() { return openid; }
    public void setOpenid(String openid) { this.openid = openid; }

    public String getNickname() { return nickname; }
    public void setNickname(String nickname) { this.nickname = nickname; }

    public String getAvatarUrl() { return avatarUrl; }
    public void setAvatarUrl(String avatarUrl) { this.avatarUrl = avatarUrl; }

    public String getMasterPasswordSalt() { return masterPasswordSalt; }
    public void setMasterPasswordSalt(String masterPasswordSalt) { this.masterPasswordSalt = masterPasswordSalt; }

    public String getMasterPasswordHash() { return masterPasswordHash; }
    public void setMasterPasswordHash(String masterPasswordHash) { this.masterPasswordHash = masterPasswordHash; }

    public LocalDateTime getLastMasterPasswordVerifiedAt() { return lastMasterPasswordVerifiedAt; }
    public void setLastMasterPasswordVerifiedAt(LocalDateTime lastMasterPasswordVerifiedAt) { this.lastMasterPasswordVerifiedAt = lastMasterPasswordVerifiedAt; }

    public String getEncryptedDek() { return encryptedDek; }
    public void setEncryptedDek(String encryptedDek) { this.encryptedDek = encryptedDek; }

    public String getKekVerification() { return kekVerification; }
    public void setKekVerification(String kekVerification) { this.kekVerification = kekVerification; }

    public String getBiometricTokenSalt() { return biometricTokenSalt; }
    public void setBiometricTokenSalt(String biometricTokenSalt) { this.biometricTokenSalt = biometricTokenSalt; }

    public String getEncryptedKekForBiometric() { return encryptedKekForBiometric; }
    public void setEncryptedKekForBiometric(String encryptedKekForBiometric) { this.encryptedKekForBiometric = encryptedKekForBiometric; }

    public Long getSyncVersion() { return syncVersion; }
    public void setSyncVersion(Long syncVersion) { this.syncVersion = syncVersion; }

    public LocalDateTime getLastSyncAt() { return lastSyncAt; }
    public void setLastSyncAt(LocalDateTime lastSyncAt) { this.lastSyncAt = lastSyncAt; }

    public Integer getStatus() { return status; }
    public void setStatus(Integer status) { this.status = status; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }

    public boolean isMasterPasswordSet() {
        return masterPasswordSalt != null && masterPasswordHash != null;
    }
}
