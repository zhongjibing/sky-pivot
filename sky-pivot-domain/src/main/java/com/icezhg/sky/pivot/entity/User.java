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
    @Index(name = "idx_users_status", columnList = "status")
})
@EntityListeners(AuditingEntityListener.class)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Lob
    @Column(name = "opaque_server_record", nullable = false, columnDefinition = "BLOB")
    private byte[] opaqueServerRecord;

    @Lob
    @Column(name = "opaque_client_record", nullable = false, columnDefinition = "BLOB")
    private byte[] opaqueClientRecord;

    @Column(name = "salt", nullable = false, length = 128)
    private String salt;

    @Column(name = "encrypted_dek", nullable = false, length = 1024)
    private String encryptedDek;

    @Column(name = "encrypted_urk_recovery", nullable = false, length = 1024)
    private String encryptedUrkRecovery;

    @Column(name = "recovery_salt", nullable = false, length = 128)
    private String recoverySalt;

    @Column(name = "recovery_key_hash", nullable = false, length = 128)
    private String recoveryKeyHash;

    @Column(name = "encrypted_profile", columnDefinition = "TEXT")
    private String encryptedProfile;

    @Column(name = "sync_version", nullable = false)
    private Long syncVersion = 0L;

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
}
