package com.icezhg.sky.pivot.entity;

import jakarta.persistence.*;
import lombok.Data;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Data
@Table(name = "shared_vault_members", indexes = {
    @Index(name = "idx_shared_member", columnList = "user_id")
})
@EntityListeners(AuditingEntityListener.class)
public class SharedVaultMember {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "vault_id", nullable = false, length = 64)
    private String vaultId;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "encrypted_sdek", nullable = false, length = 1024)
    private String encryptedSdek;

    @Column(nullable = false, length = 16)
    private String role = "MEMBER";

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
}
