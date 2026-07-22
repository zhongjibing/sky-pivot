package com.icezhg.sky.pivot.entity;

import jakarta.persistence.*;
import lombok.Data;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Data
@Table(name = "shared_vaults", indexes = {
    @Index(name = "idx_shared_owner", columnList = "owner_id")
})
@EntityListeners(AuditingEntityListener.class)
public class SharedVault {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "vault_id", nullable = false, length = 64)
    private String vaultId;

    @Column(name = "owner_id", nullable = false)
    private Long ownerId;

    @Column(name = "encrypted_name", nullable = false, length = 512)
    private String encryptedName;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
}
