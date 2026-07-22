package com.icezhg.sky.pivot.entity;

import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.annotations.SQLRestriction;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Data
@Table(name = "vault_items", indexes = {
    @Index(name = "idx_vault_user", columnList = "user_id"),
    @Index(name = "idx_vault_user_active", columnList = "user_id, deleted_at"),
    @Index(name = "idx_vault_user_item", columnList = "user_id, item_id", unique = true)
})
@EntityListeners(AuditingEntityListener.class)
@SQLRestriction("deleted_at IS NULL")
public class VaultItem {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "item_id", nullable = false, length = 64)
    private String itemId;

    @Column(name = "encrypted_blob", nullable = false, columnDefinition = "LONGTEXT")
    private String encryptedBlob;

    @Column(nullable = false)
    private Long version = 0L;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;
}
