package com.icezhg.sky.pivot.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.SQLRestriction;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@Table(name = "passwords", indexes = {
    @Index(name = "idx_passwords_user_id", columnList = "user_id"),
    @Index(name = "idx_passwords_user_active", columnList = "user_id, deleted_at"),
    @Index(name = "idx_passwords_user_trash", columnList = "user_id, deleted_at"),
    @Index(name = "idx_passwords_health", columnList = "user_id, health_level"),
    @Index(name = "idx_passwords_deleted_at", columnList = "deleted_at")
})
@EntityListeners(AuditingEntityListener.class)
@SQLRestriction("deleted_at IS NULL")
public class Password {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(nullable = false, length = 256)
    private String title;

    @Column(length = 2048)
    private String url;

    @Column(nullable = false, length = 256)
    private String account;

    @Column(name = "encrypted_password", nullable = false, columnDefinition = "TEXT")
    private String encryptedPassword;

    @Column(columnDefinition = "TEXT")
    private String notes;

    @Column(name = "health_score", columnDefinition = "TINYINT")
    private Integer healthScore;

    @Column(name = "health_level", length = 16)
    private String healthLevel;

    @CreatedDate
    @Setter(AccessLevel.NONE)
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Setter(AccessLevel.NONE)
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;

    public boolean isDeleted() {
        return deletedAt != null;
    }
}
