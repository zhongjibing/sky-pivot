package com.icezhg.sky.pivot.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@Table(name = "sync_versions", indexes = {
    @Index(name = "idx_sync_user", columnList = "user_id", unique = true)
})
@EntityListeners(AuditingEntityListener.class)
public class SyncVersion {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(nullable = false)
    private Long version = 0L;

    @LastModifiedDate
    @Setter(AccessLevel.NONE)
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    public void incrementVersion() {
        this.version++;
    }
}
