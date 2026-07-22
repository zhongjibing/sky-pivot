package com.icezhg.sky.pivot.entity;

import jakarta.persistence.*;
import lombok.Data;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.io.Serializable;
import java.time.LocalDateTime;

@Entity
@Data
@IdClass(AuditLogId.class)
@Table(name = "audit_log", indexes = {
    @Index(name = "idx_audit_user_time", columnList = "user_id, created_at"),
    @Index(name = "idx_audit_action", columnList = "action, created_at"),
    @Index(name = "idx_audit_request", columnList = "request_id")
})
@EntityListeners(AuditingEntityListener.class)
public class AuditLog implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Id
    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "device_id", length = 64)
    private String deviceId;

    @Column(nullable = false, length = 32)
    private String action;

    @Column(name = "target_id", length = 64)
    private String targetId;

    @Column(name = "target_type", length = 32)
    private String targetType;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_agent", length = 512)
    private String userAgent;

    @Column(nullable = false, length = 16)
    private String result = "SUCCESS";

    @Column(length = 256)
    private String reason;

    @Column(name = "request_id", length = 64)
    private String requestId;

    @Column(name = "latency_ms")
    private Integer latencyMs;

    @Column(name = "session_id", length = 64)
    private String sessionId;

    @Column(name = "data_before", length = 256)
    private String dataBefore;

    @Column(name = "data_after", length = 256)
    private String dataAfter;
}
