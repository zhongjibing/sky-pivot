package com.icezhg.sky.pivot.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Data
@Table(name = "login_history", indexes = {
    @Index(name = "idx_login_user", columnList = "user_id, login_at")
})
public class LoginHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "device_id", length = 64)
    private String deviceId;

    @Column(name = "login_type", nullable = false, length = 16)
    private String loginType;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "device_info", length = 256)
    private String deviceInfo;

    @Column(name = "login_at", nullable = false)
    private LocalDateTime loginAt = LocalDateTime.now();
}
