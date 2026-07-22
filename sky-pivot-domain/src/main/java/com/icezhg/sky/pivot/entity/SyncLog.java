package com.icezhg.sky.pivot.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.io.Serializable;

@Entity
@Data
@IdClass(SyncLogId.class)
@Table(name = "sync_log", indexes = {
    @Index(name = "idx_sync_user_time", columnList = "user_id, client_timestamp")
})
public class SyncLog implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Id
    @Column(name = "server_timestamp", nullable = false)
    private Long serverTimestamp;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "device_id", nullable = false, length = 64)
    private String deviceId;

    @Column(name = "op_id", nullable = false, length = 64)
    private String opId;

    @Column(nullable = false, length = 16)
    private String operation;

    @Column(name = "target_type", nullable = false, length = 16)
    private String targetType = "VAULT_ITEM";

    @Column(name = "target_id", nullable = false, length = 64)
    private String targetId;

    @Column(name = "target_version", nullable = false)
    private Long targetVersion;

    @Column(name = "client_timestamp", nullable = false)
    private Long clientTimestamp;

    @Column(name = "lamport_clock", nullable = false)
    private Long lamportClock = 0L;

    @Column(name = "device_signature", nullable = false, length = 256)
    private String deviceSignature;
}
