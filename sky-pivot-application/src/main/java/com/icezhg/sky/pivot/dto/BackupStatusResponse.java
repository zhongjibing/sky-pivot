package com.icezhg.sky.pivot.dto;

import java.time.LocalDateTime;

public record BackupStatusResponse(
        String status,
        LocalDateTime lastBackupAt,
        long lastBackupSize,
        int totalBackups,
        LocalDateTime nextScheduledAt
) {}
