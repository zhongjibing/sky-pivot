package com.icezhg.sky.pivot.dto;

import java.time.LocalDateTime;

public record AuditLogResponse(
        Long id,
        Long userId,
        String deviceId,
        String action,
        String level,
        String targetId,
        String targetType,
        String ipAddress,
        String userAgent,
        String result,
        String reason,
        String requestId,
        Integer latencyMs,
        String sessionId,
        String dataBefore,
        String dataAfter,
        LocalDateTime createdAt
) {
    public static AuditLogResponse from(com.icezhg.sky.pivot.entity.AuditLog entity) {
        return new AuditLogResponse(
                entity.getId(),
                entity.getUserId(),
                entity.getDeviceId(),
                entity.getAction(),
                entity.getLevel(),
                entity.getTargetId(),
                entity.getTargetType(),
                entity.getIpAddress(),
                entity.getUserAgent(),
                entity.getResult(),
                entity.getReason(),
                entity.getRequestId(),
                entity.getLatencyMs(),
                entity.getSessionId(),
                entity.getDataBefore(),
                entity.getDataAfter(),
                entity.getCreatedAt()
        );
    }
}
