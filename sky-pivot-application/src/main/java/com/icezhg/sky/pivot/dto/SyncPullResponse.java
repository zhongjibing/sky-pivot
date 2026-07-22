package com.icezhg.sky.pivot.dto;

import java.time.LocalDateTime;
import java.util.List;

public record SyncPullResponse(List<SyncChange> changes) {
    public record SyncChange(
        String type,
        Long entityId,
        String title,
        String account,
        String url,
        String healthLevel,
        LocalDateTime updatedAt,
        LocalDateTime deletedAt
    ) {}
}
