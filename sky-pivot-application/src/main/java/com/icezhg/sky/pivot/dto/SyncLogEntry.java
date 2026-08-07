package com.icezhg.sky.pivot.dto;

public record SyncLogEntry(
    String opId,
    String deviceId,
    String operation,
    String targetType,
    String targetId,
    Long targetVersion,
    Long clientTimestamp,
    Long serverTimestamp,
    Long lamportClock
) {}
