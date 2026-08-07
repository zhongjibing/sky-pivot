package com.icezhg.sky.pivot.dto;

public record SyncPushResponse(
    int acceptedCount,
    long currentSyncVersion
) {}
