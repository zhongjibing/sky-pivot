package com.icezhg.sky.pivot.dto;

import java.util.List;

public record SyncPullResponse(
    List<SyncLogEntry> entries,
    long currentSyncVersion
) {}
