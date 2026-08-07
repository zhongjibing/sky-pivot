package com.icezhg.sky.pivot.service;

import com.icezhg.sky.pivot.dto.SyncLogEntry;

import java.util.List;

public record SyncEvent(
    Long userId,
    long newVersion,
    List<SyncLogEntry> changedEntries
) {}
