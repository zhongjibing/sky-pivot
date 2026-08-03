package com.icezhg.sky.pivot.opaque.dto;

public record DeviceListItem(
        String deviceId,
        String deviceName,
        String deviceType,
        boolean authorized,
        boolean revoked,
        String lastSeen,
        String createdAt
) {}
