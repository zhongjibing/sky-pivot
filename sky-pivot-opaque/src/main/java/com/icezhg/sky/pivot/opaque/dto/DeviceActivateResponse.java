package com.icezhg.sky.pivot.opaque.dto;

public record DeviceActivateResponse(
        String deviceId,
        String deviceName,
        String deviceType,
        boolean authorized,
        boolean isFirstDevice,
        String createdAt
) {}
