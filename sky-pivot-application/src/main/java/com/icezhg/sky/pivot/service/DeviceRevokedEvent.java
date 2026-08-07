package com.icezhg.sky.pivot.service;

public record DeviceRevokedEvent(
    Long userId,
    String deviceId,
    String deviceName
) {}
