package com.icezhg.sky.pivot.service;

public record DeviceAuthRequestedEvent(
    Long userId,
    String requestId,
    String deviceName,
    String fingerprint
) {}
