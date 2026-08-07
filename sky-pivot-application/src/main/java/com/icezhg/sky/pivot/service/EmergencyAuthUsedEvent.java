package com.icezhg.sky.pivot.service;

public record EmergencyAuthUsedEvent(
    Long userId,
    String deviceId,
    String deviceName
) {}
