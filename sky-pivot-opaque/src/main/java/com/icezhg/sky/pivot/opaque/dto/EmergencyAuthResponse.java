package com.icezhg.sky.pivot.opaque.dto;

public record EmergencyAuthResponse(
        String deviceId,
        boolean authorized,
        boolean emergencyMode,
        String expiresAt,
        boolean requiresNewRecoveryCode
) {}
