package com.icezhg.sky.pivot.dto;

public record RecoveryTokenResponse(
    String recoveryToken,
    long expiresAt
) {}
