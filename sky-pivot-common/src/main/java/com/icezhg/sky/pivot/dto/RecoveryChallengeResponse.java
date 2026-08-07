package com.icezhg.sky.pivot.dto;

public record RecoveryChallengeResponse(
    String requestId,
    String challenge,
    long expiresAt
) {}
