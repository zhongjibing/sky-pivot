package com.icezhg.sky.pivot.opaque.dto;

public record EmergencyAuthChallengeResponse(
        String requestId,
        String recoverySalt,
        String challenge,
        String expiresAt
) {}
