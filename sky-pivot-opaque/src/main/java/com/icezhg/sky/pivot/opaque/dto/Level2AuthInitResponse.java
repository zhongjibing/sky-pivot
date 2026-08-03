package com.icezhg.sky.pivot.opaque.dto;

public record Level2AuthInitResponse(
        String requestId,
        String fingerprint,
        String expiresAt
) {}
