package com.icezhg.sky.pivot.opaque.dto;

import jakarta.validation.constraints.NotBlank;

public record Level2AuthCompleteRequest(
        @NotBlank String requestId,
        @NotBlank String encryptedDek,
        @NotBlank String ed25519PublicKey,
        @NotBlank String deviceId,
        @NotBlank String deviceName,
        @NotBlank String deviceType
) {}
