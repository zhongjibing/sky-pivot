package com.icezhg.sky.pivot.opaque.dto;

import jakarta.validation.constraints.NotBlank;

public record EmergencyAuthVerifyRequest(
        @NotBlank String requestId,
        @NotBlank String recoveryKeyHash,
        @NotBlank String smsCode,
        @NotBlank String deviceId,
        @NotBlank String deviceName,
        @NotBlank String deviceType,
        @NotBlank String ed25519PublicKey
) {}
