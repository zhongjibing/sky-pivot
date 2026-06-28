package com.icezhg.sky.pivot.dto;

import jakarta.validation.constraints.NotBlank;

public record BiometricVerifyRequest(
    @NotBlank(message = "Biometric result is required")
    String biometricResult
) {}
