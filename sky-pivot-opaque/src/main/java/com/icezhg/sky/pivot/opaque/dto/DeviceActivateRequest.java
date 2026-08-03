package com.icezhg.sky.pivot.opaque.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record DeviceActivateRequest(
        @NotBlank String deviceId,
        @NotBlank String deviceName,
        @NotBlank @Pattern(regexp = "PC|MINIAPP") String deviceType,
        @NotBlank String ed25519PublicKey
) {}
