package com.icezhg.sky.pivot.opaque.dto;

import jakarta.validation.constraints.NotBlank;

public record OpaqueLoginFinishRequest(
        @NotBlank String sessionToken,
        @NotBlank String credentialIdentifierBase64,
        @NotBlank String clientMacBase64) {
}
