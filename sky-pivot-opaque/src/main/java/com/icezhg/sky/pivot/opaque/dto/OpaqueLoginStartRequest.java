package com.icezhg.sky.pivot.opaque.dto;

import jakarta.validation.constraints.NotBlank;

public record OpaqueLoginStartRequest(
        @NotBlank String credentialIdentifierBase64,
        @NotBlank String blindedElementBase64,
        @NotBlank String clientNonceBase64,
        @NotBlank String clientAkePublicKeyBase64) {
}
