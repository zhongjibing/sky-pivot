package com.icezhg.sky.pivot.opaque.dto;

import jakarta.validation.constraints.NotBlank;

public record OpaqueCredentialUpdateRequest(
        @NotBlank String credentialIdentifierBase64,
        @NotBlank String clientPublicKeyBase64,
        @NotBlank String maskingKeyBase64,
        @NotBlank String envelopeNonceBase64,
        @NotBlank String authTagBase64) {
}
