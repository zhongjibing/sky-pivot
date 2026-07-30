package com.icezhg.sky.pivot.opaque.dto;

import jakarta.validation.constraints.NotBlank;

public record OpaqueRegisterStartRequest(
        @NotBlank String credentialIdentifierBase64,
        @NotBlank String blindedElementBase64) {
}
