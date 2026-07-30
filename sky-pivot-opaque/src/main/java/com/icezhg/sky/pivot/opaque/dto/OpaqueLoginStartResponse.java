package com.icezhg.sky.pivot.opaque.dto;

public record OpaqueLoginStartResponse(
        String sessionToken,
        String evaluatedElementBase64,
        String maskingNonceBase64,
        String maskedResponseBase64,
        String serverNonceBase64,
        String serverAkePublicKeyBase64,
        String serverMacBase64) {
}
