package com.icezhg.sky.pivot.opaque.dto;

public record OpaqueLoginFinishResponse(
        String sessionToken,
        String userId) {
}
