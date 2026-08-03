package com.icezhg.sky.pivot.opaque.dto;

import jakarta.validation.constraints.NotBlank;

public record Level2AuthInitRequest(
        @NotBlank String tempPublicKey,
        @NotBlank String fingerprint
) {}
