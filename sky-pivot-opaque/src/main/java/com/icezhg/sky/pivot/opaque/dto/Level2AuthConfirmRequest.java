package com.icezhg.sky.pivot.opaque.dto;

import jakarta.validation.constraints.NotBlank;

public record Level2AuthConfirmRequest(
        @NotBlank String requestId,
        @NotBlank String totpCode
) {}
