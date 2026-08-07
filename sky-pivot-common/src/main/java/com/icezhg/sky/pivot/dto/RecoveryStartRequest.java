package com.icezhg.sky.pivot.dto;

import jakarta.validation.constraints.NotBlank;

public record RecoveryStartRequest(
    @NotBlank(message = "requestId must not be blank")
    String requestId,

    @NotBlank(message = "authCode must not be blank")
    String authCode
) {}
