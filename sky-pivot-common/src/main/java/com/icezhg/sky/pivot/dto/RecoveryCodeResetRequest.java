package com.icezhg.sky.pivot.dto;

import jakarta.validation.constraints.NotBlank;

public record RecoveryCodeResetRequest(
    @NotBlank(message = "recoverySalt must not be blank")
    String recoverySalt,

    @NotBlank(message = "recoveryKeyHash must not be blank")
    String recoveryKeyHash,

    @NotBlank(message = "encryptedUrkRecovery must not be blank")
    String encryptedUrkRecovery
) {}
