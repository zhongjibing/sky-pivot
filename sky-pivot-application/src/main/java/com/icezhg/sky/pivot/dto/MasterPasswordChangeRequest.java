package com.icezhg.sky.pivot.dto;

import jakarta.validation.constraints.NotBlank;

public record MasterPasswordChangeRequest(
    @NotBlank(message = "Current master password is required")
    String currentMasterPassword,
    @NotBlank(message = "New master password is required")
    String newMasterPassword
) {}
