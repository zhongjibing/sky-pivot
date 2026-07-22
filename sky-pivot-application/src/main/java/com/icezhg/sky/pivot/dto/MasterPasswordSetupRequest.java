package com.icezhg.sky.pivot.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record MasterPasswordSetupRequest(
    @NotBlank(message = "Master password is required")
    @Size(min = 10, message = "Master password must be at least 10 characters")
    String masterPassword
) {}
