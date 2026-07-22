package com.icezhg.sky.pivot.dto;

import jakarta.validation.constraints.NotBlank;

public record MasterPasswordVerifyRequest(
    @NotBlank(message = "Master password is required")
    String masterPassword
) {}
