package com.icezhg.sky.pivot.dto;

import jakarta.validation.constraints.NotBlank;

public record PasswordUpdateRequest(
    String url,

    @NotBlank(message = "Account is required")
    String account,

    @NotBlank(message = "Password is required")
    String password,

    String notes
) {}
