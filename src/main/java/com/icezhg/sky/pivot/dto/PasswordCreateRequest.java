package com.icezhg.sky.pivot.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PasswordCreateRequest(
    @NotBlank(message = "Title is required")
    @Size(max = 128, message = "Title must not exceed 128 characters")
    String title,

    String url,

    @NotBlank(message = "Account is required")
    String account,

    @NotBlank(message = "Password is required")
    String password,

    String notes
) {}
