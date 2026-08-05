package com.icezhg.sky.pivot.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record VaultItemUpdateRequest(
    @NotBlank(message = "encryptedBlob is required")
    String encryptedBlob,

    @NotNull(message = "version is required")
    Long version
) {}
