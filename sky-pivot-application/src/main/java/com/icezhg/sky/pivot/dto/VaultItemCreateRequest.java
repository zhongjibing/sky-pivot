package com.icezhg.sky.pivot.dto;

import jakarta.validation.constraints.NotBlank;

public record VaultItemCreateRequest(
    @NotBlank(message = "itemId is required")
    String itemId,

    @NotBlank(message = "encryptedBlob is required")
    String encryptedBlob
) {}
