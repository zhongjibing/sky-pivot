package com.icezhg.sky.pivot.dto;

import java.time.LocalDateTime;

public record VaultItemResponse(
    long id,
    String itemId,
    String encryptedBlob,
    long version,
    LocalDateTime createdAt,
    LocalDateTime updatedAt
) {}
