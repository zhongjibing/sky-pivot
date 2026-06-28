package com.icezhg.sky.pivot.dto;

import java.time.LocalDateTime;

public record PasswordListResponse(
    Long id,
    String title,
    String url,
    String account,
    String healthLevel,
    LocalDateTime updatedAt
) {}
