package com.icezhg.sky.pivot.dto;

import java.time.LocalDateTime;

public record TrashItemResponse(
    Long id,
    String title,
    String account,
    LocalDateTime deletedAt,
    long daysRemaining
) {}
