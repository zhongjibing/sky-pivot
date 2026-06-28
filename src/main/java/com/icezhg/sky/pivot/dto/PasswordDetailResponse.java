package com.icezhg.sky.pivot.dto;

public record PasswordDetailResponse(
    Long id,
    String title,
    String url,
    String account,
    String password,
    String notes,
    Integer healthScore,
    String healthLevel
) {}
