package com.icezhg.sky.pivot.dto;

public record AccountDeletePreviewResponse(
    long totalPasswords,
    long trashedPasswords,
    long loginHistoryRecords
) {}
