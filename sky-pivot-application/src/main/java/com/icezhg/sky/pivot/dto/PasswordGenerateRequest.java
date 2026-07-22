package com.icezhg.sky.pivot.dto;

public record PasswordGenerateRequest(
    int length,
    boolean uppercase,
    boolean lowercase,
    boolean digits,
    boolean special
) {
    public PasswordGenerateRequest {
        if (length < 8) length = 8;
        if (length > 64) length = 64;
    }
}
