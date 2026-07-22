package com.icezhg.sky.pivot.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiResponse<T>(
    String code,
    String message,
    T data,
    String requestId,
    long timestamp
) {
    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>("200", "success", data, genRequestId(), System.currentTimeMillis());
    }

    public static <T> ApiResponse<T> success() {
        return new ApiResponse<>("200", "success", null, genRequestId(), System.currentTimeMillis());
    }

    public static <T> ApiResponse<T> error(String code, String message) {
        return new ApiResponse<>(code, message, null, genRequestId(), System.currentTimeMillis());
    }

    public static <T> ApiResponse<T> error(int code, String message) {
        return error(String.valueOf(code), message);
    }

    private static String genRequestId() {
        return UUID.randomUUID().toString().substring(0, 8);
    }
}
