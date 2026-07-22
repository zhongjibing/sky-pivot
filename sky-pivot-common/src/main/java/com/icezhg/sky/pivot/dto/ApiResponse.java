package com.icezhg.sky.pivot.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import org.slf4j.MDC;

import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiResponse<T>(
    String code,
    String message,
    T data,
    String requestId,
    long timestamp
) {

    private static final String MDC_REQUEST_ID_KEY = "requestId";

    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>("200", "success", data, resolveRequestId(), System.currentTimeMillis());
    }

    public static <T> ApiResponse<T> success() {
        return new ApiResponse<>("200", "success", null, resolveRequestId(), System.currentTimeMillis());
    }

    public static <T> ApiResponse<T> error(String code, String message) {
        return new ApiResponse<>(code, message, null, resolveRequestId(), System.currentTimeMillis());
    }

    public static <T> ApiResponse<T> error(int code, String message) {
        return error(String.valueOf(code), message);
    }

    private static String resolveRequestId() {
        String mdcId = MDC.get(MDC_REQUEST_ID_KEY);
        if (mdcId != null && !mdcId.isBlank()) {
            return mdcId;
        }
        return UUID.randomUUID().toString().replace("-", "");
    }
}
