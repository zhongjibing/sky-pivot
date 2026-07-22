package com.icezhg.sky.pivot.exception;

public class WeChatApiException extends RuntimeException {
    public WeChatApiException(String message) {
        super(message);
    }

    public WeChatApiException(String message, Throwable cause) {
        super(message, cause);
    }
}
