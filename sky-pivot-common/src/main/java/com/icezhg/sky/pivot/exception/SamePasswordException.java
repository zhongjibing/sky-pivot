package com.icezhg.sky.pivot.exception;

public class SamePasswordException extends RuntimeException {
    public SamePasswordException() {
        super("New password must be different from current password");
    }
}
