package com.icezhg.sky.pivot.exception;

public class MasterPasswordUserNotFoundException extends RuntimeException {
    public MasterPasswordUserNotFoundException(Long userId) {
        super("User not found: " + userId);
    }
}
