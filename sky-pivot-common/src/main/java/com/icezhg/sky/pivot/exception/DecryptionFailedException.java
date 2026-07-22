package com.icezhg.sky.pivot.exception;

public class DecryptionFailedException extends RuntimeException {
    public DecryptionFailedException() {
        super("Failed to decrypt DEK with current KEK");
    }
}
