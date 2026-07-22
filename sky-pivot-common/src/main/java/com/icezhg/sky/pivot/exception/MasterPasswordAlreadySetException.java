package com.icezhg.sky.pivot.exception;

public class MasterPasswordAlreadySetException extends RuntimeException {
    public MasterPasswordAlreadySetException() {
        super("Master password already set");
    }
}
