package com.icezhg.sky.pivot.exception;

public class MasterPasswordNotSetException extends RuntimeException {
    public MasterPasswordNotSetException() {
        super("Master password not set");
    }
}
