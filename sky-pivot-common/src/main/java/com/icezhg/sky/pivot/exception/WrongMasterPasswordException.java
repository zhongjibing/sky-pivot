package com.icezhg.sky.pivot.exception;

public class WrongMasterPasswordException extends RuntimeException {
    public WrongMasterPasswordException() {
        super("Wrong master password");
    }
}
