package com.icezhg.sky.pivot.exception;

public class AccountDeletedException extends RuntimeException {
    public AccountDeletedException() {
        super("Account has been deleted");
    }
}
