package com.icezhg.sky.pivot.exception;

public class AccountDisabledException extends RuntimeException {
    public AccountDisabledException() {
        super("Account has been disabled");
    }
}
