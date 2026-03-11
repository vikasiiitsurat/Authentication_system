package com.vikas.authsystem.exception;

public class AccountLockedException extends ApiException {
    public AccountLockedException(String message) {
        super(message);
    }
}
