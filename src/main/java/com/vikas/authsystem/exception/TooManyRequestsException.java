package com.vikas.authsystem.exception;

public class TooManyRequestsException extends ApiException {
    public TooManyRequestsException(String message) {
        super(message);
    }
}
