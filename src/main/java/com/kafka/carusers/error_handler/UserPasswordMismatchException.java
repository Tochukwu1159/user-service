package com.kafka.carusers.error_handler;


public class UserPasswordMismatchException extends RuntimeException {
    public UserPasswordMismatchException(String message) {
        super(message);
    }
}
