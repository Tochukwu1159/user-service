package com.kafka.carusers.error_handler;
public class UserLoggedOutException extends RuntimeException {
    public UserLoggedOutException(String message) {
        super(message);
    }
}