package com.kafka.carusers.error_handler;

public class AuthenticationFailedException extends RuntimeException{
        public AuthenticationFailedException(String message) {
            super(message);
        }
    }

