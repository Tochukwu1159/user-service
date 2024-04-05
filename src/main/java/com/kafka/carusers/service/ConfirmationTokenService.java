package com.kafka.carusers.service;


import com.kafka.carusers.entity.ConfirmationToken;

public interface ConfirmationTokenService {
    void saveConfirmationToken(ConfirmationToken token);
    ConfirmationToken getToken(String token);
    int setConfirmedAt(String token);
}
