package com.kafka.carusers.service;


import com.kafka.carusers.entity.BlacklistedToken;

public interface BlacklistService {
    BlacklistedToken blacklistToken(String token);
//    boolean tokenExist(String token);
    boolean isTokenBlacklisted(String token);
}
