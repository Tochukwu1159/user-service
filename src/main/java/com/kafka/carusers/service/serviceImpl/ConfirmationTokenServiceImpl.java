package com.kafka.carusers.service.serviceImpl;

import com.kafka.carusers.entity.ConfirmationToken;
import com.kafka.carusers.repository.ConfirmationTokenRepository;
import com.kafka.carusers.service.ConfirmationTokenService;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@Getter
@Setter
@AllArgsConstructor
public class ConfirmationTokenServiceImpl implements ConfirmationTokenService {

    private final ConfirmationTokenRepository confirmationTokenRepository;
    @Override
    public void saveConfirmationToken(ConfirmationToken token) {

        confirmationTokenRepository.saveAndFlush(token);
    }

    @Override
    public ConfirmationToken getToken(String token) {

        return confirmationTokenRepository.findByToken(token);
    }
    @Override
    public int setConfirmedAt(String token) {
        return confirmationTokenRepository.updateConfirmedAt(
                token, LocalDateTime.now());
    }

}