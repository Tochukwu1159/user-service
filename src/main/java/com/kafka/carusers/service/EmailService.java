package com.kafka.carusers.service;

import com.kafka.carusers.dto.EmailDetails;

public interface EmailService {
    void sendEmailAlert(EmailDetails emailDetails);


    void sendEmailWithAttachment(EmailDetails emailDetails);
}
