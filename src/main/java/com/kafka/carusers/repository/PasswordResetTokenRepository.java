package com.kafka.carusers.repository;

import com.kafka.carusers.entity.PasswordResetToken;
import com.kafka.carusers.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    void deleteByToken(String token);

    PasswordResetToken findByUsersDetails(User user);
}
