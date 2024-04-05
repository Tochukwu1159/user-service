package com.kafka.carusers.repository;

import com.kafka.carusers.entity.User;
import com.kafka.carusers.utils.Roles;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Boolean existsByEmail(String email);

    Optional<User> findByEmail(String email);



    User findByEmailAndRoles(String email, Roles roles);
}