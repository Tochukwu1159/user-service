package com.kafka.carusers.entity;
import com.kafka.carusers.utils.Roles;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "users")
@Entity
@Builder
public class User extends BaseEntity {
    private String firstName;
//    @Size(min = 3, message = "Last name can not be less than 3")
    private String lastName;

    private String email;
//    @Size(min = 6, message = "Password should have at least 6 characters")
    private String password;
    @Enumerated(value = EnumType.STRING)
    private Roles roles;
//    @Size(min = 10, message = "Phone number should have at least 10 characters")
    private String phoneNumber;

    private Boolean isVerified;



}
