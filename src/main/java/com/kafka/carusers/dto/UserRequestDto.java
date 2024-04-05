package com.kafka.carusers.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserRequestDto {
    @NotNull(message = "First Name is required")
    @NotEmpty(message = "first name cannot be empty")
    private String firstName;
    @NotNull(message = "Last Name is required")
    @NotEmpty(message = "Last name cannot be empty")
    private String lastName;
    @NotNull(message = "Password is required")
    @NotEmpty(message = "Password cannot be empty")
    private  String password;
    @NotNull(message = "Confirm Password is required")
    @NotEmpty(message = "Confirm Password cannot be empty")
    private String confirmPassword;
    @NotNull(message = "Email is required")
    @Email
    private String email;
    @NotNull(message = "Phone Number is required")
    @NotEmpty(message = "Phone Number cannot be empty")
    private String phoneNumber;




}
