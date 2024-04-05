package com.kafka.carusers.service;


import com.kafka.carusers.dto.*;
import com.kafka.carusers.entity.ConfirmationToken;
import org.springframework.http.ResponseEntity;

import java.util.List;

public interface UserService {
    UserResponse createAccount(UserRequestDto userRequest);
    UserResponse createAdmin(UserRequestDto userRequest);

    String verifyUser(String userToken);
    ConfirmationToken generateNewToken(String oldToken);

    LoginResponse loginUser(LoginRequest loginRequest);
    BaseResponse<?> logout();

    UserResponse editUserDetails(EditUserRequest editUserDto);

    UserResponse forgotPassword(ForgotPasswordRequest forgotPasswordRequest);

    UserResponse resetPassword(PasswordResetRequest passwordRequest, String token);
//    public UserResponse forgotPassword1(ForgotPasswordRequest forgotPasswordRequest);

    UserResponse updatePassword(ChangePasswordRequest changePasswordRequest);

    List<UserResponse> getAllUsers();
    UserResponse getUser();
     ResponseEntity<Void> deleteUser(Long userId);



}
