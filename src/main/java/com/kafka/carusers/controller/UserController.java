package com.kafka.carusers.controller;
import com.kafka.carusers.dto.*;
import com.kafka.carusers.entity.ConfirmationToken;
import com.kafka.carusers.entity.User;
import com.kafka.carusers.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;


@RestController
@RequestMapping(value="/api/v1/users")
public class UserController {
    @Autowired
    UserService userService;

    @PostMapping("/create")
    public ResponseEntity<UserResponse>
    createAccount(@RequestBody @Valid UserRequestDto userRequest){
        return new ResponseEntity<>(userService.createAccount(userRequest),HttpStatus.CREATED);
    }
    @PostMapping("/admin/create")
    public ResponseEntity<UserResponse> createAdmin(@RequestBody @Valid UserRequestDto userRequest){
        return new ResponseEntity<>(userService.createAdmin(userRequest),HttpStatus.CREATED);

    }
    @GetMapping("/verify")
    public  ResponseEntity<String> verifyUser(@RequestParam("token") String token){
        return new ResponseEntity<>(userService.verifyUser(token),HttpStatus.OK);


    }

    @GetMapping("/resend-verify")
    public ResponseEntity<ConfirmationToken> generateNewToken(@RequestParam("token") String token){

        return new ResponseEntity<>(userService.generateNewToken(token),HttpStatus.OK);

    }

    @DeleteMapping("/logout")
    public BaseResponse<?> logout() {
        userService.logout();
        return new BaseResponse<>(HttpStatus.OK, "Logout Successful", null);
    };

    @PostMapping("/login")
    public ResponseEntity<LoginResponse>
    loginUser(@RequestBody @Valid LoginRequest loginRequest){
        return  new ResponseEntity<>(userService.loginUser(loginRequest),HttpStatus.OK);

    }

    @PostMapping("/edit")
    public ResponseEntity<UserResponse> editUserDetails( @RequestBody @Valid EditUserRequest editUserDto){
        return new ResponseEntity<>(userService.editUserDetails(editUserDto),HttpStatus.OK);
    }
    @PostMapping("/forgot-password")
    public  ResponseEntity<UserResponse> forgotPassword(@RequestBody @Valid ForgotPasswordRequest forgotPasswordRequest){
        return new ResponseEntity<>(userService.forgotPassword(forgotPasswordRequest),HttpStatus.OK);
    }

    @GetMapping("/reset-password")
    public  ResponseEntity<UserResponse> resetPassword(@RequestBody @Valid PasswordResetRequest passwordResetRequest, @RequestParam("token") String token) {
        return new ResponseEntity<>(userService.resetPassword(passwordResetRequest, token), HttpStatus.OK);
    }


    @PostMapping("/update")
    public ResponseEntity<UserResponse> updatePassword (@RequestBody @Valid ChangePasswordRequest changePasswordRequest){
        return new ResponseEntity<>(userService.updatePassword(changePasswordRequest),HttpStatus.OK);
    }
    @GetMapping("/getAll")
    public ResponseEntity<List<UserResponse>> getAllUsers(){
        return new ResponseEntity<>(userService.getAllUsers(),HttpStatus.OK);
    }

    @DeleteMapping("/delete/{userId}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long userId) {
        boolean deleted = userService.deleteUser(userId).hasBody();
        if (deleted) {
            return ResponseEntity.noContent().build();
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }



}
