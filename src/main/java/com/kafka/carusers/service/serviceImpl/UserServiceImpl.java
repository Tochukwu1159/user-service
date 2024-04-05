package com.kafka.carusers.service.serviceImpl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kafka.carusers.Security.CustomUserDetailService;
import com.kafka.carusers.Security.JwtUtil;
import com.kafka.carusers.Security.SecurityConfig;
import com.kafka.carusers.dto.*;
import com.kafka.carusers.entity.ConfirmationToken;
import com.kafka.carusers.entity.PasswordResetToken;
import com.kafka.carusers.entity.User;
import com.kafka.carusers.error_handler.*;
import com.kafka.carusers.repository.ConfirmationTokenRepository;
import com.kafka.carusers.repository.PasswordResetTokenRepository;
import com.kafka.carusers.repository.UserRepository;
import com.kafka.carusers.service.BlacklistService;
import com.kafka.carusers.service.ConfirmationTokenService;
import com.kafka.carusers.service.EmailService;
import com.kafka.carusers.service.UserService;
import com.kafka.carusers.utils.AccountUtils;
import com.kafka.carusers.utils.Roles;
import jakarta.persistence.EntityExistsException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


@Service
public class UserServiceImpl implements UserService {
    @Autowired
    UserRepository userRepository;
    @Autowired
    EmailService emailService;
    @Autowired
    ConfirmationTokenService confirmationTokenService;
    @Autowired
    private  HttpServletRequest httpServletRequest;
    @Autowired
    private  ObjectMapper objectMapper;

    @Autowired
    JwtUtil jwtUtil;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    CustomUserDetailService customUserDetailsService;
    @Autowired
    PasswordResetTokenRepository passwordResetTokenRepository;
    @Autowired
    BlacklistService blacklistService;
    @Autowired
    private ConfirmationTokenRepository confirmationTokenRepository;

    @Override
    public UserResponse createAccount(UserRequestDto userRequest) {
        try {
            if (userRepository.existsByEmail(userRequest.getEmail())) {
                throw new UserAlreadyExistException("Email already exists");
            }

            if (!AccountUtils.validatePassword(userRequest.getPassword(), userRequest.getConfirmPassword())) {
                throw new UserPasswordMismatchException("Password does not match");
            }

            if (existsByMail(userRequest.getEmail())) {
                throw new BadRequestException("Error: Email is already taken!");
            }

            if (!isValidEmail(userRequest.getEmail())) {
                throw new BadRequestException("Error: Email must be valid");
            }

            if (userRequest.getPassword().length() < 8 || userRequest.getConfirmPassword().length() < 8) {
                throw new BadRequestException("Error: Password is too short");
            }

            if (!isValidPassword(userRequest.getPassword())) {
                throw new BadRequestException("Error: Password must contain at least 8 characters, Uppercase, LowerCase, and Number");
            }

            User newUser = User.builder()
                    .firstName(userRequest.getFirstName())
                    .lastName(userRequest.getLastName())
                    .email(userRequest.getEmail())
                    .phoneNumber(userRequest.getPhoneNumber())
                    .password(passwordEncoder.encode(userRequest.getPassword()))
                    .isVerified(false)
                    .roles(Roles.CUSTOMER)
                    .build();
            User savedUser = userRepository.save(newUser);

            String token = jwtUtil.generateToken(userRequest.getEmail());
            ConfirmationToken confirmationToken = new ConfirmationToken(
                    token,
                    LocalDateTime.now().plusMinutes(30),
                    newUser
            );
            confirmationTokenService.saveConfirmationToken(confirmationToken);

            EmailDetails emailDetails = EmailDetails.builder()
                    .recipient(savedUser.getEmail())
                    .subject("ACCOUNT CREATION")
                    .messageBody("Congratulations! Your Account Has Been Successfully Created.\nYour Account Details:\nAccount Name: " + savedUser.getFirstName() + " " + savedUser.getLastName())
                    .build();
            emailService.sendEmailAlert(emailDetails);

            return mapToUserResponse(savedUser);
        } catch (Exception ex) {
            throw new RuntimeException("Error creating a user "+ex);
        }
    }


    @Override
    public UserResponse createAdmin(UserRequestDto userRequest) {
        try {
            if (userRepository.existsByEmail(userRequest.getEmail())) {
                throw new UserAlreadyExistException("User with email already exists");
            }

            if (!AccountUtils.validatePassword(userRequest.getPassword(), userRequest.getConfirmPassword())) {
                throw new UserPasswordMismatchException("Password does not match");
            }

            if (existsByMail(userRequest.getEmail())) {
                throw new BadRequestException("Error: Email is already taken!");
            }

            if (!isValidEmail(userRequest.getEmail())) {
                throw new BadRequestException("Error: Email must be valid");
            }

            if (userRequest.getPassword().length() < 8 || userRequest.getConfirmPassword().length() < 8) {
                throw new BadRequestException("Error: Password is too short");
            }

            if (!isValidPassword(userRequest.getPassword())) {
                throw new BadRequestException("Error: password must contain at least 8 characters, Uppercase, LowerCase, and Number");
            }

            User newUser = User.builder()
                    .firstName(userRequest.getFirstName())
                    .lastName(userRequest.getLastName())
                    .email(userRequest.getEmail())
                    .phoneNumber(userRequest.getPhoneNumber())
                    .password(passwordEncoder.encode(userRequest.getPassword()))
                    .isVerified(true)
                    .roles(Roles.ADMIN)
                    .build();
            User savedUser = userRepository.save(newUser);

            String token = jwtUtil.generateToken(userRequest.getEmail());
            ConfirmationToken confirmationToken = new ConfirmationToken(
                    token,
                    LocalDateTime.now().plusMinutes(80),
                    newUser
            );
            confirmationTokenService.saveConfirmationToken(confirmationToken);

            EmailDetails emailDetails = EmailDetails.builder()
                    .recipient(savedUser.getEmail())
                    .subject("ACCOUNT CREATION")
                    .messageBody("Congratulations! Your Account Has Been Successfully Created as Admin.\nYour Account Details:\nAccount Name: " + savedUser.getFirstName() + " " + savedUser.getLastName())
                    .build();
            emailService.sendEmailAlert(emailDetails);

            return mapToUserResponse(savedUser);
        } catch (Exception ex) {
           throw  new RuntimeException("Failed to create admin "+ex);
        }
    }



    @Override
    public String verifyUser(String userToken) {
        try {
            ConfirmationToken confirmationToken = confirmationTokenService.getToken(userToken);
            if (confirmationToken == null) {
                throw new CustomNotFoundException("Token not found");
            }
            if (confirmationToken.getConfirmedAt() != null) {
                throw new EntityExistsException("Email already confirmed");
            }
            LocalDateTime expiredAt = confirmationToken.getExpiresAt();
            if (expiredAt.isBefore(LocalDateTime.now())) {
                throw new CustomNotFoundException("Token expired");
            }
            confirmationTokenService.setConfirmedAt(userToken);
            User user = confirmationToken.getUser();
            Optional<User> userOptional = userRepository.findById(user.getId());
            if (userOptional.isEmpty()) {
                throw new CustomNotFoundException("User does not exist");
            }
            User verifiedUser = userOptional.get();
            verifiedUser.setIsVerified(true);
            userRepository.save(verifiedUser);
            return "confirmed";
        } catch (Exception ex) {
         throw new RuntimeException("Failed to verify user "+ex);
        }
    }


    @Override
    public ConfirmationToken generateNewToken(String oldToken) {
        try {
            ConfirmationToken verificationToken = confirmationTokenRepository.findByToken(oldToken);
            if (verificationToken == null) {
                throw new CustomNotFoundException("Token not found");
            }
            verificationToken.setToken(UUID.randomUUID().toString());
            LocalDateTime expirationDate = LocalDateTime.now().plusMinutes(40);
            verificationToken.setExpiresAt(expirationDate);
            confirmationTokenRepository.save(verificationToken);
            return verificationToken;
        } catch (Exception ex) {
           throw new RuntimeException("Failed to generate new token "+ex);
        }
    }


    @Override
    public LoginResponse loginUser(LoginRequest loginRequest) {
        try {
            Authentication authenticate = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword())
            );

            if (!authenticate.isAuthenticated()) {
                throw new AuthenticationFailedException("Wrong email or password");
            }

            Optional<User> user = userRepository.findByEmail(loginRequest.getEmail());

            if (!user.isPresent()) {
                throw new CustomNotFoundException("User does not exist");
            }

            if (!user.get().getIsVerified()) {
                throw new UserNotVerifiedException("User is not verified");
            }

            SecurityContextHolder.getContext().setAuthentication(authenticate);
            String token = "Bearer " + jwtUtil.generateToken(loginRequest.getEmail());
            return new LoginResponse(token);
        } catch (BadCredentialsException ex) {
            // Handle the "Bad credentials" error here
            throw new AuthenticationFailedException("Wrong email or password "+ex);
        }
    }

    @Override
    public BaseResponse<?> logout() {
        try {
            String token = httpServletRequest.getHeader("Authorization");
            if (token == null || !token.startsWith("Bearer ")) {
                throw new IllegalArgumentException("Invalid token format");
            }

            // Extract token from the Authorization header
            token = token.substring(7); // Remove "Bearer " prefix

            blacklistService.blacklistToken(token);

            return new BaseResponse<>(HttpStatus.OK, "Logout Successful", null);
        } catch (Exception ex) {
            throw new RuntimeException("Error during logout "  +ex); // Or any other appropriate error handling
        }
    }



    @Override
    public UserResponse editUserDetails(EditUserRequest editUserDto) {
        try {
            String email = SecurityConfig.getAuthenticatedUserEmail(); // Assuming this method retrieves the authenticated user's email
            System.out.println(email + "email");
            Object loggedInUsername1 = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            System.out.println(loggedInUsername1 + "loggedInUsername1");

            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            if (user == null) {
                throw new CustomNotFoundException("User does not exist");
            }

            user.setFirstName(editUserDto.getFirstName());
            user.setLastName(editUserDto.getLastName());
            user.setPhoneNumber(editUserDto.getPhoneNumber());

            User updatedUser = userRepository.save(user);

            return mapToUserResponse(updatedUser);
        } catch (Exception ex) {
            throw  new RuntimeException("Error editing password "+ex);
        }
    }


    @Override
    public UserResponse forgotPassword(ForgotPasswordRequest forgotPasswordRequest) {
        try {
            Optional<User> userOptional = userRepository.findByEmail(forgotPasswordRequest.getEmail());

            if (!userOptional.isPresent()) {
                throw new CustomNotFoundException("User with provided Email not found");
            }

            User user = userOptional.get();
            UserDetails userDetails = customUserDetailsService.loadUserByUsername(forgotPasswordRequest.getEmail());

            String token = new JwtUtil().generateToken(userDetails.getUsername());

            PasswordResetToken existingToken = passwordResetTokenRepository.findByUsersDetails(user);

            if (existingToken != null) {
                existingToken.setToken(token);
            } else {
                PasswordResetToken passwordResetTokenEntity = new PasswordResetToken();
                passwordResetTokenEntity.setToken(token);
                passwordResetTokenEntity.setUsersDetails(user);
                passwordResetTokenRepository.save(passwordResetTokenEntity);
            }

            EmailDetails emailDetails = EmailDetails.builder()
                    .recipient(forgotPasswordRequest.getEmail())
                    .subject("PASSWORD RESET LINK")
                    .messageBody("http://localhost:8080/api/users/resetPassword?token=" + token)
                    .build();
            try {
                emailService.sendEmailAlert(emailDetails);
            } catch (Exception e) {
                throw new EmailSendingException("Failed to send the password reset email "+e);
            }

            return mapToUserResponse(user);
        } catch (Exception ex) {
            // Handle any exceptions here
            ex.printStackTrace(); // Or log the exception
            throw new RuntimeException("Error ");        }
    }


    @Override
    @Transactional
    public UserResponse resetPassword(PasswordResetRequest passwordRequest, String token) {
        try {
            if (!passwordRequest.getNewPassword().equals(passwordRequest.getConfirmPassword())) {
                throw new CustomNotFoundException("Password do not match");
            }

            String email = jwtUtil.extractUsername(token);

            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            if (user == null) {
                throw new UsernameNotFoundException("User not found");
            }

            if (passwordRequest.getNewPassword().length() < 8 || passwordRequest.getConfirmPassword().length() < 8) {
                throw new BadRequestException("Error: Password is too short");
            }

            if (!isValidPassword(passwordRequest.getNewPassword())) {
                throw new BadRequestException("Error: Password must contain at least 8 characters, Uppercase, Lowercase, and Number");
            }

            if (jwtUtil.isTokenExpired(token)) {
                throw new TokenExpiredException("Token has expired");
            }

            user.setPassword(passwordEncoder.encode(passwordRequest.getNewPassword()));
            userRepository.save(user);

            passwordResetTokenRepository.deleteByToken(token);

            return mapToUserResponse(user);
        } catch (Exception ex) {
     throw new RuntimeException("Errow re-seting Pasword "+ex);
        }
    }


    @Override
    public UserResponse updatePassword(ChangePasswordRequest changePasswordRequest) {
        try {
            String email = SecurityConfig.getAuthenticatedUserEmail(); // Assuming this method retrieves the authenticated user's email
            String oldPassword = changePasswordRequest.getOldPassword();
            String newPassword = changePasswordRequest.getNewPassword();
            String confirmPassword = changePasswordRequest.getConfirmPassword();

            Optional<User> optionalUser = userRepository.findByEmail(email);

            if (optionalUser.isPresent()) {
                User user = optionalUser.get();
                String encodedPassword = user.getPassword();
                boolean isPasswordAMatch = passwordEncoder.matches(oldPassword, encodedPassword);

                if (!isPasswordAMatch) {
                    throw new BadRequestException("Old Password does not match");
                }

                if (newPassword.length() < 8 || confirmPassword.length() < 8) {
                    throw new BadRequestException("Error: Password is too short");
                }

                if (!isValidPassword(newPassword)) {
                    throw new BadRequestException("Error: password must contain at least 8 characters, Uppercase, LowerCase and Number");
                }

                boolean isPasswordEquals = newPassword.equals(confirmPassword);

                if (!isPasswordEquals) {
                    throw new BadRequestException("New Password does not match confirm password");
                }

                user.setPassword(passwordEncoder.encode(newPassword));

                userRepository.save(user);

                return mapToUserResponse(user);
            } else {
                throw new NotFoundException("User not found");
            }
        } catch (Exception ex) {
           throw new RuntimeException("Error updating password "+ex);
        }
    }

    @Override
    public List<UserResponse> getAllUsers() {
        try {
            List<User> userList = userRepository.findAll();
            return userList.stream()
                    .map(this::mapToUserResponse)
                    .collect(Collectors.toList());
        } catch (Exception ex) {
      throw new RuntimeException("Error gettinng the user list "+ex);
        }
    }


    @Override
    public UserResponse getUser() {
        try {
            String loggedInEmail = SecurityContextHolder.getContext().getAuthentication().getName();
            if (loggedInEmail.equals("anonymousUser")) {
                throw  new CustomNotFoundException("not found");
            }
            User user = userRepository.findByEmail(loggedInEmail).orElseThrow(() -> new UsernameNotFoundException("User not found"));

            return mapToUserResponse(user);
        } catch (Exception ex) {
            throw new RuntimeException("Error occurred while fetching user data "+ex);
        }
    }


    public ResponseEntity<Void> deleteUser(Long userId) {
        try {
            String email = SecurityConfig.getAuthenticatedUserEmail();
            User admin = userRepository.findByEmailAndRoles(email, Roles.ADMIN);

            if (!admin.getIsVerified()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            if (userRepository.existsById(userId)) {
                userRepository.deleteById(userId);
                return ResponseEntity.noContent().build(); // User deleted successfully
            } else {
                throw  new NotFoundException("User not found");
            }
        } catch (Exception e) {
           throw new RuntimeException("Failed to delete user " +e);
        }
    }




    private boolean isValidPassword(String password) {
        String regex = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=\\S+$).{8,}$";

        // Compile the ReGex
        Pattern p = Pattern.compile(regex);
        if (password == null) {
            throw new BadRequestException("Error: Password cannot be null");
        }
        Matcher m = p.matcher(password);
        return m.matches();
    }


    private boolean isValidEmail(String email) {
        String regex = "^[\\w!#$%&'*+/=?`{|}~^-]+(?:\\.[\\w!#$%&'*+/=?`{|}~^-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,6}$";

        // Compile the ReGex
        Pattern p = Pattern.compile(regex);
        if (email == null) {
            throw new BadRequestException("Error: Email cannot be null");
        }
        Matcher m = p.matcher(email);
        return m.matches();
    }
    private boolean existsByMail(String email) {
        return userRepository.existsByEmail(email);


    }

    public UserResponse mapToUserResponse(User user) {
        UserResponse userResponse = new UserResponse();
        userResponse.setId(user.getId());
        userResponse.setPhoneNumber(user.getPhoneNumber());
        userResponse.setLastName(user.getLastName());
        userResponse.setFirstName(user.getFirstName());
        userResponse.setEmail(user.getEmail());
        return userResponse;
    }



}

