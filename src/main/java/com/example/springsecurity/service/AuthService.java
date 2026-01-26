package com.example.springsecurity.service;

import com.example.springsecurity.dto.UserDto;
import com.example.springsecurity.exception.EmailAlreadyExistsException;
import com.example.springsecurity.exception.ResourceNotFoundException;
import com.example.springsecurity.model.EnumRole;
import com.example.springsecurity.model.User;
import com.example.springsecurity.repository.UserRepository;
import com.example.springsecurity.util.JwtUtils;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;

@Service
public class AuthService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Value("${file.upload-dir}")
    private String uploadDir;

    public User signUp(User user) throws EmailAlreadyExistsException {

        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            throw new EmailAlreadyExistsException("Please use another email.");
        }

        User _user = User.builder()
                .userName(user.getUserName())
                .email(user.getEmail())
                .password(passwordEncoder.encode((user.getPassword())))
                .build();

       return userRepository.save(_user);
    }

    @Transactional
    public UserDto signIn(User user) throws ResourceAccessException{

        Authentication authenticationRequest = UsernamePasswordAuthenticationToken.unauthenticated(user.getEmail(), user.getPassword());
        Authentication authenticationResponse = authenticationManager.authenticate(authenticationRequest);

        /**
         * SecurityContextHolder.getContext().setAuthentication(authenticationResponse) - logs the authenticated user
         * authenticationResponse.getPrincipal() - returns an Object (class: UserDetails)
         * Cast returned UserDetails to User entity (userDetails doesn't have access modifier for "userName")
         * Within userDetails "userName" ≠ attribute "username")
         * The typecasting allows the extraction of: userName (≠ username), email and role
         */

        SecurityContextHolder.getContext().setAuthentication(authenticationResponse);
        User _user = (User) authenticationResponse.getPrincipal();

        String token = jwtUtils.generateToken(_user);
        String refreshToken = jwtUtils.generateRefreshToken(new HashMap<>(), _user);
        Long expirationTime = jwtUtils.extractExpirationTime(token);

        UserDto userDto = UserDto.builder()
                .userName(_user.getUserName())  // Return athenticated user userName
                .email(_user.getEmail())        // Return athenticated user email, akin to UserDetails.getUsername());
                .token(token)                   // Return prepared token
                .refreshToken(refreshToken)     // Return prepared refresh token
                .expirationTime(expirationTime) // Return prepared expiry
                .message("success")             // Return "success" as a message
                .role(_user.getRole())          // Return authenticated user's role
                .build();

        return userDto;
    }

    public UserDto update(User user, MultipartFile image) throws IOException, ResourceNotFoundException {

        // Obtain the user's identity from Spring Security
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentEmail = authentication.getName();

        // Fetch the managed user
        User existingUser = userRepository.findByEmail(currentEmail)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        // Map ONLY the fields you want to allow updating
        existingUser.setUserName(user.getUserName());

        if (user.getUserName() != null)
            existingUser.setUserName(user.getUserName());

        if (user.getPassword() != null)
            existingUser.setPassword(passwordEncoder.encode(user.getPassword()));

        if (user.getUserBio() != null)
            existingUser.setUserBio(user.getUserBio());

        // role should not be updated by an end user

        userRepository.saveAndFlush(existingUser);

        // Use _user.getId() to ensure user is saved
        if (image != null && !image.isEmpty() && existingUser.getId() != null) {

            // TODO check if the file is a .jpg or .jpeg or .png

            String fileName = "profile_" + System.currentTimeMillis()+ "_" + image.getOriginalFilename();
            String filePath = uploadDir + File.separator + fileName;
            File imageFile = new File(filePath);
            image.transferTo(imageFile.toPath());

            existingUser.setUserProfileImage(filePath);
            userRepository.save(existingUser);
        }

        // package the data to return
        UserDto userDto = UserDto.builder()
                .userName(existingUser.getUserName())
                .email(existingUser.getEmail())
                .userBio(existingUser.getUserBio())
                .userProfileImage(existingUser.getUserProfileImage())
                .message("update success")
                .build();

        // The following are not returned as updates
        // - role
        // - token
        // - refreshToken
        // - expiration

        return userDto;
    }

}
