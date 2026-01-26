package com.example.springsecurity.controller;

import com.example.springsecurity.dto.UserDto;
import com.example.springsecurity.exception.EmailAlreadyExistsException;
import com.example.springsecurity.exception.ResourceNotFoundException;
import com.example.springsecurity.model.User;
import com.example.springsecurity.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.Nullable;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1")
@CrossOrigin("*")
public class UserController {

    @Autowired
    private AuthService authService;


    @PostMapping("/public/signup") /** public endpoint: sign-up */
    public ResponseEntity<Object> signUp(@Valid @RequestBody User user) throws EmailAlreadyExistsException {

        return new ResponseEntity<>(authService.signUp(user), HttpStatus.CREATED);
    }

    @PostMapping("/public/signin") /** public endpoint: sign-in */
    public ResponseEntity<Object> signIn(@RequestBody User user) {

        return new ResponseEntity<>(authService.signIn(user), HttpStatus.OK);
    }

    @PutMapping("/user/update")
    public ResponseEntity<Object> update(
            @RequestParam("data") String data,
            @Nullable @RequestParam(value = "image", required = false) MultipartFile image) throws IOException, ResourceNotFoundException {

        ObjectMapper objectMapper = new ObjectMapper();
        User user = objectMapper.readValue(data, User.class);

        return new ResponseEntity<>(authService.update(user, image), HttpStatus.CREATED);
    }

}
