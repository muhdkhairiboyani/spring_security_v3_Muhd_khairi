package com.example.springsecurity.exception;

public class ResourceNotFoundException extends Throwable{

    public ResourceNotFoundException(String message) {
        super(message);
    }
}
