package com.example.springsecurity.exception;

public class EmailAlreadyExistsException extends Throwable{

    public EmailAlreadyExistsException(String message) {
        super(message);
    }
}
