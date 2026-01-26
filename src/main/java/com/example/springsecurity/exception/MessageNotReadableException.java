package com.example.springsecurity.exception;

public class MessageNotReadableException extends RuntimeException {

    public MessageNotReadableException() {
        super("Invalid Data. Please check.");
    }
}
