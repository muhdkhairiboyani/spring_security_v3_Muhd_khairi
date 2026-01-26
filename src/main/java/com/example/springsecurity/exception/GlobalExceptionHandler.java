package com.example.springsecurity.exception;

import jakarta.validation.constraints.NotNull;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.HashMap;
import java.util.Map;

@Order(Ordered.HIGHEST_PRECEDENCE)      // when exceptions occur, the GlobalExceptionHandler takes precedence
@RestControllerAdvice                   // addressing exceptions in the app globally
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    // GlobalExceptionHandler extends the ResponseEntityExceptionHandler
    // to inherits the built-in methods from it

    // 1. When the user sends data that is not readable, throw the error: handleHttpMessageNotReadableException
    @Override
    protected @NotNull ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException ex,
                                                                           HttpHeaders headers,
                                                                           HttpStatusCode status,
                                                                           WebRequest request) {

        // Prepare the custom message using MessageNotReadableException
        MessageNotReadableException messageNotReadableException = new MessageNotReadableException();

        // store the various error responses in a HashMap, to returning as part of the exception handling response
        Map<String, String> errorResponse = new HashMap<>();

        errorResponse.put("error:", messageNotReadableException.getMessage());

        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    // 2. When the user sends a request body that has attributes that is/are empty OR in incorrect format
    // call handleMethodArgumentNotValid to respond to @Valid annotation applied to @RequestBody
    @Override
    protected @NotNull ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
                                                                           HttpHeaders headers,
                                                                           HttpStatusCode status,
                                                                           WebRequest request) {
        Map<String, String> errors = new HashMap<>();

        ex.getBindingResult().getFieldErrors().forEach(err -> { /** revised to getFieldErrors(); */
            String field = err.getField();                      /** call the error's field **/
            String message = err.getDefaultMessage();
            errors.put(field, message);
        });

        // store the various error responses in a HashMap, to returning as part of the exception handling response
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error:", errors);

        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    // 3. Manage ResourceNotFoundException at a global level
    // Derive our own custom methods to handle httpEntityNotFound
    @ExceptionHandler(ResourceNotFoundException.class)
    protected ResponseEntity<Object> httpEntityNotFound(ResourceNotFoundException ex){

        // store the various error responses in a HashMap, to returning as part of the exception handling response
        Map<String, String> errorResponse = new HashMap<>();
        errorResponse.put("error:", ex.getMessage());

        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);

    }

    // 4. Manage NoResourceFoundException at a global level
    @Override
    protected @NotNull ResponseEntity<Object> handleNoResourceFoundException(NoResourceFoundException ex,
                                                                    HttpHeaders headers,
                                                                    HttpStatusCode status,
                                                                    WebRequest request) {

        // Re-using ResponseNotFoundException for the purpose of
        // catching exceptions when no path variable is supplied
        ResourceNotFoundException resourceNotFoundException = new ResourceNotFoundException("Resource not found.");

        Map<String, String> errorResponse = new HashMap<>();

        errorResponse.put("error:", resourceNotFoundException.getMessage());

        return new ResponseEntity<>(errorResponse, HttpStatus.NOT_FOUND);

    }

    // 5. Manage EmailAlreadyExistsException at a global level
    @ExceptionHandler(EmailAlreadyExistsException.class)
    protected ResponseEntity<Object> handleEmailAlreadyExistsException(EmailAlreadyExistsException ex){

        // store the various error responses in a HashMap, to returning as part of the exception handling response
        Map<String, String> errorResponse = new HashMap<>();
        errorResponse.put("error:", ex.getMessage());

        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);

    }

    // 6. Manage UsernameNotFoundException at global level
    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<Map<String, String>> handleUsernameNotFoundException(UsernameNotFoundException ex) {

        Map<String, String> errorResponse = new HashMap<>();
        errorResponse.put("error", "Authentication Failed");

        return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED); // 401 Unauthorized
    }
}
