package com.aadhaar.auth.auth_backend.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import com.aadhaar.auth.auth_backend.dtos.ErrorResponse;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    // resource not found exception :: method
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleResourceNotFoundException(ResourceNotFoundException exception) {
        ErrorResponse internalServerError = new ErrorResponse(exception.getMessage(), HttpStatus.NOT_FOUND, "Internal Server Error");
        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(internalServerError);
    }

//    illegal argument exception :: method
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(IllegalArgumentException exception) {
        ErrorResponse internalServerError = new ErrorResponse(exception.getMessage(), HttpStatus.BAD_REQUEST, "Internal Server Error");
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(internalServerError);
    }
}
