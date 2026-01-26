package com.aadhaar.auth.auth_backend.dtos;

import org.springframework.http.HttpStatus;

public record ErrorResponse(
        String message,
        HttpStatus status,
        String error
) {
}
