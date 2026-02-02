package com.aadhaar.auth.auth_backend.dtos;

public record LoginRequest(
        String email,
        String password
) {

}
