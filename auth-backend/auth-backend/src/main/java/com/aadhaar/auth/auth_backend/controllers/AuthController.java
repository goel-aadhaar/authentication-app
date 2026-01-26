package com.aadhaar.auth.auth_backend.controllers;

import com.aadhaar.auth.auth_backend.dtos.UserDto;
import com.aadhaar.auth.auth_backend.services.AuthService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/auth")
@AllArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<UserDto> registerUser(@RequestBody UserDto userDto) {

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(authService.registerUser(userDto));
    }
}
