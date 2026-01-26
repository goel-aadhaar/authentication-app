package com.aadhaar.auth.auth_backend.services.impl;

import com.aadhaar.auth.auth_backend.dtos.UserDto;
import com.aadhaar.auth.auth_backend.services.AuthService;
import com.aadhaar.auth.auth_backend.services.UserService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserService userService;

    @Override
    public UserDto registerUser(UserDto userDto) {

        return userService.createUser(userDto);
    }
}
