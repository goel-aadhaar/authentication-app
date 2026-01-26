package com.aadhaar.auth.auth_backend.services;

import com.aadhaar.auth.auth_backend.dtos.UserDto;

public interface AuthService {

    UserDto registerUser(UserDto userDto);


}
