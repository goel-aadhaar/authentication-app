package com.aadhaar.auth.auth_backend.services;

import com.aadhaar.auth.auth_backend.dtos.UserDto;

import java.util.UUID;

public interface UserService {

    UserDto createUser(UserDto user);

    UserDto getUserByEmail(String email);

    UserDto updateUser(UserDto userDto , String userId);

    void deleteUser(String userId);

    UserDto getUserById(String userId);

    Iterable<UserDto> getAllUsers();
}
