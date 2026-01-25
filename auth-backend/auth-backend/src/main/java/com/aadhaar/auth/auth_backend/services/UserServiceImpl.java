package com.aadhaar.auth.auth_backend.services;

import com.aadhaar.auth.auth_backend.dtos.UserDto;
import com.aadhaar.auth.auth_backend.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    public UserDto createUser(UserDto user) {
        return null;
    }

    @Override
    public UserDto getUserByEmail(String email) {
        return null;
    }

    @Override
    public UserDto updateUser(UserDto userDto, String userId) {
        return null;
    }

    @Override
    public UserDto deleteUser(String userId) {
        return null;
    }

    @Override
    public UserDto getUserById(String userId) {
        return null;
    }

    @Override
    public Iterable<UserDto> getAllUsers() {
        return null;
    }
}
