package com.aadhaar.auth.auth_backend.services.impl;

import com.aadhaar.auth.auth_backend.dtos.UserDto;
import com.aadhaar.auth.auth_backend.enitites.Provider;
import com.aadhaar.auth.auth_backend.enitites.User;
import com.aadhaar.auth.auth_backend.exceptions.ResourceNotFoundException;
import com.aadhaar.auth.auth_backend.helpers.UserHelper;
import com.aadhaar.auth.auth_backend.repositories.UserRepository;
import com.aadhaar.auth.auth_backend.services.UserService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final ModelMapper modelMapper;

    @Override
    @Transactional
    public UserDto createUser(UserDto userDto) {

        if(userDto.getEmail() == null || userDto.getEmail().isBlank()) {
            throw new IllegalArgumentException("Email is Required");
        }
        if(userRepository.existsByEmail(userDto.getEmail())) {
            throw new IllegalArgumentException(("Email Already Exists"));
        }
//        extra checks

        User user = modelMapper.map(userDto , User.class);
        user.setProvider(userDto.getProvider() != null ? userDto.getProvider() : Provider.LOCAL);
//        role assignment
        User savedUser = userRepository.save(user);

        return modelMapper.map(savedUser , UserDto.class);
    }

    @Override
    public UserDto getUserByEmail(String email) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(
                        () -> new ResourceNotFoundException("User Not Found ! Please check your Email...")
                );

        return modelMapper.map(user , UserDto.class);
    }

    @Override
    public UserDto updateUser(UserDto userDto, String userId) {
        UUID uuid = UserHelper.parseUUID(userId);
        User existingUser = userRepository.findById(uuid)
                        .orElseThrow(
                                () -> new IllegalArgumentException(("User ID does ot exist"))
                        );
        if(userDto.getName() != null) {
            existingUser.setName(userDto.getName());
        }
        if(userDto.getImage() != null) {
            existingUser.setImage(userDto.getImage());
        }
        if(userDto.getProvider() != null) {
            existingUser.setProvider(userDto.getProvider());
        }
        if(userDto.getPassword() != null) {
            existingUser.setPassword(userDto.getPassword());
        }
        existingUser.setEnable(userDto.isEnable());

        existingUser.setUpdatedAt(Instant.now());

        User updatedUser = userRepository.save(existingUser);

        return modelMapper.map(updatedUser , UserDto.class);
    }

    @Override
    @Transactional
    public void deleteUser(String userId) {

        UUID uuid = UserHelper.parseUUID(userId);

        User user = userRepository.findById(uuid)
                .orElseThrow(() -> new IllegalArgumentException("User ID does not exist"));

        userRepository.delete(user);
    }


    @Override
    public UserDto getUserById(String userId) {
        UUID uuid = UserHelper.parseUUID(userId);
        User user = userRepository.findById(uuid)
                .orElseThrow(
                        () -> new IllegalArgumentException("User ID does not exist")
                );
        return modelMapper.map(user , UserDto.class);
    }

    @Override
    public Iterable<UserDto> getAllUsers() {
        return userRepository
                .findAll()
                .stream()
                .map(user -> {
                    return modelMapper.map(user, UserDto.class);
                }).toList();
    }
}
