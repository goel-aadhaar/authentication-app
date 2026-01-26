package com.aadhaar.auth.auth_backend.security;

import com.aadhaar.auth.auth_backend.enitites.User;
import com.aadhaar.auth.auth_backend.exceptions.ResourceNotFoundException;
import com.aadhaar.auth.auth_backend.repositories.UserRepository;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userRepository.findByEmail(username).orElseThrow(() -> new ResourceNotFoundException("Incorrect Email! Please login with correct email"));

        return user;
    }
}
