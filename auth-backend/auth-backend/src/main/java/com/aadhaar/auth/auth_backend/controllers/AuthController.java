package com.aadhaar.auth.auth_backend.controllers;

import com.aadhaar.auth.auth_backend.dtos.LoginRequest;
import com.aadhaar.auth.auth_backend.dtos.TokenResponse;
import com.aadhaar.auth.auth_backend.dtos.UserDto;
import com.aadhaar.auth.auth_backend.enitites.RefreshToken;
import com.aadhaar.auth.auth_backend.enitites.User;
import com.aadhaar.auth.auth_backend.repositories.RefreshTokenRepository;
import com.aadhaar.auth.auth_backend.repositories.UserRepository;
import com.aadhaar.auth.auth_backend.security.JWTService;
import com.aadhaar.auth.auth_backend.services.AuthService;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.UUID;

@RestController
@RequestMapping("api/v1/auth")
@AllArgsConstructor
public class AuthController {

    private final AuthService authService;

    private final RefreshTokenRepository refreshTokenRepository;

    private final AuthenticationManager authenticationManager;

    private final UserRepository userRepository;

    private final JWTService jwtService;

    private final ModelMapper modelMapper;

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(
            @RequestBody LoginRequest loginRequest
    ) {
        Authentication authentication = authenticate(loginRequest);
        User user = userRepository.findByEmail(loginRequest.email())
                .orElseThrow(
                        () -> new BadCredentialsException("Invalid Username or Password")
                );
        if(!user.isEnable()) {
            throw new DisabledException("User is Disabled");
        }

        String jti = UUID.randomUUID().toString();
        var refreshTokenObject = RefreshToken.builder()
                .jti(jti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt((Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds())))
                .revoked(false)
                .build();

        refreshTokenRepository.save(refreshTokenObject);
;
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user , refreshTokenObject.getJti());

        TokenResponse tokenResponse =  TokenResponse.of(
                accessToken,
                refreshToken,
                jwtService.getAccessTtlSeconds(),
                modelMapper.map(user, UserDto.class)
        );

        return new ResponseEntity<>(tokenResponse , HttpStatus.OK);
    }

    private Authentication authenticate(LoginRequest loginRequest) {
        try {
            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.email(),
                            loginRequest.password()
                    )
            );
        } catch (Exception e) {
            throw new BadCredentialsException("Invalid Credentials");
        }
    }


    @PostMapping("/register")
    public ResponseEntity<UserDto> registerUser(@RequestBody UserDto userDto) {

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(authService.registerUser(userDto));
    }
}
