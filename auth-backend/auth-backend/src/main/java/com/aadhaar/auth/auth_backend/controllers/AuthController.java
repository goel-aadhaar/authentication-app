package com.aadhaar.auth.auth_backend.controllers;

import com.aadhaar.auth.auth_backend.dtos.LoginRequest;
import com.aadhaar.auth.auth_backend.dtos.RefreshTokenRequest;
import com.aadhaar.auth.auth_backend.dtos.TokenResponse;
import com.aadhaar.auth.auth_backend.dtos.UserDto;
import com.aadhaar.auth.auth_backend.enitites.RefreshToken;
import com.aadhaar.auth.auth_backend.enitites.User;
import com.aadhaar.auth.auth_backend.repositories.RefreshTokenRepository;
import com.aadhaar.auth.auth_backend.repositories.UserRepository;
import com.aadhaar.auth.auth_backend.security.CookieService;
import com.aadhaar.auth.auth_backend.security.JWTService;
import com.aadhaar.auth.auth_backend.services.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("api/v1/auth")
@AllArgsConstructor
public class AuthController {

    private final AuthService authService;

    private final CookieService cookieService;

    private final RefreshTokenRepository refreshTokenRepository;

    private final AuthenticationManager authenticationManager;

    private final UserRepository userRepository;

    private final JWTService jwtService;

    private final ModelMapper modelMapper;

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(
            @RequestBody LoginRequest loginRequest,
            HttpServletResponse response
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

        cookieService.attachRefreshCookie(response , refreshToken , (int) jwtService.getRefreshTtlSeconds());
        cookieService.addNoStoreHeaders(response);

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

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(
            @RequestBody(required = false) RefreshTokenRequest body,
            HttpServletResponse response,
            HttpServletRequest request
    ) {
        String refreshToken = readRefreshTokenFromRequest(body , request)
                .orElseThrow(() -> new BadCredentialsException("Refresh Token is required"));

        if(!jwtService.isRefreshToken(refreshToken)) {
            throw new BadCredentialsException("Invalid Refresh Token");
        }

        String jti = jwtService.getJti(refreshToken);
        UUID userId = jwtService.getUserId(refreshToken);
        RefreshToken storedRefreshToken = refreshTokenRepository.findByJti(jti)
                .orElseThrow(() -> new BadCredentialsException("Invalid Refresh Token"));

        if(storedRefreshToken.isRevoked()) {
            throw new BadCredentialsException("Refresh Token is revoked");
        }
        if(storedRefreshToken.getExpiresAt().isBefore(Instant.now())) {
            throw new BadCredentialsException("Refresh Token is expired");
        }
        if(!storedRefreshToken.getUser().getId().equals(userId)) {
            throw new BadCredentialsException("Refresh Token does not match user");
        }

        storedRefreshToken.setRevoked(true);

        String newJti = UUID.randomUUID().toString();
        storedRefreshToken.setReplacedByToken(newJti);
        refreshTokenRepository.save(storedRefreshToken);

        User user = storedRefreshToken.getUser();

        var newRefreshTokenObject = RefreshToken.builder()
                .jti(newJti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt((Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds())))
                .revoked(false)
                .build();

        refreshTokenRepository.save(newRefreshTokenObject);

        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user , newRefreshTokenObject.getJti());

        cookieService.attachRefreshCookie(response , newRefreshToken , (int) jwtService.getRefreshTtlSeconds());
        cookieService.addNoStoreHeaders(response);

        return ResponseEntity.ok(
                TokenResponse.of(
                        newAccessToken,
                        newRefreshToken,
                        jwtService.getAccessTtlSeconds(),
                        modelMapper.map(user, UserDto.class)
                )
        );
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        readRefreshTokenFromRequest(null , request)
                .ifPresent(
                        token -> {
                            try {
                                if(jwtService.isRefreshToken(token)) {
                                    String jti = jwtService.getJti(token);
                                    refreshTokenRepository
                                            .findByJti(jti)
                                            .ifPresent(
                                                    rt -> {
                                                        rt.setRevoked(true);
                                                        refreshTokenRepository.save(rt);
                                                    }
                                            );
                                }
                            } catch (Exception ignored) {
                            }
                        }
                );
        cookieService.clearRefreshCookie(response);
        cookieService.addNoStoreHeaders(response);

        SecurityContextHolder.clearContext();

        return ResponseEntity
                .status(HttpStatus.NO_CONTENT)
                .build();
    }

    private Optional<String> readRefreshTokenFromRequest(RefreshTokenRequest body, HttpServletRequest request) {
        if(request.getCookies() != null) {
            Optional<String> fromCookie = Arrays.stream(request.getCookies())
                    .filter(c -> Objects.equals(c.getName(), cookieService.getRefreshTokenCookieName()))
                    .map(Cookie::getValue)
                    .filter(v -> !v.isBlank())
                    .findFirst();
            if(fromCookie.isPresent()) {
                return fromCookie;
            }
        }

        if(body != null && body.refreshToken() != null && !body.refreshToken().isBlank()) {
            return Optional.of(body.refreshToken());
        }

        String refreshHeader = request.getHeader("X-Refresh_Token");
        if(refreshHeader != null && !refreshHeader.isBlank()) {
            return Optional.of(refreshHeader.trim());
        }

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if(authHeader != null && authHeader.regionMatches(true , 0 , "Bearer ", 0, 7)) {
            String candidate = authHeader.substring(7).trim();
            if(!candidate.isEmpty()) {
                try {
                    if(jwtService.isRefreshToken(candidate)) {
                        return Optional.of(candidate);
                    }
                } catch(Exception ignored) {
                }
            }
        }
        return Optional.empty();
    }


    @PostMapping("/register")
    public ResponseEntity<UserDto> registerUser(@RequestBody UserDto userDto) {

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(authService.registerUser(userDto));
    }
}
