package com.aadhaar.auth.auth_backend.security;

import com.aadhaar.auth.auth_backend.enitites.Provider;
import com.aadhaar.auth.auth_backend.enitites.RefreshToken;
import com.aadhaar.auth.auth_backend.enitites.User;
import com.aadhaar.auth.auth_backend.repositories.RefreshTokenRepository;
import com.aadhaar.auth.auth_backend.repositories.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final Logger logger = LoggerFactory.getLogger(OAuth2SuccessHandler.class);

    private final UserRepository userRepository;

    private final JWTService jwtService;

    private final RefreshTokenRepository refreshTokenRepository;

    private final CookieService cookieService;

    @Value("${app.auth.frontend.success-redirect}")
    private String frontendSuccessUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        logger.info("Successful Authentication");
        logger.info(authentication.toString());

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String registrationId = "unknown";
        if(authentication instanceof OAuth2AuthenticationToken token) {
            registrationId = token.getAuthorizedClientRegistrationId();
        }

        logger.info("OAuth2 Provider: {}", registrationId);
        logger.info("User Attributes: {}", oAuth2User.getAttributes().toString());

        User user;

        switch (registrationId) {
            case "google" -> {

                String googleId = oAuth2User.getAttributes().getOrDefault("sub" , "").toString();
                String email = oAuth2User.getAttributes().getOrDefault("email" , "").toString();
                String name = oAuth2User.getAttributes().getOrDefault("name" , "").toString();
                String picture = oAuth2User.getAttributes().getOrDefault("picture" , "").toString();

                User newUser = User.builder()
                        .email(email)
                        .name(name)
                        .image(picture)
                        .enable(true)
                        .provider(Provider.GOOGLE)
                        .providerId(googleId)
                        .build();

                user = userRepository.findByEmail(email).orElseGet(
                        () -> userRepository.save(newUser)
                );
            }
            case "github" -> {
                String name = oAuth2User.getAttributes().getOrDefault("login" , "").toString();
                String email = String.valueOf(oAuth2User.getAttributes().get("email"));
                String githubId = oAuth2User.getAttributes().getOrDefault("id" , "").toString();
                String picture = oAuth2User.getAttributes().getOrDefault("avatar_url" , "").toString();

                User newUser = User.builder()
                        .email(email)
                        .name(name)
                        .image(picture)
                        .enable(true)
                        .provider(Provider.GITHUB)
                        .providerId(githubId)
                        .build();

                user = userRepository.findByEmail(email).orElseGet(
                        () -> userRepository.save(newUser)
                );
            }
            default -> {
                throw new RuntimeException("Invalid OAuth2 Provider: " + registrationId);
            }
        }

        String jti = UUID.randomUUID().toString();
        RefreshToken refreshTokenObject = RefreshToken.builder()
                .jti(jti)
                .user(user)
                .revoked(false)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .build();

        refreshTokenRepository.save(refreshTokenObject);

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user, refreshTokenObject.getJti());

        cookieService.attachRefreshCookie(response, refreshToken, (int) jwtService.getRefreshTtlSeconds());
        cookieService.addNoStoreHeaders(response);

//        res

        response.sendRedirect(frontendSuccessUrl);
    }
}
