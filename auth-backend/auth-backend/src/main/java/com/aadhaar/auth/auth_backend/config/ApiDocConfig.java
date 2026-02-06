package com.aadhaar.auth.auth_backend.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "Aadhaar Authentication API",
                version = "1.0",
                description = "API for Aadhaar authentication and token management",
                contact = @Contact(
                        name = "Aadhaar Goel",
                        email = "aadhaargoel123@gmail.com",
                        url = "goelaadhaar.live"
                ),
                summary = "This API provides endpoints for user authentication, token generation, and token refresh operations. It is designed to securely manage user sessions and provide a seamless authentication experience."
        ),
        security = {
                @SecurityRequirement(
                        name = "bearerAuth"
                )
        }
)
@SecurityScheme(
        name = "bearerAuth",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT"
)
public class ApiDocConfig {

}
