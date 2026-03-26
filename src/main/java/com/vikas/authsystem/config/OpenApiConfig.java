package com.vikas.authsystem.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI authSystemOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("Auth System API")
                        .version("0.0.1-SNAPSHOT")
                        .description(
                                "Production-grade authentication and session management API covering " +
                                        "registration, login, JWT token lifecycle, active session controls, " +
                                        "email verification OTP flows, and user profile access."
                        )
                        .contact(new Contact()
                                .name("Auth System API Support")
                                .email("support@authsystem.local")
                        ))
                .components(new Components()
                        .addSecuritySchemes(
                                "bearerAuth",
                                new SecurityScheme()
                                        .name("Authorization")
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("JWT access token. Example: Bearer eyJhbGciOiJIUzI1NiJ9...")
                        ));
    }

    @Bean
    public GroupedOpenApi authenticationApi() {
        return GroupedOpenApi.builder()
                .group("authentication")
                .pathsToMatch(
                        "/api/auth/register",
                        "/api/auth/login",
                        "/api/users/**",
                        "/api/admin/users"
                )
                .build();
    }

    @Bean
    public GroupedOpenApi tokenManagementApi() {
        return GroupedOpenApi.builder()
                .group("token-management")
                .pathsToMatch(
                        "/api/auth/refresh",
                        "/api/auth/logout",
                        "/api/sessions/**"
                )
                .build();
    }

    @Bean
    public GroupedOpenApi passwordAndOtpApi() {
        return GroupedOpenApi.builder()
                .group("password-otp")
                .pathsToMatch(
                        "/api/auth/change-password",
                        "/api/auth/verify-email",
                        "/api/auth/resend-verification-otp"
                )
                .build();
    }
}
