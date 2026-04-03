package com.vikas.authsystem.config;

import io.jsonwebtoken.io.Decoders;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

@Component
public class StartupValidationService {

    private final JwtProperties jwtProperties;
    private final OtpProperties otpProperties;
    private final MailProperties mailProperties;
    private final String mailUsername;
    private final String mailPassword;

    public StartupValidationService(
            JwtProperties jwtProperties,
            OtpProperties otpProperties,
            MailProperties mailProperties,
            @Value("${spring.mail.username:}") String mailUsername,
            @Value("${spring.mail.password:}") String mailPassword
    ) {
        this.jwtProperties = jwtProperties;
        this.otpProperties = otpProperties;
        this.mailProperties = mailProperties;
        this.mailUsername = mailUsername;
        this.mailPassword = mailPassword;
    }

    @PostConstruct
    void validate() {
        validateJwtSecret();
        validateOtpSecret();
        validateMailConfiguration();
    }

    private void validateJwtSecret() {
        String secret = requireValue(jwtProperties.getSecret(), "JWT secret is not configured. Set JWT_SECRET.");
        byte[] decoded = decodeBase64(secret, "JWT secret must be valid Base64.");
        if (decoded.length < 32) {
            throw new IllegalStateException("JWT secret must decode to at least 32 bytes.");
        }
        if (jwtProperties.getIssuer() == null || jwtProperties.getIssuer().isBlank()) {
            throw new IllegalStateException("JWT issuer is not configured. Set JWT_ISSUER.");
        }
        if (jwtProperties.getAccessTokenMinutes() <= 0 || jwtProperties.getRefreshTokenDays() <= 0) {
            throw new IllegalStateException("JWT token lifetimes must be greater than zero.");
        }
    }

    private void validateOtpSecret() {
        String secret = requireValue(otpProperties.getSecret(), "OTP secret is not configured. Set OTP_SECRET.");
        if (secret.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalStateException("OTP secret must be at least 32 bytes.");
        }
    }

    private void validateMailConfiguration() {
        if (!"smtp".equalsIgnoreCase(mailProperties.getDeliveryMode())) {
            return;
        }
        requireValue(mailProperties.getFrom(), "MAIL_FROM must be configured when SMTP delivery is enabled.");
        requireValue(mailUsername, "MAIL_USERNAME must be configured when SMTP delivery is enabled.");
        requireValue(mailPassword, "MAIL_PASSWORD must be configured when SMTP delivery is enabled.");
    }

    private String requireValue(String value, String message) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(message);
        }
        return value.trim();
    }

    private byte[] decodeBase64(String value, String message) {
        try {
            return Decoders.BASE64.decode(value.trim());
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException(message, ex);
        }
    }
}
