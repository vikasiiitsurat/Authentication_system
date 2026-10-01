package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(
        name = "AuthenticationResponse",
        description = "Result of an authentication attempt. Either contains tokens for a completed login or a 2FA challenge that must be verified before tokens are issued."
)
public record AuthenticationResponse(
        @Schema(description = "Authentication state returned by the server", example = "AUTHENTICATED")
        String authenticationStatus,

        @Schema(description = "Human-readable authentication result message", example = "Login successful")
        String message,

        @Schema(description = "JWT access token used for authenticated API requests when login is fully completed", example = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature", nullable = true)
        String accessToken,

        @Schema(description = "Opaque refresh token used to rotate and obtain new access tokens when login is fully completed", example = "r3fR35hTok3nValue", nullable = true)
        String refreshToken,

        @Schema(description = "Authentication scheme for the access token", example = "Bearer", nullable = true)
        String tokenType,

        @Schema(description = "Access token validity duration in seconds for a completed login", example = "900", nullable = true)
        Long expiresInSeconds,

        @Schema(description = "Opaque challenge token required to verify the login OTP when 2FA is enabled", example = "y6wpr0yZ4n2XH5N6G6i8GsbSx0qnLxul8QK-v7Q9Or4", nullable = true)
        String twoFactorChallengeToken,

        @Schema(description = "Remaining lifetime of the login 2FA challenge in seconds", example = "300", nullable = true)
        Long twoFactorExpiresInSeconds,

        @Schema(description = "Seconds until the current login 2FA code can be resent", example = "60", nullable = true)
        Long twoFactorResendAvailableInSeconds
) {

    public static AuthenticationResponse authenticated(
            String accessToken,
            String refreshToken,
            String tokenType,
            long expiresInSeconds
    ) {
        return new AuthenticationResponse(
                "AUTHENTICATED",
                "Login successful",
                accessToken,
                refreshToken,
                tokenType,
                expiresInSeconds,
                null,
                null,
                null
        );
    }

    public static AuthenticationResponse twoFactorRequired(
            String challengeToken,
            long expiresInSeconds,
            long resendAvailableInSeconds
    ) {
        return new AuthenticationResponse(
                "TWO_FACTOR_REQUIRED",
                "A login verification code has been sent to your email address.",
                null,
                null,
                null,
                null,
                challengeToken,
                expiresInSeconds,
                resendAvailableInSeconds
        );
    }
}
