package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "LoginResponse", description = "Access token and refresh token pair issued after successful authentication or refresh.")
public record LoginResponse(
        @Schema(description = "JWT access token used for authenticated API requests", example = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature")
        String accessToken,
        @Schema(description = "Opaque refresh token used to rotate and obtain new access tokens", example = "r3fR35hTok3nValue")
        String refreshToken,
        @Schema(description = "Authentication scheme for the access token", example = "Bearer")
        String tokenType,
        @Schema(description = "Access token validity duration in seconds", example = "900")
        long expiresInSeconds
) {
}
