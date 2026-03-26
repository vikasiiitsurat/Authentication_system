package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(name = "LogoutRequest", description = "Payload used to revoke a refresh token during logout.")
public record LogoutRequest(
        @NotBlank(message = "refreshToken is required")
        @Size(max = 512, message = "refreshToken must not exceed 512 characters")
        @Schema(description = "Refresh token associated with the session being logged out", example = "r3fR35hTok3nValue")
        String refreshToken
) {
}
