package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(name = "RefreshTokenRequest", description = "Refresh token rotation request payload.")
public record RefreshTokenRequest(
        @NotBlank(message = "refreshToken is required")
        @Size(max = 512, message = "refreshToken must not exceed 512 characters")
        @Schema(description = "Previously issued refresh token", example = "r3fR35hTok3nValue")
        String refreshToken,

        @Size(max = 128, message = "deviceId must not exceed 128 characters")
        @Schema(description = "Device identifier that must match the session bound to the refresh token", example = "pixel-8-pro")
        String deviceId
) {
}
