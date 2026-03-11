package com.vikas.authsystem.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RefreshTokenRequest(
        @NotBlank(message = "refreshToken is required")
        @Size(max = 512, message = "refreshToken must not exceed 512 characters")
        String refreshToken,

        @Size(max = 128, message = "deviceId must not exceed 128 characters")
        String deviceId
) {
}
