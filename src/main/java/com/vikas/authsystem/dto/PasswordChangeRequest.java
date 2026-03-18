package com.vikas.authsystem.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PasswordChangeRequest(
        @NotBlank(message = "currentPassword is required")
        @Size(min = 8, max = 72, message = "currentPassword must be between 8 and 72 characters")
        String currentPassword,

        @NotBlank(message = "newPassword is required")
        @Size(min = 8, max = 72, message = "newPassword must be between 8 and 72 characters")
        String newPassword,

        @Size(max = 128, message = "deviceId must not exceed 128 characters")
        String deviceId
) {
}
