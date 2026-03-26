package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(name = "PasswordChangeRequest", description = "Authenticated password change payload.")
public record PasswordChangeRequest(
        @NotBlank(message = "currentPassword is required")
        @Size(min = 8, max = 72, message = "currentPassword must be between 8 and 72 characters")
        @Schema(description = "Current password for the authenticated account", example = "CurrentPass@123")
        String currentPassword,

        @NotBlank(message = "newPassword is required")
        @Size(min = 8, max = 72, message = "newPassword must be between 8 and 72 characters")
        @Schema(description = "Replacement password for the account", example = "NewSecurePass@123")
        String newPassword,

        @Size(max = 128, message = "deviceId must not exceed 128 characters")
        @Schema(description = "Optional device identifier for audit and session attribution", example = "macbook-pro-16")
        String deviceId
) {
}
