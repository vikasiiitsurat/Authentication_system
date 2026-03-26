package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(name = "DeleteAccountRequest", description = "Payload required to permanently delete the authenticated account.")
public record DeleteAccountRequest(
        @NotBlank(message = "currentPassword is required")
        @Size(min = 8, max = 256, message = "currentPassword must be between 8 and 256 characters")
        @Schema(description = "Current password for destructive-action confirmation", example = "StrongPass123")
        String currentPassword,

        @NotBlank(message = "confirmEmail is required")
        @Email(message = "confirmEmail must be a valid email address")
        @Size(max = 320, message = "confirmEmail must not exceed 320 characters")
        @Schema(description = "Authenticated account email that must be typed to confirm permanent deletion", example = "user@example.com")
        String confirmEmail,

        @Size(max = 128, message = "deviceId must not exceed 128 characters")
        @Schema(description = "Client-controlled device identifier for audit visibility", example = "web-browser")
        String deviceId
) {
}
