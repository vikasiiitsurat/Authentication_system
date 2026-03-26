package com.vikas.authsystem.dto;

import com.vikas.authsystem.entity.UserRole;
import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;
import java.util.UUID;

@Schema(name = "UserProfileResponse", description = "User profile details returned by authenticated lookup endpoints.")
public record UserProfileResponse(
        @Schema(description = "Unique user identifier", example = "6a6c97fb-2a07-455c-8b2f-b6d21e70f98e")
        UUID id,
        @Schema(description = "User email address", example = "user@example.com")
        String email,
        @Schema(description = "Application role granted to the user", example = "USER")
        UserRole role,
        @Schema(description = "Timestamp when the account was created", example = "2026-03-18T10:15:30Z")
        Instant createdAt,
        @Schema(description = "Timestamp of the most recent profile update", example = "2026-03-20T10:47:27Z")
        Instant updatedAt
) {
}
