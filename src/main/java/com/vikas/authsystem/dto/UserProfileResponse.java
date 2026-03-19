package com.vikas.authsystem.dto;

import com.vikas.authsystem.entity.UserRole;

import java.time.Instant;
import java.util.UUID;

public record UserProfileResponse(
        UUID id,
        String email,
        UserRole role,
        Instant createdAt,
        Instant updatedAt
) {
}
