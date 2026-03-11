package com.vikas.authsystem.dto;

import java.time.Instant;
import java.util.UUID;

public record RegisterResponse(
        UUID userId,
        String email,
        String message,
        Instant createdAt
) {
}
