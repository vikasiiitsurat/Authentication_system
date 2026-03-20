package com.vikas.authsystem.security;

import com.vikas.authsystem.entity.UserRole;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public final class AuthenticatedUser {

    private final UUID userId;
    private final UserRole role;
    private final UUID sessionId;
    private final String tokenId;
    private final Instant tokenExpiresAt;

    public AuthenticatedUser(UUID userId, UserRole role, UUID sessionId, String tokenId, Instant tokenExpiresAt) {
        this.userId = Objects.requireNonNull(userId, "userId must not be null");
        this.role = Objects.requireNonNull(role, "role must not be null");
        this.sessionId = Objects.requireNonNull(sessionId, "sessionId must not be null");
        this.tokenId = tokenId;
        this.tokenExpiresAt = tokenExpiresAt;
    }

    public UUID getUserId() {
        return userId;
    }

    public UserRole getRole() {
        return role;
    }

    public UUID getSessionId() {
        return sessionId;
    }

    public String getTokenId() {
        return tokenId;
    }

    public Instant getTokenExpiresAt() {
        return tokenExpiresAt;
    }

    @Override
    public String toString() {
        return userId.toString();
    }
}
